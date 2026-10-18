use crate::netem::{NetPacket, NetemPath};
use crate::pcap::{CapturedPacket, write_pcapng};
use crate::protocol::{NetemSettings, SessionReport};
use std::{
    collections::VecDeque,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use str0m::{
    Candidate, Event, Input, Output, Rtc, RtcConfig,
    change::{SdpAnswer, SdpOffer, SdpPendingOffer},
    channel::ChannelId,
    config::{DtlsCert, DtlsVersion},
    crypto::dtls::ProtocolVersion,
    net::{Protocol, Receive},
};
use tokio::{net::UdpSocket, sync::oneshot};
use tracing::{debug, info, warn};

pub enum DataChannelAction {
    None,
    Echo {
        /// Send a "ready" beacon after ChannelOpen to trigger Chrome's SCTP output flush.
        send_ready_beacon: bool,
    },
    SendAndExpectEcho {
        message: Vec<u8>,
        result_tx: oneshot::Sender<Option<Duration>>,
    },
}

pub struct Peer {
    pub rtc: Rtc,
    pub socket: UdpSocket,
    pub local_addr: SocketAddr,
    pending_offer: Option<SdpPendingOffer>,
    netem: Option<(NetemSettings, u64)>,
}

impl Peer {
    pub fn new(
        ice_lite: bool,
        adv_addr: IpAddr,
        udp_port: u16,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_cert(ice_lite, adv_addr, udp_port, None, true, None)
    }

    pub fn with_cert(
        ice_lite: bool,
        adv_addr: IpAddr,
        udp_port: u16,
        cert: Option<&DtlsCert>,
        snap_enabled: bool,
        dtls_version: Option<DtlsVersion>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let udp_socket = std::net::UdpSocket::bind(SocketAddr::new(adv_addr, udp_port))?;
        let std_socket = udp_socket;
        std_socket.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(std_socket)?;
        let local_addr = socket.local_addr()?;

        let mut config = RtcConfig::new().set_snap_enabled(snap_enabled);

        if let Some(v) = dtls_version {
            config = config.set_dtls_version(v);
        }
        if ice_lite {
            config = config.set_ice_lite(true);
        }
        if let Some(c) = cert {
            config = config.set_dtls_cert(c.clone());
        }
        let rtc = config.build(Instant::now());

        info!(%local_addr, ice_lite, snap_enabled, ?dtls_version, "Created new peer");

        let mut peer = Self {
            rtc,
            socket,
            local_addr,
            pending_offer: None,
            netem: None,
        };

        let candidate = Candidate::host(local_addr, "udp")?;
        info!(candidate = %candidate.to_sdp_string(), "Adding local host candidate");
        peer.rtc.add_local_candidate(candidate);

        Ok(peer)
    }

    /// Emulate network conditions with str0m-netem between `Rtc` and the UDP socket.
    /// `seed` applies to links that don't set their own (see [`crate::netem::session_seed`]).
    pub fn set_netem(&mut self, settings: NetemSettings, seed: u64) {
        info!(?settings, seed, "Netem enabled");
        self.netem = (!settings.is_empty()).then_some((settings, seed));
    }

    pub fn create_offer(
        &mut self,
        channel_label: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut api = self.rtc.sdp_api();
        let _cid = api.add_channel(channel_label.into());
        let (offer, pending) = api.apply().ok_or("No SDP changes to apply")?;
        self.pending_offer = Some(pending);
        let sdp = offer.to_sdp_string();
        info!(len = sdp.len(), "Created SDP offer");
        Ok(sdp)
    }

    pub fn force_dtls_active(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.rtc.direct_api().start_dtls(true)?;
        info!("Forced DTLS to active (this peer = DTLS client)");
        Ok(())
    }

    pub fn accept_offer(&mut self, sdp_offer: &str) -> Result<String, Box<dyn std::error::Error>> {
        let offer = SdpOffer::from_sdp_string(sdp_offer)?;
        let answer = self.rtc.sdp_api().accept_offer(offer)?;
        let sdp = answer.to_sdp_string();
        info!(len = sdp.len(), "Created SDP answer");
        Ok(sdp)
    }

    pub fn accept_answer(&mut self, sdp_answer: &str) -> Result<(), Box<dyn std::error::Error>> {
        let pending = self
            .pending_offer
            .take()
            .ok_or("No pending offer to accept answer for")?;
        let answer = SdpAnswer::from_sdp_string(sdp_answer)?;
        self.rtc.sdp_api().accept_answer(pending, answer)?;
        info!("Accepted remote SDP answer");
        Ok(())
    }

    /// Drive the peer until `shutdown` fires or an error occurs. The pcap is written
    /// either way; a failure is reported in [`SessionReport::error`].
    pub async fn run(
        &mut self,
        session_id: &str,
        role: &str,
        on_connected: oneshot::Sender<()>,
        on_channel_open: oneshot::Sender<()>,
        dc_action: DataChannelAction,
        shutdown: oneshot::Receiver<()>,
    ) -> SessionReport {
        let mut buf = vec![0u8; 65535];
        let mut on_connected = Some(on_connected);
        let mut on_channel_open = Some(on_channel_open);
        let mut dc_action = Some(dc_action);
        let mut dc_channel_id: Option<ChannelId> = None;
        let mut pending_echo: Vec<(ChannelId, bool, Vec<u8>)> = Vec::new();
        let mut pending_send: Option<Vec<u8>> = None;
        let mut pending_ready_beacon: bool = false;
        let mut expected_echo: Option<(Vec<u8>, oneshot::Sender<Option<Duration>>)> = None;
        let mut echo_send_time: Option<Instant> = None;
        tokio::pin!(shutdown);

        let mut io = PeerIo::new(self.local_addr, self.netem.as_ref());
        let mut report = SessionReport::default();

        info!(%session_id, %role, netem = self.netem.is_some(), "Event loop started");

        let result: Result<(), String> = async {
            // str0m's ICE agent schedules nothing until its first tick, and dimpl
            // (since algesten/dimpl#162) no longer requests an immediate timeout for
            // unarmed timers. Without this, a full-ICE str0m peer whose DTLS role is
            // passive never starts its connectivity checks.
            self.rtc
                .handle_input(Input::Timeout(Instant::now()))
                .map_err(|e| format!("handle_input initial timeout: {e}"))?;

            loop {
                let next_timeout = loop {
                    match self.rtc.poll_output() {
                        Ok(Output::Timeout(t)) => break t,
                        Ok(Output::Transmit(t)) => {
                            io.transmit(&self.socket, t.destination, &t.contents).await;
                        }
                        Ok(Output::Event(event)) => match event {
                            Event::Connected => {
                                if report.connected_ms.is_none() {
                                    report.connected_ms = Some(io.elapsed_ms());
                                }
                                report.dtls_version = self
                                    .rtc
                                    .direct_api()
                                    .dtls_protocol_version()
                                    .map(format_dtls_version);
                                info!(
                                    %session_id, %role,
                                    packets_sent = io.packets_sent,
                                    packets_recv = io.packets_recv,
                                    dtls = report.dtls_version.as_deref().unwrap_or("?"),
                                    "Connected"
                                );
                                if let Some(tx) = on_connected.take() {
                                    let _ = tx.send(());
                                }
                            }
                            Event::ChannelOpen(cid, label) => {
                                info!(%session_id, %role, ?cid, %label, "ChannelOpen");
                                if report.channel_open_ms.is_none() {
                                    report.channel_open_ms = Some(io.elapsed_ms());
                                }

                                dc_channel_id = Some(cid);

                                if let Some(tx) = on_channel_open.take() {
                                    let _ = tx.send(());
                                }

                                match dc_action.take() {
                                    Some(DataChannelAction::SendAndExpectEcho {
                                        message,
                                        result_tx,
                                    }) => {
                                        pending_send = Some(message.clone());
                                        expected_echo = Some((message, result_tx));
                                    }
                                    other => {
                                        if matches!(
                                            other.as_ref(),
                                            Some(DataChannelAction::Echo {
                                                send_ready_beacon: true
                                            })
                                        ) {
                                            pending_ready_beacon = true;
                                        }
                                        dc_action = other;
                                    }
                                }

                                for (id, binary, data) in std::mem::take(&mut pending_echo) {
                                    if matches!(
                                        dc_action.as_ref(),
                                        Some(DataChannelAction::Echo { .. })
                                    ) && let Some(mut ch) = self.rtc.channel(id)
                                    {
                                        ch.write(binary, &data).map_err(|e| {
                                            format!("channel echo write (buffered): {e}")
                                        })?;
                                    } else {
                                        warn!(%role, ?id, "Could not echo buffered data");
                                    }
                                }
                            }
                            Event::ChannelData(cd) => {
                                let text = String::from_utf8_lossy(&cd.data);
                                debug!(%role, %text, channel_id = ?cd.id, data_len = cd.data.len(), "ChannelData");

                                if matches!(
                                    dc_action.as_ref(),
                                    Some(DataChannelAction::Echo { .. })
                                ) {
                                    if dc_channel_id == Some(cd.id) {
                                        if let Some(mut ch) = self.rtc.channel(cd.id) {
                                            ch.write(cd.binary, &cd.data)
                                                .map_err(|e| format!("channel echo write: {e}"))?;
                                        } else {
                                            warn!(%role, "channel not found for echo");
                                        }
                                    } else {
                                        debug!(%role, "Buffering echo (channel not yet open)");
                                        pending_echo.push((cd.id, cd.binary, cd.data.to_vec()));
                                    }
                                }

                                if let Some((ref expected, _)) = expected_echo
                                    && cd.data == *expected
                                {
                                    let rtt =
                                        echo_send_time.map(|t| t.elapsed()).unwrap_or_default();
                                    info!(%role, ?rtt, "Echo matched");
                                    let (_, tx) = expected_echo.take().unwrap();
                                    let _ = tx.send(Some(rtt));
                                }
                            }
                            Event::IceConnectionStateChange(state) => {
                                info!(?state, "ICE connection state changed");
                            }
                            other => {
                                debug!("Event: {other:?}");
                            }
                        },
                        Err(e) => return Err(format!("poll_output error: {e}")),
                    }
                };

                io.flush_egress(&self.socket).await;

                if pending_ready_beacon {
                    if let Some(cid) = dc_channel_id
                        && let Some(mut ch) = self.rtc.channel(cid)
                    {
                        ch.write(false, b"ready")
                            .map_err(|e| format!("ready beacon write: {e}"))?;
                        info!(%role, "Sent ready beacon");
                    }
                    pending_ready_beacon = false;
                    continue;
                }

                if let (Some(msg), Some(cid)) = (pending_send.take(), dc_channel_id)
                    && let Some(mut ch) = self.rtc.channel(cid)
                {
                    let text = String::from_utf8_lossy(&msg);
                    ch.write(false, &msg)
                        .map_err(|e| format!("channel write: {e}"))?;
                    echo_send_time = Some(Instant::now());
                    info!(%role, %text, "Sent data to channel");
                    continue; // re-drain outputs to transmit
                }

                let wake_at = io
                    .next_netem_deadline()
                    .map_or(next_timeout, |d| d.min(next_timeout));
                let wait = wake_at.saturating_duration_since(Instant::now());
                let sleep = tokio::time::sleep(wait);

                tokio::select! {
                    biased;

                    result = self.socket.recv_from(&mut buf) => {
                        match result {
                            Ok((n, source)) => {
                                debug!(n, %source, %role, "UDP recv");
                                let now = Instant::now();
                                io.receive(now, source, &buf[..n]);
                                deliver_ingress(&mut self.rtc, &mut io, now)?;
                            }
                            Err(e) => {
                                if e.kind() == std::io::ErrorKind::ConnectionReset {
                                    debug!("ConnectionReset on UDP recv (ignoring)");
                                    self.rtc
                                        .handle_input(Input::Timeout(Instant::now()))
                                        .map_err(|e| format!("handle_input timeout: {e}"))?;
                                } else {
                                    return Err(format!("UDP recv: {e}"));
                                }
                            }
                        }
                    }
                    _ = sleep => {
                        debug!(elapsed_us = now_us(), wait_ms = wait.as_millis(), "Timer fired");
                        let now = Instant::now();
                        deliver_ingress(&mut self.rtc, &mut io, now)?;
                        self.rtc
                            .handle_input(Input::Timeout(now))
                            .map_err(|e| format!("handle_input timeout: {e}"))?;
                    }
                    _ = &mut shutdown => {
                        info!("Shutdown signal received");
                        return Ok(());
                    }
                }
            }
        }
        .await;

        if let Err(e) = result {
            warn!(%session_id, %role, "Peer event loop failed: {e}");
            report.error = Some(e);
        }
        io.finish(session_id, role, &mut report);
        report
    }
}

/// Hand every ingress packet that is due at `now` to str0m.
fn deliver_ingress(rtc: &mut Rtc, io: &mut PeerIo, now: Instant) -> Result<(), String> {
    while let Some(packet) = io.pop_ingress(now) {
        let receive = Receive::new(Protocol::Udp, packet.addr, io.local_addr, &packet.data)
            .map_err(|e| format!("parse received packet: {e}"))?;
        rtc.handle_input(Input::Receive(now, receive))
            .map_err(|e| format!("handle_input receive: {e}"))?;
    }
    Ok(())
}

/// Everything between `Rtc` and the UDP socket: str0m-netem, pcap capture and counters.
///
/// The capture is str0m's view of the network: egress packets are recorded before
/// netem (they may still be dropped or delayed), ingress packets after netem.
struct PeerIo {
    local_addr: SocketAddr,
    started: Instant,
    captured: Vec<CapturedPacket>,
    packets_sent: u64,
    packets_recv: u64,
    egress: Option<NetemPath>,
    ingress: Option<NetemPath>,
    /// Arrived packets waiting for str0m when there is no ingress emulation.
    direct_ingress: VecDeque<NetPacket>,
}

impl PeerIo {
    fn new(local_addr: SocketAddr, netem: Option<&(NetemSettings, u64)>) -> Self {
        let (egress, ingress) = netem.map_or((None, None), |(settings, seed)| {
            NetemPath::from_settings(settings, *seed)
        });
        Self {
            local_addr,
            started: Instant::now(),
            captured: Vec::new(),
            packets_sent: 0,
            packets_recv: 0,
            egress,
            ingress,
            direct_ingress: VecDeque::new(),
        }
    }

    fn elapsed_ms(&self) -> f64 {
        self.started.elapsed().as_secs_f64() * 1000.0
    }

    async fn transmit(&mut self, socket: &UdpSocket, destination: SocketAddr, data: &[u8]) {
        self.packets_sent += 1;
        self.captured.push(CapturedPacket {
            timestamp_us: now_us(),
            src: self.local_addr,
            dst: destination,
            payload: data.to_vec(),
        });
        match &mut self.egress {
            Some(path) => path.push(
                Instant::now(),
                NetPacket {
                    addr: destination,
                    data: data.to_vec(),
                },
            ),
            None => send(socket, destination, data).await,
        }
    }

    /// Send egress packets whose emulated delay has elapsed.
    async fn flush_egress(&mut self, socket: &UdpSocket) {
        let Some(path) = &mut self.egress else {
            return;
        };
        let now = Instant::now();
        while let Some(packet) = path.pop(now) {
            send(socket, packet.addr, &packet.data).await;
        }
    }

    fn receive(&mut self, now: Instant, source: SocketAddr, data: &[u8]) {
        let packet = NetPacket {
            addr: source,
            data: data.to_vec(),
        };
        match &mut self.ingress {
            Some(path) => path.push(now, packet),
            None => self.direct_ingress.push_back(packet),
        }
    }

    fn pop_ingress(&mut self, now: Instant) -> Option<NetPacket> {
        let packet = self
            .direct_ingress
            .pop_front()
            .or_else(|| self.ingress.as_mut()?.pop(now))?;
        self.packets_recv += 1;
        self.captured.push(CapturedPacket {
            timestamp_us: now_us(),
            src: packet.addr,
            dst: self.local_addr,
            payload: packet.data.clone(),
        });
        Some(packet)
    }

    fn next_netem_deadline(&self) -> Option<Instant> {
        [&self.egress, &self.ingress]
            .into_iter()
            .filter_map(|path| path.as_ref()?.next_deadline())
            .min()
    }

    /// Write the pcap and fill in the counters of `report`.
    fn finish(self, session_id: &str, role: &str, report: &mut SessionReport) {
        report.packets_sent = self.packets_sent;
        report.packets_received = self.packets_recv;
        report.netem_egress = self.egress.as_ref().map(NetemPath::stats);
        report.netem_ingress = self.ingress.as_ref().map(NetemPath::stats);
        if let Some(stats) = report.netem_egress {
            info!(%session_id, %role, ?stats, "Netem egress");
        }
        if let Some(stats) = report.netem_ingress {
            info!(%session_id, %role, ?stats, "Netem ingress");
        }

        dump_packet_timeline(session_id, role, &self.captured);
        let pcap_dir = "target/pcap";
        std::fs::create_dir_all(pcap_dir).ok();
        let pcap_filename = format!("{pcap_dir}/{session_id}_{role}.pcapng");
        if let Err(e) = std::fs::write(&pcap_filename, write_pcapng(&self.captured)) {
            warn!("Failed to write pcap-ng {pcap_filename}: {e}");
        } else {
            info!(
                pcap_filename,
                count = self.captured.len(),
                "Pcap-ng saved (full session)"
            );
        }
    }
}

async fn send(socket: &UdpSocket, destination: SocketAddr, data: &[u8]) {
    if let Err(e) = socket.send_to(data, destination).await {
        warn!(dest = %destination, "UDP send failed: {e}");
    }
}

fn format_dtls_version(version: ProtocolVersion) -> String {
    match version.as_u16() {
        0xFEFD => "1.2".to_string(),
        0xFEFC => "1.3".to_string(),
        other => format!("{other:#06x}"),
    }
}

fn dump_packet_timeline(session_id: &str, role: &str, packets: &[CapturedPacket]) {
    if packets.is_empty() {
        return;
    }
    let t0 = packets[0].timestamp_us;
    info!(%session_id, %role, "---- Packet Timeline ----");
    for (i, pkt) in packets.iter().enumerate() {
        let rel_us = pkt.timestamp_us - t0;
        let rel_ms = rel_us as f64 / 1000.0;
        let dir = if pkt.src.port() < pkt.dst.port() {
            "->"
        } else {
            "<-"
        };
        let size = pkt.payload.len();

        let pkt_type = identify_packet_type(&pkt.payload);

        info!(
            %session_id, %role,
            "  [{i:2}] +{rel_ms:8.1}ms  {dir}  {size:4}B  {pkt_type}",
        );
    }
    info!(%session_id, %role, "-------------------------");
}

fn identify_packet_type(payload: &[u8]) -> &'static str {
    let Some(&first) = payload.first() else {
        return "empty";
    };
    // RFC 7983 demultiplexing: STUN 0..=3, DTLS 20..=63.
    match first {
        0..=3 => match payload.get(..2) {
            Some([0x00, 0x01]) => "STUN Binding Request",
            Some([0x01, 0x01]) => "STUN Binding Response",
            _ => "STUN (other)",
        },
        20 => "DTLS ChangeCipherSpec",
        21 => "DTLS Alert",
        22 => "DTLS Handshake",
        23 => "DTLS ApplicationData",
        24..=31 => "DTLS (other)",
        // DTLS 1.3 unified header (RFC 9147 §4): encrypted record.
        32..=63 => "DTLS 1.3 ciphertext",
        _ => "unknown",
    }
}

fn now_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}
