use crate::pcap::{CapturedPacket, write_pcapng};
use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use str0m::{
    Candidate, Event, Input, Output, Rtc, RtcConfig,
    change::{SdpAnswer, SdpOffer, SdpPendingOffer},
    channel::ChannelId,
    config::DtlsCert,
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
}

impl Peer {
    pub fn new(
        ice_lite: bool,
        adv_addr: IpAddr,
        udp_port: u16,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_cert(ice_lite, adv_addr, udp_port, None)
    }

    pub fn with_cert(
        ice_lite: bool,
        adv_addr: IpAddr,
        udp_port: u16,
        cert: Option<&DtlsCert>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let udp_socket = std::net::UdpSocket::bind(SocketAddr::new(adv_addr, udp_port))?;
        let std_socket = udp_socket;
        std_socket.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(std_socket)?;
        let local_addr = socket.local_addr()?;

        let mut config = RtcConfig::new();
        if ice_lite {
            config = config.set_ice_lite(true);
        }
        if let Some(c) = cert {
            config = config.set_dtls_cert(c.clone());
        }
        let rtc = config.build(Instant::now());

        info!(%local_addr, ice_lite, "Created new peer");

        let mut peer = Self {
            rtc,
            socket,
            local_addr,
            pending_offer: None,
        };

        let candidate = Candidate::host(local_addr, "udp")?;
        info!(candidate = %candidate.to_sdp_string(), "Adding local host candidate");
        peer.rtc.add_local_candidate(candidate);

        Ok(peer)
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

    pub async fn run(
        &mut self,
        session_id: &str,
        role: &str,
        on_connected: oneshot::Sender<()>,
        on_channel_open: oneshot::Sender<()>,
        dc_action: DataChannelAction,
        shutdown: oneshot::Receiver<()>,
    ) -> Result<(), String> {
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

        let mut captured: Option<Vec<CapturedPacket>> = Some(Vec::new());
        let mut packets_sent: u32 = 0;
        let mut packets_recv: u32 = 0;
        let pcap_dir = "target/pcap";
        std::fs::create_dir_all(pcap_dir).ok();
        let pcap_filename = format!("{pcap_dir}/{session_id}_{role}.pcapng");

        info!(%session_id, %role, "Event loop started");

        loop {
            let next_timeout = loop {
                match self.rtc.poll_output() {
                    Ok(Output::Timeout(t)) => break t,
                    Ok(Output::Transmit(t)) => {
                        if let Some(cap) = captured.as_mut() {
                            packets_sent += 1;
                            cap.push(CapturedPacket {
                                timestamp_us: now_us(),
                                src: self.local_addr,
                                dst: t.destination,
                                payload: t.contents.to_vec(),
                            });
                        }

                        if let Err(e) = self.socket.send_to(&t.contents, t.destination).await {
                            warn!(dest = %t.destination, "UDP send failed: {e}");
                        }
                    }
                    Ok(Output::Event(event)) => match event {
                        Event::Connected => {
                            info!(%session_id, %role, packets_sent, packets_recv, "Connected");
                            if let Some(tx) = on_connected.take() {
                                let _ = tx.send(());
                            }
                        }
                        Event::ChannelOpen(cid, label) => {
                            info!(%session_id, %role, ?cid, %label, "ChannelOpen");

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

                            if matches!(dc_action.as_ref(), Some(DataChannelAction::Echo { .. })) {
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
                                let rtt = echo_send_time.map(|t| t.elapsed()).unwrap_or_default();
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

            let wait = next_timeout.saturating_duration_since(Instant::now());
            let sleep = tokio::time::sleep(wait);

            tokio::select! {
                biased;

                result = self.socket.recv_from(&mut buf) => {
                    match result {
                        Ok((n, source)) => {
                            debug!(n, %source, %role, "UDP recv");

                            if let Some(cap) = captured.as_mut() {
                                packets_recv += 1;
                                cap.push(CapturedPacket {
                                    timestamp_us: now_us(),
                                    src: source,
                                    dst: self.local_addr,
                                    payload: buf[..n].to_vec(),
                                });
                            }

                            let receive = Receive::new(
                                Protocol::Udp,
                                source,
                                self.local_addr,
                                &buf[..n],
                            )
                            .map_err(|e| format!("parse received packet: {e}"))?;

                            self.rtc
                                .handle_input(Input::Receive(Instant::now(), receive))
                                .map_err(|e| format!("handle_input receive: {e}"))?;
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
                    self.rtc
                        .handle_input(Input::Timeout(Instant::now()))
                        .map_err(|e| format!("handle_input timeout: {e}"))?;
                }
                _ = &mut shutdown => {
                    info!("Shutdown signal received");
                    if let Some(ref packets) = captured {
                        dump_packet_timeline(session_id, role, packets);
                    }
                    if let Some(packets) = captured.take() {
                        let pcapng_data = write_pcapng(&packets);
                        if let Err(e) = std::fs::write(&pcap_filename, &pcapng_data) {
                            warn!("Failed to write pcap-ng {pcap_filename}: {e}");
                        } else {
                            info!(pcap_filename, count = packets.len(), "Pcap-ng saved (full session)");
                        }
                    }
                    return Ok(());
                }
            }
        }
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
    if payload.is_empty() {
        return "empty";
    }
    let first = payload[0];
    if first == 0x00 || first == 0x01 {
        if payload.len() >= 2 {
            let msg_type = u16::from_be_bytes([payload[0], payload[1]]);
            return match msg_type {
                0x0001 => "STUN Binding Request",
                0x0101 => "STUN Binding Response",
                _ => "STUN (other)",
            };
        }
        return "STUN";
    }
    if (20..=25).contains(&first) {
        return match first {
            20 => "DTLS ChangeCipherSpec",
            21 => "DTLS Alert",
            22 => "DTLS Handshake",
            23 => "DTLS ApplicationData",
            _ => "DTLS (other)",
        };
    }
    "unknown"
}

fn now_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64
}
