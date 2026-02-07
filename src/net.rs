use std::net::{IpAddr, Ipv4Addr};

use tracing::info;

/// Enumerate network interfaces and pick the first non-loopback, non-VPN IP (preferring IPv4).
pub fn detect_public_ip() -> Result<IpAddr, Box<dyn std::error::Error>> {
    let interfaces = if_addrs::get_if_addrs()?;

    info!("Detected network interfaces:");
    for iface in &interfaces {
        let skipped = if is_vpn_interface(iface) {
            " [skipped: VPN]"
        } else {
            ""
        };
        info!(
            "  {} -> {} (loopback: {}){skipped}",
            iface.name,
            iface.ip(),
            iface.is_loopback(),
        );
    }

    // Collect non-loopback, non-VPN IPs, prefer IPv4
    let mut ipv4_addrs = Vec::new();
    let mut ipv6_addrs = Vec::new();

    for iface in &interfaces {
        if iface.is_loopback() || is_vpn_interface(iface) {
            continue;
        }
        match iface.ip() {
            addr @ IpAddr::V4(_) => ipv4_addrs.push(addr),
            addr @ IpAddr::V6(_) => ipv6_addrs.push(addr),
        }
    }

    ipv4_addrs
        .first()
        .or_else(|| ipv6_addrs.first())
        .copied()
        .ok_or_else(|| "No suitable (non-loopback, non-VPN) IP address found".into())
}

/// Heuristic to detect VPN/tunnel interfaces.
fn is_vpn_interface(iface: &if_addrs::Interface) -> bool {
    let name = iface.name.to_lowercase();

    // Common VPN/tunnel interface name patterns
    if name.contains("vpn")
        || name.contains("tun")
        || name.contains("tap")
        || name.contains("ppp")
        || name.contains("ztun")
        || name.contains("wg") // WireGuard
        || name.contains("tailscale")
        || name.contains("utun")
    // macOS tunnel
    {
        return true;
    }

    // CGNAT range 100.64.0.0/10 is commonly used by VPNs (e.g., Azure VPN, Tailscale)
    if let IpAddr::V4(v4) = iface.ip()
        && is_cgnat(v4)
    {
        return true;
    }

    false
}

/// Check if an IPv4 address is in the CGNAT range (100.64.0.0/10).
const fn is_cgnat(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 100 && (octets[1] & 0xC0) == 64 // 100.64.0.0 - 100.127.255.255
}
