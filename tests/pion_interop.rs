//! Pion ↔ str0m interop integration tests.
//!
//! Tests both directions:
//!   - str0m server + pion client
//!   - pion server + str0m client

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Stdio;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use str0m_browser_integration_tests::UdpPortAllocator;
use tokio::process::Command;
use tracing::info;

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

static NEXT_WS_PORT: AtomicU16 = AtomicU16::new(19400);

fn alloc_ws_port() -> u16 {
    NEXT_WS_PORT.fetch_add(1, Ordering::Relaxed)
}

fn init() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    str0m_browser_integration_tests::init_crypto();
}

/// Build project root path.
fn project_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Get path to the pion server binary, building it if needed.
fn pion_server_bin() -> std::path::PathBuf {
    let root = project_root();
    let name = if cfg!(windows) {
        "server.exe"
    } else {
        "server"
    };
    root.join("pion").join(name)
}

/// Get path to the pion client binary, building it if needed.
fn pion_client_bin() -> std::path::PathBuf {
    let root = project_root();
    let name = if cfg!(windows) {
        "client.exe"
    } else {
        "client"
    };
    root.join("pion").join(name)
}

/// Build the Go binaries in the pion/ directory.
async fn build_pion_binaries() {
    let root = project_root();
    let pion_dir = root.join("pion");

    let server_name = if cfg!(windows) {
        "server.exe"
    } else {
        "server"
    };
    let client_name = if cfg!(windows) {
        "client.exe"
    } else {
        "client"
    };

    let output = Command::new("go")
        .args(["build", "-o", server_name, "./cmd/server/"])
        .current_dir(&pion_dir)
        .output()
        .await
        .expect("Failed to run go build for pion server");

    if !output.status.success() {
        panic!(
            "Failed to build pion server:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let output = Command::new("go")
        .args(["build", "-o", client_name, "./cmd/client/"])
        .current_dir(&pion_dir)
        .output()
        .await
        .expect("Failed to run go build for pion client");

    if !output.status.success() {
        panic!(
            "Failed to build pion client:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// Start the str0m signaling server, returning the server task handle.
async fn start_str0m_server(ws_port: u16) {
    let sessions = Arc::new(Mutex::new(HashMap::new()));
    let udp_ports = Arc::new(UdpPortAllocator::new(0));

    tokio::spawn(async move {
        str0m_browser_integration_tests::server::run_server(
            ws_port, sessions, LOCALHOST, udp_ports,
        )
        .await
        .expect("str0m server failed");
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
}

/// Start the pion signaling server as a child process.
async fn start_pion_server(ws_port: u16) -> tokio::process::Child {
    let bin = pion_server_bin();
    let pcap_dir = project_root().join("target").join("pcap");
    let child = Command::new(&bin)
        .args([
            &format!("-ws-port={ws_port}"),
            &format!("-adv-addr=127.0.0.1"),
            &format!("-pcap-dir={}", pcap_dir.display()),
        ])
        .current_dir(project_root())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap_or_else(|e| panic!("Failed to start pion server at {}: {e}", bin.display()));

    // Wait for the server to be ready
    tokio::time::sleep(Duration::from_millis(500)).await;
    child
}

/// Run the pion client against a running server.
async fn run_pion_client(
    ws_port: u16,
    session_id: &str,
    sdp_role: &str,
    ice_mode: &str,
    dtls_role: &str,
) -> Result<(), String> {
    let bin = pion_client_bin();
    let ws_url = format!("ws://127.0.0.1:{ws_port}");
    let pcap_dir = project_root().join("target").join("pcap");

    let output = Command::new(&bin)
        .args([
            &format!("-ws-url={ws_url}"),
            &format!("-session-id={session_id}"),
            &format!("-sdp-role={sdp_role}"),
            &format!("-ice-mode={ice_mode}"),
            &format!("-dtls-role={dtls_role}"),
            &format!("-pcap-dir={}", pcap_dir.display()),
            "-timeout=15s",
        ])
        .current_dir(project_root())
        .output()
        .await
        .map_err(|e| format!("Failed to run pion client: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    info!("pion client stdout:\n{stdout}");
    info!("pion client stderr:\n{stderr}");

    if output.status.success() && stdout.contains("CLIENT OK") {
        Ok(())
    } else {
        Err(format!(
            "Pion client failed (exit={}):\nstdout: {stdout}\nstderr: {stderr}",
            output.status
        ))
    }
}

/// Run the str0m client against a running server.
async fn run_str0m_client(
    ws_port: u16,
    session_id: &str,
    sdp_role: &str,
    ice_mode: &str,
    dtls_role: &str,
) -> Result<(), String> {
    let ws_url = format!("ws://127.0.0.1:{ws_port}");

    // Use cargo run to invoke the str0m-client binary
    let output = Command::new(env!("CARGO"))
        .args([
            "run",
            "--bin",
            "str0m-client",
            "--",
            "--ws-url",
            &ws_url,
            "--session-id",
            session_id,
            "--sdp-role",
            sdp_role,
            "--ice-mode",
            ice_mode,
            "--dtls-role",
            dtls_role,
            "--timeout",
            "15",
            "--adv-addr",
            "127.0.0.1",
        ])
        .output()
        .await
        .map_err(|e| format!("Failed to run str0m client: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    info!("str0m client stdout:\n{stdout}");
    info!("str0m client stderr:\n{stderr}");

    if output.status.success() && stdout.contains("CLIENT OK") {
        Ok(())
    } else {
        Err(format!(
            "str0m client failed (exit={}):\nstdout: {stdout}\nstderr: {stderr}",
            output.status
        ))
    }
}

// ───────────────────────────────────────────────────────────────
// str0m server ← pion client
// ───────────────────────────────────────────────────────────────

async fn test_pion_client_to_str0m_server(
    test_name: &str,
    sdp_role: &str,
    ice_mode: &str,
    dtls_role: &str,
) {
    init();
    build_pion_binaries().await;

    let ws_port = alloc_ws_port();
    start_str0m_server(ws_port).await;

    info!(%ws_port, %test_name, "str0m server started, running pion client...");

    run_pion_client(ws_port, test_name, sdp_role, ice_mode, dtls_role)
        .await
        .unwrap_or_else(|e| panic!("{test_name} FAILED: {e}"));

    info!(%test_name, "=== Test passed ===");
}

// ───────────────────────────────────────────────────────────────
// pion server ← str0m client
// ───────────────────────────────────────────────────────────────

async fn test_str0m_client_to_pion_server(
    test_name: &str,
    sdp_role: &str,
    ice_mode: &str,
    dtls_role: &str,
) {
    init();
    build_pion_binaries().await;

    let ws_port = alloc_ws_port();
    let mut pion_server = start_pion_server(ws_port).await;

    info!(%ws_port, %test_name, "pion server started, running str0m client...");

    let result = run_str0m_client(ws_port, test_name, sdp_role, ice_mode, dtls_role).await;

    // Kill the pion server
    pion_server.kill().await.ok();

    result.unwrap_or_else(|e| panic!("{test_name} FAILED: {e}"));

    info!(%test_name, "=== Test passed ===");
}

// ───────────────────────────────────────────────────────────────
// Test cases: pion client → str0m server
// ───────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn pion_to_str0m_offerer_active_full() {
    test_pion_client_to_str0m_server(
        "pion_str0m_offerer_active_full",
        "offerer",
        "full",
        "active",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pion_to_str0m_offerer_active_lite() {
    test_pion_client_to_str0m_server(
        "pion_str0m_offerer_active_lite",
        "offerer",
        "lite",
        "active",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pion_to_str0m_offerer_passive_full() {
    test_pion_client_to_str0m_server(
        "pion_str0m_offerer_passive_full",
        "offerer",
        "full",
        "passive",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pion_to_str0m_offerer_passive_lite() {
    test_pion_client_to_str0m_server(
        "pion_str0m_offerer_passive_lite",
        "offerer",
        "lite",
        "passive",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pion_to_str0m_answerer_active_full() {
    test_pion_client_to_str0m_server(
        "pion_str0m_answerer_active_full",
        "answerer",
        "full",
        "active",
    )
    .await;
}

// ───────────────────────────────────────────────────────────────
// Test cases: str0m client → pion server
// ───────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn str0m_to_pion_offerer_active_full() {
    test_str0m_client_to_pion_server(
        "str0m_pion_offerer_active_full",
        "offerer",
        "full",
        "active",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn str0m_to_pion_offerer_active_lite() {
    test_str0m_client_to_pion_server(
        "str0m_pion_offerer_active_lite",
        "offerer",
        "lite",
        "active",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn str0m_to_pion_offerer_passive_full() {
    test_str0m_client_to_pion_server(
        "str0m_pion_offerer_passive_full",
        "offerer",
        "full",
        "passive",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn str0m_to_pion_offerer_passive_lite() {
    test_str0m_client_to_pion_server(
        "str0m_pion_offerer_passive_lite",
        "offerer",
        "lite",
        "passive",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn str0m_to_pion_answerer_active_full() {
    test_str0m_client_to_pion_server(
        "str0m_pion_answerer_active_full",
        "answerer",
        "full",
        "active",
    )
    .await;
}
