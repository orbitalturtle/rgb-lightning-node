use super::*;

use std::fs::File;
use std::net::TcpListener as StdTcpListener;
use std::process::{Child, Command as StdCommand, Stdio};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

const TEST_DIR_BASE: &str = "tmp/junk_consignment_vanilla_bypass_fixed/";
const VICTIM_PEER_PORT: u16 = 9820;

// Picks a free TCP port by binding to it and releasing it immediately. There's a race between
// releasing the port here and the victim subprocess binding it, but this test is serialized
// against the rest of the suite and nothing else in it competes for the port in that window.
fn free_port() -> u16 {
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

// Path to the real `rgb-lightning-node` binary, building it first if needed. Unlike the rest of
// this suite -- which drives nodes in-process via `app(args)`, calling straight into library code
// -- this test needs the actual OS process: the crash claim is about that binary's process
// lifecycle (its panic hook, its `std::process::exit`), which `app(args)` never runs.
fn victim_binary_path() -> PathBuf {
    static BUILD: std::sync::Once = std::sync::Once::new();
    BUILD.call_once(|| {
        println!("building rgb-lightning-node binary for the vanilla-bypass repro...");
        let status = StdCommand::new("cargo")
            .args(["build", "--bin", "rgb-lightning-node"])
            .status()
            .expect("failed to invoke cargo build");
        assert!(
            status.success(),
            "failed to build the rgb-lightning-node binary"
        );
    });
    // the test binary lives at <target-dir>/<profile>/deps/<name>-<hash>; the product binary this
    // test just (maybe) built sits one directory up, as a sibling of `deps`.
    let test_exe = std::env::current_exe().expect("current test executable");
    test_exe
        .parent()
        .and_then(Path::parent)
        .expect("test executable has a <target-dir>/<profile>/deps parent")
        .join("rgb-lightning-node")
}

// Kills the wrapped subprocess when dropped, so a failing assertion or timeout in this test never
// leaves an orphaned node process running against the shared regtest backend.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn wait_for_daemon_port_ready(port: u16) {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                drop(stream);
                return;
            }
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(err) => {
                panic!("victim daemon port {port} did not accept connections in time: {err}")
            }
        }
    }
}

// Launches the real node binary as a subprocess against `storage_dir`, with stdout/stderr
// redirected to a log file (rather than piped) so a chatty run before the crash can never block
// the child on a full pipe buffer, while still letting this test inspect the panic message after
// the process exits.
fn spawn_victim(storage_dir: &str, daemon_port: u16) -> KillOnDrop {
    std::fs::create_dir_all(storage_dir).unwrap();
    let log = File::create(format!("{storage_dir}/subprocess.log")).unwrap();
    let child = StdCommand::new(victim_binary_path())
        .arg(storage_dir)
        .args(["--network", "regtest"])
        .args(["--daemon-listening-port", &daemon_port.to_string()])
        .args(["--ldk-peer-listening-port", &VICTIM_PEER_PORT.to_string()])
        .arg("--disable-authentication")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .expect("failed to spawn victim node subprocess");
    KillOnDrop(child)
}

// Confirms the subprocess is still alive after waiting out `window` -- i.e. that it did *not*
// crash in that time. Panics with its exit status (and log) if it did.
async fn assert_still_running(victim: &mut KillOnDrop, storage_dir: &str, window: Duration) {
    tokio::time::sleep(window).await;
    if let Some(status) = victim.0.try_wait().unwrap() {
        let log = std::fs::read_to_string(format!("{storage_dir}/subprocess.log")).unwrap_or_default();
        panic!("victim node exited unexpectedly with status {status:?}; log:\n{log}");
    }
}

/// FIX REGRESSION TEST: the same vanilla-channel-open + injected-fake-consignment attack that
/// crashes the unfixed node (see `junk_consignment_vanilla_bypass` on the sibling
/// `security-repro/vanilla-channel-consignment-crash` branch) must no longer do anything to it.
///
/// The fix makes `ChannelPending`'s acceptor branch decide whether to load a consignment by
/// checking whether `handle_funding` actually validated one for this channel (a pending `RgbInfo`
/// record only it ever writes), instead of trusting `consignment_path.exists()`. For a vanilla
/// (uncolored) channel that record was never written, so the branch now returns early and never
/// touches the attacker's file at all -- the vanilla channel should just open normally, as if the
/// attack had never been attempted.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn junk_consignment_vanilla_bypass_is_fixed() {
    initialize();

    let victim_dir = format!("{TEST_DIR_BASE}victim");
    let attacker_dir = format!("{TEST_DIR_BASE}attacker");
    if Path::new(&victim_dir).is_dir() {
        std::fs::remove_dir_all(&victim_dir).unwrap();
    }

    let daemon_port = free_port();
    let mut victim = spawn_victim(&victim_dir, daemon_port);
    wait_for_daemon_port_ready(daemon_port).await;
    let victim_addr = SocketAddr::from(([127, 0, 0, 1], daemon_port));

    let password = "junk-consignment-vanilla-bypass-fixed";
    init(victim_addr, password, None).await;
    unlock(victim_addr, password).await;
    let victim_pubkey = node_info(victim_addr).await.pubkey;

    // the attacker: an ordinary node from the in-process harness. Its only special behavior is the
    // test hook that makes it send a fake consignment alongside an entirely vanilla channel open --
    // no asset is ever issued or involved, which is exactly the point.
    let (attacker_addr, _) = start_node(&attacker_dir, NODE1_PEER_PORT, false).await;
    fund_and_create_utxos(attacker_addr, None).await;
    let attacker_pubkey = node_info(attacker_addr).await.pubkey;
    let _inject_guard = NodeOverrideGuard::set(
        &INJECT_FAKE_CONSIGNMENT_ON_VANILLA_OPEN_ON_NODE,
        &attacker_pubkey,
    );

    // same attack as the unfixed repro: open a plain vanilla channel and separately inject a fake
    // consignment for its funding txid. `open_channel_raw` only sends the request and returns; it
    // never depends on the victim's own channel-status view, so it works the same whether or not
    // the victim ends up surviving.
    let open_result = tokio::time::timeout(
        Duration::from_secs(30),
        open_channel_raw(
            attacker_addr,
            &victim_pubkey,
            Some(VICTIM_PEER_PORT),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            true,
            true,
        ),
    )
    .await;
    println!("open_channel outcome while attacking the victim: {open_result:?}");

    // the unfixed node panics within about a second of this point (see the sibling repro branch);
    // give it a generous multiple of that and confirm it's still alive and responsive.
    assert_still_running(&mut victim, &victim_dir, Duration::from_secs(10)).await;
    let info = node_info(victim_addr).await;
    println!("victim survived the attack and is still responsive, pubkey {}", info.pubkey);

    let log = std::fs::read_to_string(format!("{victim_dir}/subprocess.log")).unwrap();
    assert!(
        !log.contains("successful consignment load"),
        "victim hit the consignment-load panic despite the fix; log:\n{log}",
    );
    assert!(
        !log.contains("panicked"),
        "victim panicked despite the fix; log:\n{log}",
    );
    println!(
        "confirmed: the vanilla channel open + injected fake consignment no longer crashes the victim"
    );

    // restart, for good measure: the unfixed node also crash-loops on every subsequent startup
    // (see the sibling repro branch's second half). Confirm the fixed node comes back up cleanly
    // instead, with no attack repeated.
    victim.0.kill().unwrap();
    victim.0.wait().unwrap();
    let daemon_port_2 = free_port();
    let mut victim_2 = spawn_victim(&victim_dir, daemon_port_2);
    wait_for_daemon_port_ready(daemon_port_2).await;
    let victim_addr_2 = SocketAddr::from(([127, 0, 0, 1], daemon_port_2));
    unlock(victim_addr_2, password).await;

    assert_still_running(&mut victim_2, &victim_dir, Duration::from_secs(10)).await;
    let info_2 = node_info(victim_addr_2).await;
    println!("victim survived a restart and is still responsive, pubkey {}", info_2.pubkey);

    let log_2 = std::fs::read_to_string(format!("{victim_dir}/subprocess.log")).unwrap();
    assert!(
        !log_2.contains("panicked"),
        "victim panicked on restart despite the fix; log:\n{log_2}",
    );
    println!("confirmed: the victim also restarts cleanly, with no crash loop");
}
