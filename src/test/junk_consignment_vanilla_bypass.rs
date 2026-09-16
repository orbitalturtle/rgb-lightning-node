use super::*;

use std::fs::File;
use std::net::TcpListener as StdTcpListener;
use std::process::{Child, Command as StdCommand, Stdio};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

const TEST_DIR_BASE: &str = "tmp/junk_consignment_vanilla_bypass/";
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

// Polls the subprocess for exit, returning its status once it has one. Panics once `timeout`
// elapses with the process still running -- meaning the crash this test expects never happened.
async fn wait_for_exit(victim: &mut KillOnDrop, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = victim.0.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            panic!("victim node did not exit within {timeout:?} -- expected crash did not happen");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// SECURITY REPRO (upstream-only variant): a remote peer can crash the node by attaching a fake
/// "consignment" to an entirely ordinary, uncolored (vanilla) channel open.
///
/// `rgb_utils::handle_funding` -- called from `internal_funding_created` on the receiver side --
/// already validates any consignment a *colored* channel-open carries, and cleanly force-closes on
/// bad content well before the funding transaction ever broadcasts. That gate only runs when
/// `inbound_chan.funding.is_colored()`, though, and `rgb_file_transfer.rs`'s chunk acceptor has no
/// way to know whether a channel negotiated as colored -- it only checks that the sender has *a*
/// channel with us. So a peer can open a plain vanilla channel (nothing about it looks colored, the
/// gate above never runs) while separately sending garbage over the same p2p file-transfer
/// mechanism, tagged with that channel's funding txid. `ChannelPending`'s acceptor branch decides
/// whether to load anything purely by `consignment_path.exists()` -- with no link back to whether
/// `handle_funding` ever ran or approved anything -- so it loads the attacker's junk and panics.
///
/// The attacker side here uses the `INJECT_FAKE_CONSIGNMENT_ON_VANILLA_OPEN_ON_NODE` test hook to
/// model exactly that: a node that sends bogus file-transfer chunks independent of what its own
/// REST/RGB layer would ever construct, which is exactly what a peer fully in control of their own
/// node can always do.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn junk_consignment_vanilla_bypass() {
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

    let password = "junk-consignment-vanilla-bypass";
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

    // open a plain vanilla (uncolored) channel attacker -> victim: no asset_amount, no asset_id.
    // The victim auto-accepts it (manually_accept_inbound_channels + unconditional
    // accept_inbound_channel); since it's uncolored, `handle_funding`'s validation gate never runs
    // at all, and the attacker's injected junk file just sits on disk until `ChannelPending` fires.
    //
    // `ChannelPending` fires as soon as both sides have exchanged signed funding messages -- well
    // before the funding tx ever confirms on chain -- so this attack needs no mining at all.
    // `open_channel_raw` only sends the request and returns; it never depends on the victim staying
    // alive, unlike `open_channel`/`open_channel_funded_raw`, which poll the channel status on the
    // attacker's own node and would just time out once the victim is dead.
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

    let status = wait_for_exit(&mut victim, Duration::from_secs(60)).await;
    assert_eq!(
        status.code(),
        Some(70),
        "victim did not exit with the fatal-panic code; full status: {status:?}",
    );
    let log = std::fs::read_to_string(format!("{victim_dir}/subprocess.log")).unwrap();
    assert!(
        log.contains("successful consignment load"),
        "victim's crash was not the expected consignment-load panic; log:\n{log}",
    );
    println!("confirmed: a vanilla channel open + an injected fake consignment crashed the victim");

    // THE CRASH LOOP: relaunch the victim against the very same data dir. The attack is never
    // repeated -- the junk file and the channel-manager state that names it are already on disk --
    // so if restart alone replays `ChannelPending` against them, the victim should hit the very same
    // `.expect()` again with no attacker involvement at all this time.
    let daemon_port_2 = free_port();
    let mut victim_2 = spawn_victim(&victim_dir, daemon_port_2);
    wait_for_daemon_port_ready(daemon_port_2).await;
    let victim_addr_2 = SocketAddr::from(([127, 0, 0, 1], daemon_port_2));
    unlock(victim_addr_2, password).await;

    let status_2 = wait_for_exit(&mut victim_2, Duration::from_secs(30)).await;
    assert_eq!(
        status_2.code(),
        Some(70),
        "victim did not crash again on restart; full status: {status_2:?}",
    );
    let log_2 = std::fs::read_to_string(format!("{victim_dir}/subprocess.log")).unwrap();
    assert!(
        log_2.contains("successful consignment load"),
        "victim's restart crash was not the expected consignment-load panic; log:\n{log_2}",
    );
    println!("confirmed: the victim crashes again on restart, with no attack repeated");
}
