//! Opt-in: requires Wireshark 5.0rc+, Npcap/libpcap, and capture permissions.
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use telemetryradar::process_tree::{CaptureScope, ProcessSelection};
use telemetryradar::wireshark::{CaptureOptions, CapturePhase, CaptureSession, Installation};

#[test]
#[ignore = "requires installed Wireshark and capture privileges"]
fn traffic_helper() {
    let Ok(address) = std::env::var("TELEMETRYRADAR_TEST_ADDRESS") else {
        return;
    };
    if let Ok(pid_file) = std::env::var("TELEMETRYRADAR_TEST_TREE") {
        let mut command = [0];
        std::io::stdin().read_exact(&mut command).unwrap();
        if command == [0] {
            return;
        }
        let child_exe = std::env::var_os("TELEMETRYRADAR_TEST_CHILD_EXE")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::env::current_exe().unwrap());
        let mut child = Command::new(child_exe)
            .args(["--ignored", "--exact", "traffic_helper", "--nocapture"])
            .env_remove("TELEMETRYRADAR_TEST_TREE")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        std::fs::write(pid_file, child.id().to_string()).unwrap();
        assert!(child.wait().unwrap().success());
        return;
    }
    let mut socket = TcpStream::connect(address).unwrap();
    for _ in 0..40 {
        socket.write_all(b"telemetryradar-loopback-test").unwrap();
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
#[ignore = "requires installed Wireshark and capture privileges"]
fn captures_system_scope_without_pid_selection() {
    let installation = Installation::detect(None).unwrap();
    let interface = installation
        .interfaces()
        .unwrap()
        .into_iter()
        .find(|i| {
            i.description.contains("Loopback")
                || i.description.starts_with("lo ")
                || i.description == "lo"
        })
        .expect("loopback interface");
    let directory = tempfile::tempdir().unwrap();
    let session = CaptureSession::start(
        installation,
        CaptureOptions {
            interfaces: vec![interface.index.to_string().into()],
            output: directory.path().join("system.pcapng"),
            duration: Some(Duration::from_secs(15)),
            ..Default::default()
        },
    )
    .unwrap();
    // An idle adapter must become ready from dumpcap's status acknowledgement,
    // without generating probe traffic or waiting for the first packet.
    let deadline = Instant::now() + Duration::from_secs(30);
    while session.phase() != CapturePhase::Recording {
        assert!(!session.is_finished(), "capture ended before ready");
        assert!(Instant::now() < deadline, "capture startup timed out");
        thread::sleep(Duration::from_millis(20));
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut server, _) = listener.accept().unwrap();
    client.write_all(b"system-scope-test").unwrap();
    let mut data = [0; 17];
    server.read_exact(&mut data).unwrap();
    drop(client);
    drop(server);
    thread::sleep(Duration::from_millis(200));
    let report = session.wait().unwrap();
    assert!(report.captured_packets > 0);
    assert_eq!(report.selected_packets, report.captured_packets);
    assert!(report.processes.is_empty());
    assert!(report.images.is_empty());
    assert!(report.output.is_file());
}

#[test]
#[ignore = "requires installed Wireshark and capture privileges"]
fn captures_invalid_filter_reports_failure_before_ready() {
    let installation = Installation::detect(None).unwrap();
    let interface = installation
        .interfaces()
        .unwrap()
        .into_iter()
        .find(|i| {
            i.description.contains("Loopback")
                || i.description.starts_with("lo ")
                || i.description == "lo"
        })
        .expect("loopback interface");
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("invalid.pcapng");
    let session = CaptureSession::start(
        installation,
        CaptureOptions {
            interfaces: vec![interface.index.to_string().into()],
            output: output.clone(),
            capture_filter: Some("tcp and (".into()),
            duration: Some(Duration::from_secs(2)),
            ..Default::default()
        },
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while !session.is_finished() {
        assert_ne!(session.phase(), CapturePhase::Recording);
        assert!(
            Instant::now() < deadline,
            "invalid filter did not fail promptly"
        );
        thread::sleep(Duration::from_millis(20));
    }
    let error = session.wait().unwrap_err();
    let (operation, recovery) = match &error {
        telemetryradar::Error::Recovery {
            operation,
            directory,
        } => (operation.as_ref(), directory),
        _ => panic!("capture failure did not retain diagnostics: {error}"),
    };
    assert!(
        matches!(
            operation,
            telemetryradar::Error::Tool {
                tool: "dumpcap",
                ..
            }
        ),
        "{error}"
    );
    assert!(recovery.join("dumpcap.log").is_file());
    assert!(
        error.to_string().to_lowercase().contains("filter"),
        "{error}"
    );
    assert!(!output.exists());
}

#[test]
#[ignore = "requires installed Wireshark and capture privileges"]
fn captures_all_interfaces_without_status_framing_errors() {
    let installation = Installation::detect(None).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let session = CaptureSession::start(
        installation,
        CaptureOptions {
            output: directory.path().join("all-interfaces.pcapng"),
            capture_filter: Some("tcp port 9".into()),
            duration: Some(Duration::from_secs(2)),
            ..Default::default()
        },
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while !session.is_finished() {
        assert!(
            Instant::now() < deadline,
            "all-interface capture did not finish"
        );
        thread::sleep(Duration::from_millis(20));
    }
    let report = session.wait().unwrap();
    assert!(report.output.is_file());
    assert_eq!(report.selected_packets, report.captured_packets);
}

#[test]
#[ignore = "requires installed Wireshark and capture privileges"]
fn captures_descendant_traffic_and_stops_on_request() {
    let installation = Installation::detect(None).unwrap();
    let interface = installation
        .interfaces()
        .unwrap()
        .into_iter()
        .find(|i| {
            i.description.contains("Loopback")
                || i.description.starts_with("lo ")
                || i.description == "lo"
        })
        .expect("loopback interface");
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("tree.pcapng");
    let pid_file = directory.path().join("child.pid");
    // A distinct selected image keeps the test driver outside the selection.
    let helper = directory.path().join(if cfg!(windows) {
        "selected-helper.exe"
    } else {
        "selected-helper"
    });
    std::fs::copy(std::env::current_exe().unwrap(), &helper).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut root = Command::new(&helper)
        .args(["--ignored", "--exact", "traffic_helper", "--nocapture"])
        .env(
            "TELEMETRYRADAR_TEST_ADDRESS",
            listener.local_addr().unwrap().to_string(),
        )
        .env("TELEMETRYRADAR_TEST_TREE", &pid_file)
        .env(
            "TELEMETRYRADAR_TEST_CHILD_EXE",
            std::env::current_exe().unwrap(),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let original_pid = root.id();
    let session = CaptureSession::start(
        installation.clone(),
        CaptureOptions {
            scope: CaptureScope::ProcessTrees(ProcessSelection::from_pids(&[root.id()]).unwrap()),
            interfaces: vec![interface.index.to_string().into()],
            output: output.clone(),
            duration: Some(Duration::from_secs(15)),
            ..Default::default()
        },
    )
    .unwrap();
    let startup = Instant::now();
    loop {
        if session.phase() == CapturePhase::Recording {
            break;
        }
        assert!(
            !session.is_finished(),
            "capture ended before becoming ready"
        );
        assert!(
            startup.elapsed() < Duration::from_secs(20),
            "capture startup timeout"
        );
        thread::sleep(Duration::from_millis(20));
    }
    // The originally selected process exits completely. Its replacement is
    // launched by the unselected test driver, so ancestry alone cannot match it.
    root.stdin.as_mut().unwrap().write_all(&[0]).unwrap();
    assert!(root.wait().unwrap().success());
    root = Command::new(&helper)
        .args(["--ignored", "--exact", "traffic_helper", "--nocapture"])
        .env(
            "TELEMETRYRADAR_TEST_ADDRESS",
            listener.local_addr().unwrap().to_string(),
        )
        .env("TELEMETRYRADAR_TEST_TREE", &pid_file)
        .env(
            "TELEMETRYRADAR_TEST_CHILD_EXE",
            std::env::current_exe().unwrap(),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let restarted_pid = root.id();
    root.stdin.as_mut().unwrap().write_all(&[1]).unwrap();
    let (mut socket, _) = listener.accept().unwrap();
    let mut bytes = Vec::new();
    socket.read_to_end(&mut bytes).unwrap();
    assert!(root.wait().unwrap().success());
    let child_pid: u32 = std::fs::read_to_string(pid_file).unwrap().parse().unwrap();
    // Generate traffic outside the selected process tree on a distinct port.
    let unrelated = TcpListener::bind("127.0.0.1:0").unwrap();
    let unrelated_port = unrelated.local_addr().unwrap().port();
    let mut sender = TcpStream::connect(unrelated.local_addr().unwrap()).unwrap();
    let (mut receiver, _) = unrelated.accept().unwrap();
    for _ in 0..10 {
        sender.write_all(b"unrelated").unwrap();
        receiver.read_exact(&mut [0; 9]).unwrap();
        thread::sleep(Duration::from_millis(50));
    }
    let stopped = Instant::now();
    session.stop();
    let report = session.wait().unwrap();
    assert!(stopped.elapsed() < Duration::from_secs(10));
    assert!(report.processes.iter().any(|p| p.pid == child_pid));
    assert!(report.processes.iter().any(|p| p.pid == original_pid));
    assert!(report.processes.iter().any(|p| p.pid == restarted_pid));
    assert!(!report.processes.iter().any(|p| p.pid == std::process::id()));
    assert!(report.selected_packets > 0);
    assert!(report.selected_packets < report.captured_packets);
    let initial_syn = Command::new(&installation.tshark)
        .arg("-r")
        .arg(&output)
        .arg("-Y")
        .arg(format!(
            "tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.dstport == {}",
            listener.local_addr().unwrap().port()
        ))
        .args(["-T", "fields", "-e", "frame.number"])
        .output()
        .unwrap();
    assert!(initial_syn.status.success());
    assert!(
        !initial_syn.stdout.is_empty(),
        "initial connection packets were lost"
    );
    let unrelated_packets = Command::new(&installation.tshark)
        .arg("-r")
        .arg(&output)
        .arg("-Y")
        .arg(format!("tcp.port == {unrelated_port}"))
        .args(["-T", "fields", "-e", "frame.number"])
        .output()
        .unwrap();
    assert!(unrelated_packets.status.success());
    assert!(
        unrelated_packets.stdout.is_empty(),
        "unrelated packets were retained"
    );
    let packets = Command::new(&installation.tshark)
        .arg("-r")
        .arg(&output)
        .args(["-T", "fields", "-e", "frame.process.pid"])
        .output()
        .unwrap();
    assert!(
        packets.status.success(),
        "{}",
        String::from_utf8_lossy(&packets.stderr)
    );
    let pids = String::from_utf8_lossy(&packets.stdout);
    assert!(
        pids.split(|c: char| !c.is_ascii_digit())
            .any(|s| s == child_pid.to_string()),
        "no child metadata: {pids}"
    );
    let allowed: Vec<_> = report.processes.iter().map(|p| p.pid.to_string()).collect();
    for line in pids.lines() {
        assert!(
            line.split(',').any(|pid| allowed.iter().any(|p| p == pid)),
            "unselected packet: {line}"
        );
    }
}
