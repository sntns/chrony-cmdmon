//! Requests encoded exactly as the installed chronyc encodes them, whatever
//! its version: `CHRONY_CMDMON_CHRONYC=/usr/bin/chronyc cargo test --test
//! chronyc_live` (skipped without the variable; `ci/test-chrony.sh` sets
//! it). For each command, chronyc is pointed at a socket of the test's own
//! (`chronyc -h`): nothing reaches a chronyd. A command an older chronyc does
//! not know is skipped.

mod common;

use std::os::unix::net::UnixDatagram;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;

use common::*;

/// The first packet chronyc sends for `command`, if it sends one.
fn capture(chronyc: &str, dir: &std::path::Path, command: &str) -> Option<Vec<u8>> {
    let socket = dir.join("capture.sock");
    let _ = std::fs::remove_file(&socket);
    let server = UnixDatagram::bind(&socket).unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut child = Command::new(chronyc)
        // The zone `settime`'s date was captured in (fixed: CET).
        .env("TZ", "CET-1")
        .arg("-h")
        .arg(&socket)
        .args(command.split(' '))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut buffer = [0u8; 2048];
    let packet = server.recv(&mut buffer).ok().map(|n| buffer[..n].to_vec());
    let _ = child.kill();
    let _ = child.wait();
    packet
}

#[test]
fn every_request_is_encoded_as_this_chronyc_encodes_it() {
    let Ok(chronyc) = std::env::var("CHRONY_CMDMON_CHRONYC") else {
        eprintln!("CHRONY_CMDMON_CHRONYC not set: skipped");
        return;
    };
    let version = Command::new(&chronyc).arg("--version").output().unwrap();
    let version_text = String::from_utf8_lossy(&version.stdout);
    eprintln!("{}", version_text.trim());
    let version = parse_version(&version_text);
    let dir = std::env::temp_dir().join(format!("chrony-cmdmon-live-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let (mut matched, mut skipped, mut mismatches) = (0, Vec::new(), Vec::new());
    for command in commands() {
        let Some(theirs) = capture(&chronyc, &dir, command) else {
            skipped.push(command);
            continue;
        };
        match encode_like(&request(command), &theirs, version) {
            None => mismatches.push(format!(
                "`{command}`: chronyc sent command {}, unknown here",
                u16::from_be_bytes([theirs[4], theirs[5]])
            )),
            Some(ours) => match difference(&ours, &theirs) {
                None => matched += 1,
                Some(difference) => mismatches.push(format!("`{command}`: {difference}")),
            },
        }
    }
    std::fs::remove_dir_all(&dir).unwrap();
    eprintln!(
        "{matched} identical, {} not known to this chronyc: {skipped:?}",
        skipped.len()
    );
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    assert!(matched > 0);
}
