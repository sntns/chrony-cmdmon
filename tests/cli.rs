//! `cmdmon` against chronyc, on a running chronyd: the same reports in the
//! same comma-separated layout (`-c`), and the commands done. Run by
//! `ci/test-chrony.sh` (`CHRONY_CMDMON_SOCKET`, `CHRONY_CMDMON_CHRONYC`);
//! skipped otherwise. cmdmon prints as chronyc 4.8 and later.

mod common;

use std::process::Command;

use common::*;

/// One test at a time: one adds a source while the other lists them.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Tools {
    socket: String,
    chronyc: String,
}

fn tools() -> Option<Tools> {
    let socket = std::env::var("CHRONY_CMDMON_SOCKET").ok()?;
    let chronyc = std::env::var("CHRONY_CMDMON_CHRONYC").ok()?;
    let version = Command::new(&chronyc).arg("--version").output().ok()?;
    if parse_version(&String::from_utf8_lossy(&version.stdout)) < (4, 8) {
        eprintln!("chronyc before 4.8: its layout differs, skipped");
        return None;
    }
    Some(Tools { socket, chronyc })
}

fn run(program: &str, args: &[&str]) -> Vec<Vec<String>> {
    let output = Command::new(program).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| line.split(',').map(str::to_string).collect())
        .collect()
}

/// Numbers may differ (chronyd updates them between the two runs), the
/// rest may not.
fn same_layout(report: &str, ours: &[Vec<String>], theirs: &[Vec<String>]) {
    assert_eq!(
        ours.len(),
        theirs.len(),
        "{report}: lines\n{ours:?}\n{theirs:?}"
    );
    for (our, their) in ours.iter().zip(theirs) {
        assert_eq!(
            our.len(),
            their.len(),
            "{report}: fields\n{our:?}\n{their:?}"
        );
        for (a, b) in our.iter().zip(their) {
            let numbers = a.parse::<f64>().is_ok() && b.parse::<f64>().is_ok();
            assert!(
                numbers || a == b,
                "{report}: `{a}` against chronyc's `{b}`\n{our:?}\n{their:?}"
            );
        }
    }
}

#[test]
fn reports_are_laid_out_as_chronyc_lays_them_out() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let Some(tools) = tools() else {
        eprintln!("CHRONY_CMDMON_SOCKET or CHRONY_CMDMON_CHRONYC not set: skipped");
        return;
    };
    let cmdmon = env!("CARGO_BIN_EXE_cmdmon");
    for report in [
        "tracking",
        "sources",
        "sourcestats",
        "selectdata",
        "activity",
        "serverstats",
        "authdata",
        "ntpdata",
        "manual list",
    ] {
        let words: Vec<&str> = report.split(' ').collect();
        let mut args = vec!["-c", "-h", &tools.socket];
        args.extend(&words);
        let ours = run(cmdmon, &args);
        let mut args = vec!["-c", "-n", "-h", &tools.socket];
        args.extend(&words);
        let theirs = run(&tools.chronyc, &args);
        same_layout(report, &ours, &theirs);
    }
}

#[test]
fn commands_are_done() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let Some(tools) = tools() else {
        return;
    };
    let cmdmon = env!("CARGO_BIN_EXE_cmdmon");
    for command in [
        "burst 1/2",
        "reload sources",
        "add server 192.0.2.124 offline",
        "delete 192.0.2.124",
    ] {
        let mut args = vec!["-h", tools.socket.as_str()];
        args.extend(command.split(' '));
        assert_eq!(run(cmdmon, &args), [["200 OK"]], "{command}");
    }
    // Human-readable reports too.
    for report in [
        "tracking",
        "sources",
        "sourcestats",
        "selectdata",
        "ntpdata",
    ] {
        run(cmdmon, &["-h", &tools.socket, report]);
    }
}
