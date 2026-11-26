//! Requests encoded exactly as chronyc encodes them.
//!
//! `fixtures/chronyc-requests.tsv` holds the first packet chronyc 4.8 sent
//! for each command, captured on a socket of its own (`chronyc -h`): the
//! command, a tab, the packet in hex. Each must match this crate's encoding
//! of the same request byte for byte, but for the sequence number and the
//! attempt count, which are the client's own. `chronyc_live.rs` does the
//! same with the chronyc installed, whatever its version.

mod common;

use common::*;

#[test]
fn every_request_is_encoded_as_chronyc_encodes_it() {
    let fixtures = include_str!("fixtures/chronyc-requests.tsv");
    let mut checked = 0;
    let mut mismatches = Vec::new();
    for line in fixtures.lines().filter(|l| !l.starts_with('#')) {
        let (command, packet) = line.split_once('\t').unwrap();
        let chronyc = unhex(packet);
        match encode_like(&request(command), &chronyc, (4, 8)) {
            None => mismatches.push(format!("`{command}`: chronyc sent another command")),
            Some(ours) => {
                if let Some(difference) = difference(&ours, &chronyc) {
                    mismatches.push(format!("`{command}`: {difference}"));
                }
            }
        }
        checked += 1;
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    assert_eq!(checked, 69);
}
