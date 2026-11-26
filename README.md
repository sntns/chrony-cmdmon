# chrony-cmdmon

An async Rust client for [chrony](https://chrony-project.org)'s command and
monitoring protocol: what `chronyc` speaks to `chronyd`, over chronyd's Unix
socket. It comes with `cmdmon`, a command line tool equivalent to `chronyc`.

```rust
let chronyd = chrony_cmdmon::Client::connect(chrony_cmdmon::DEFAULT_SOCKET).await?;

let tracking = chronyd.tracking().await?;
println!("synchronized: {}, offset {:+.6} s", tracking.synchronized(), tracking.current_correction);

for source in chronyd.sources().await? {
    println!("{}{} {} reach {:o}", source.mode.symbol(), source.state.symbol(), source.address, source.reachability);
}

chronyd.add_source(chrony_cmdmon::NtpSource::pool("pool.ntp.org")).await?;
```

API documentation: [docs.rs/chrony-cmdmon](https://docs.rs/chrony-cmdmon), or
`cargo doc --all-features --open`.

## What it covers

It implements protocol version 6 in full, as chrony 4.0 to 4.9 speak it: 60 requests and every kind of reply.

- **`Client`** has a method for each `chronyc` report and command: `tracking`, `sources`, `sourcestats`, `selectdata`, `ntpdata`, `sourcename`, `authdata`, `activity`, `smoothing`, `rtcdata`, `serverstats`, `manual list`, `clients`, `settime`, `burst`, `online`/`offline`, `onoffline`, `add`, `delete`, `makestep`, `reload sources`, `reset sources`, `refresh`, `reselect`, `dump`, `cyclelogs`, `rekey`, `writertc`, `trimrtc`, `shutdown`, `accheck`/`cmdaccheck`, and others.
- **`Client::request`** sends any `Request` (`minpoll`, `maxdelay`, `local`, `allow`, `selectopts`, `offset`, ...).
- **`protocol`** encodes requests and decodes replies without any I/O, for other transports. `Client::request_raw` returns chronyd's answers undecoded.

Commands that chronyd 4.0 already refused (`logon`, the old client and subnet reports) are left out.

## chrony versions

Some commands changed form within protocol version 6. The client sends the current form. If chronyd refuses it as invalid, the client sends the earlier form and remembers which form that chronyd takes.

| Command | Current form | Earlier form |
|---|---|---|
| `add server/peer/pool` | `ADD_SOURCE2` (4.9 and later) | `ADD_SOURCE` (4.0 to 4.8) |
| `local` | `LOCAL3` (4.6 and later) | `LOCAL2` (4.0 to 4.5) |
| `doffset` | `DOFFSET2` (4.1 and later) | `DOFFSET` (4.0) |

The client also decodes the earlier replies (`serverstats` before 4.4, `ntpdata` before 4.6), with 0 in the fields they lack. A command that an older chronyd does not know (`selectopts` before 4.4, `offset` before 4.6, ...) fails with `Error::Status(Status::Invalid)`.

The CI tests every release listed in [`ci/chrony-versions.txt`](ci/chrony-versions.txt): 4.0, 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.6.1, 4.7, 4.8 and 4.9.

## The `cmdmon` tool

```sh
cargo install chrony-cmdmon --features cli
cmdmon tracking
cmdmon -c sources              # comma-separated values, as chronyc -c
cmdmon -h /run/chrony/chronyd.sock burst 4/4
sudo cmdmon add server ntp.example.org iburst
cmdmon help
```

`cmdmon` takes chronyc's commands and arguments. It prints the reports as chronyc 4.8 does, in the human format and in the `-c` format. It does not resolve names (as with `chronyc -n`) and has no interactive mode.

## Notes

- **Privileges.** chronyd accepts privileged commands (everything that changes something) on its Unix socket only. That socket (`/run/chrony/chronyd.sock`) is usually reachable by root and chronyd's user only.
- **The client's own socket.** chronyd answers to the address a request came from, so the client binds a socket of its own, as `chronyc` does: `<socket dir>/chrony-cmdmon.<pid>/<random>/sock`. The directories are 0711 and the socket 0666, so that chronyd, which drops root for its own user, can reach it. It is removed when the client is dropped.
- **Retries.** A request is sent again after 1 s without an answer, 3 times in all (`with_timeout`, `with_attempts`). A late answer to an earlier request is ignored.
- **Concurrency.** Requests from tasks sharing a client go one at a time.

## Testing

```sh
cargo test --all-features
```

- **Interoperability with chronyc.** `tests/fixtures/chronyc-requests.tsv` holds the packets chronyc 4.8 sent for 69 commands, captured on a socket of its own. Each must be encoded the same, byte for byte, floats included.
- **Real replies.** `tests/fixtures/chronyd-replies.tsv` holds chronyd 4.8's answers to every request that changes nothing, recorded with `examples/capture.rs`. They must decode to what `chronyc -c` printed at the same time (`tests/fixtures/chronyc-outputs.txt`).
- **Properties** (proptest): floats keep their 24 significant bits, every request encodes to its length, and decoding never panics whatever the bytes.
- **Client behaviour**, against a scripted chronyd: retries, late answers, timeouts, sources removed meanwhile, batches of clients, refusals, the fallback to earlier forms, concurrent requests, socket cleanup.
- **`cmdmon`**: argument parsing and output. When a chronyc is available, the tests also check that each report has the same layout as chronyc's.
- **Against a running chronyd**, skipped unless asked:

  ```sh
  sudo CHRONY_CMDMON_SOCKET=/run/chrony/chronyd.sock cargo test --all-features --test live
  ```

  Add `CHRONY_CMDMON_PRIVILEGED=1` to also send the commands that change something (`burst`, `reload sources`, adding and deleting a source). Add `CHRONY_CMDMON_CHRONYC=$(command -v chronyc)` to compare the requests with that chronyc's and the reports with its output.

### Against each chrony version, in Docker

```sh
ci/docker-test.sh 4.9                 # the whole suite
ci/docker-test.sh 4.0 --test live     # cargo test arguments
```

The image builds chrony from its release tarball, with NTS (`ci/Dockerfile`). In the container, `ci/test-chrony.sh` starts two chronyd that never touch the clock (`-x`):

- one serves NTP on port 12300;
- the other is synchronized to it, and the tests use its socket with every option above, the privileged commands included.

### CI

- **`.github/workflows/ci.yml`**, on each push and pull request:
  - the tests with stable Rust and 1.75;
  - formatting, clippy, documentation (warnings are errors), packaging;
  - coverage;
  - the Docker suite against each version of `ci/chrony-versions.txt`.
- **`.github/workflows/upstream.yml`**, every Monday (and on demand): `ci/upstream.sh` looks for chrony releases newer than the newest of `ci/chrony-versions.txt` and runs the Docker suite against each.
  - **Passing:** a pull request adds the version to `ci/chrony-versions.txt`.
  - **Failing:** an issue reports it with the end of the log, once per version.

  `DRY_RUN=1 ci/upstream.sh` shows what it would do. It needs the repository setting *Allow GitHub Actions to create and approve pull requests*. Pull requests opened with the workflow's token do not trigger `ci.yml` themselves. To run it, close and reopen the pull request, or give the workflow a token of its own as `GH_TOKEN`.

## Minimum Rust version

1.75. `.cargo/config.toml` makes cargo pick dependencies compatible with it.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

This crate is an independent implementation of the protocol. It contains no code from chrony, which is GPL-2.0, nor from other client libraries.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
