# chrony-cmdmon

An async Rust client for [chrony](https://chrony-project.org)'s command and
monitoring protocol: what `chronyc` speaks to `chronyd`, over chronyd's Unix
socket.

```rust
let chronyd = chrony_cmdmon::Client::connect(chrony_cmdmon::DEFAULT_SOCKET).await?;

let tracking = chronyd.tracking().await?;
println!("synchronized: {}, offset {:+.6} s", tracking.synchronized(), tracking.current_correction);

for source in chronyd.sources().await? {
    println!("{}{} {} reach {:o}", source.mode.symbol(), source.state.symbol(), source.address, source.reachability);
}

chronyd.add_source(chrony_cmdmon::NtpSource::pool("pool.ntp.org")).await?;
```

## What it covers

It speaks protocol version 6, the version of chrony 4.x, and implements every command chronyd 4.8 accepts: 60 requests and their 16 kinds of reply.

- **`Client`** has a method for each `chronyc` report and the common commands: `tracking`, `sources`, `sourcestats`, `selectdata`, `ntpdata`, `sourcename`, `authdata`, `activity`, `smoothing`, `rtcdata`, `serverstats`, `manual list`, `clients`, `settime`, `burst`, `online`/`offline`, `onoffline`, `add`, `delete`, `makestep`, `reload sources`, `reset sources`, `refresh`, `reselect`, `dump`, `cyclelogs`, `rekey`, `writertc`, `trimrtc`, `shutdown`, `accheck`/`cmdaccheck`.
- **`Client::request`** sends any `Request`, the rest included (`minpoll`, `maxdelay`, `local`, `allow`, `selectopts`, `offset`, ...).
- **`protocol`** encodes requests and decodes replies without any I/O, for other transports. `Client::request_raw` returns chronyd's answers undecoded.

Commands of earlier protocol versions that chronyd now refuses (`logon`, the first `local` and `add server` forms, `doffset`, the old client and subnet reports) are left out.

## Notes

- **Privileges.** chronyd accepts privileged commands (everything that changes something) on its Unix socket only. That socket (`/run/chrony/chronyd.sock`) is usually reachable by root and chronyd's user only.
- **The client's own socket.** chronyd answers to the address a request came from, so the client binds a socket of its own, as `chronyc` does: `<socket dir>/chrony-cmdmon.<pid>/<random>/sock`. The directories are 0711 and the socket 0666, so that chronyd, which drops root for its own user, can reach it. It is removed when the client is dropped.
- **Retries.** A request is sent again after 1 s without an answer, 3 times in all (`with_timeout`, `with_attempts`). A late answer to an earlier request is ignored.
- **Concurrency.** Requests from tasks sharing a client go one at a time.

## Testing

```sh
cargo test
```

- **Interoperability with chronyc.** `tests/fixtures/chronyc-requests.tsv` holds the packets chronyc 4.8 sent for 69 commands, captured on a socket of its own. Each must be encoded the same, byte for byte, floats included.
- **Real replies.** `tests/fixtures/chronyd-replies.tsv` holds chronyd 4.8's answers to every request that changes nothing, recorded with `examples/capture.rs`. They must decode to what `chronyc -c` printed at the same time (`tests/fixtures/chronyc-outputs.txt`).
- **Properties** (proptest): floats keep their 24 significant bits, every request encodes to its length, and decoding never panics whatever the bytes.
- **Client behaviour**, against a scripted chronyd: retries, late answers, timeouts, sources removed meanwhile, batches of clients, refusals, concurrent requests, socket cleanup.
- **Against a running chronyd**, skipped unless asked:

  ```sh
  sudo CHRONY_CMDMON_SOCKET=/run/chrony/chronyd.sock cargo test --test live
  ```

  Add `CHRONY_CMDMON_PRIVILEGED=1` to also send `burst` and `reload sources`.

## Examples

- `examples/chronyc.rs`: a tiny `chronyc` (`tracking`, `sources`, `burst`, `makestep`, `reload`).
- `examples/capture.rs`: records chronyd's replies to every request that changes nothing (the test fixtures).

```sh
cargo run --example chronyc -- sources
```

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
