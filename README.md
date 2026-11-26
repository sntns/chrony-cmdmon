# chrony-cmdmon

An async Rust client for [chrony](https://chrony-project.org)'s command and
monitoring protocol: what `chronyc` speaks to `chronyd`, over chronyd's Unix
socket.

```rust
let chronyd = chrony_cmdmon::Client::connect(chrony_cmdmon::DEFAULT_SOCKET).await?;

let tracking = chronyd.tracking().await?;
println!("synchronized: {}, offset {:+.6} s", tracking.synchronized(), tracking.current_correction);

for source in chronyd.sources().await? {
    println!("{} {} reach {:o}", source.state.symbol(), source.address, source.reachability);
}

chronyd.reload_sources().await?;
```

## What it covers

| `chronyc` | `Client` |
|---|---|
| `tracking` | `tracking()` |
| `sources` | `sources()` |
| `burst n/m` | `burst(n, m)` |
| `online` / `offline` | `set_online(bool)` |
| `makestep` | `make_step()` |
| `reload sources` | `reload_sources()` |

It speaks protocol version 6, the one of chrony 4.x. The `protocol` module encodes the requests and decodes the replies without any I/O, for other transports.

## Notes

- **Privileges.** chronyd accepts privileged commands (`burst`, `makestep`, `reload sources`, ...) on its Unix socket only. That socket (`/run/chrony/chronyd.sock`) is usually reachable by root and chronyd's user only.
- **The client's own socket.** chronyd answers to the address a request came from, so the client binds a socket of its own, as `chronyc` does: `<socket dir>/chrony-cmdmon.<pid>/<random>/sock`. The directories are 0711 and the socket 0666, so that chronyd, which drops root for its own user, can reach it. It is removed when the client is dropped.
- **Retries.** A request is sent again after 1 s without an answer, 3 times in all (`with_timeout`, `with_attempts`).

## Example

`examples/chronyc.rs` is a tiny `chronyc`:

```sh
cargo run --example chronyc -- tracking
cargo run --example chronyc -- /run/chrony/chronyd.sock sources
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

This crate is an independent implementation of the protocol. It contains no code from chrony, which is GPL-2.0, nor from other client libraries.
