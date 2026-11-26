# Changelog

## Unreleased

First release.

- **Protocol:** chronyd's command and monitoring protocol, version 6, as chrony 4.0 to 4.9 speak it. Every request (60) and every kind of reply, encoded and decoded without I/O, the earlier forms of `add`, `local`, `doffset`, `serverstats` and `ntpdata` included.
- **Client:** an async client over chronyd's Unix socket (tokio), with retries and a method for each `chronyc` report and command. It falls back to a command's earlier form when chronyd refuses the current one.
- **`cmdmon`** (feature `cli`): chronyc's equivalent, with the same commands and output (`-c` included).
- **Tests:**
  - against chronyc 4.8's own packets (byte for byte);
  - against chronyd 4.8's replies (as chronyc prints them);
  - property tests;
  - a scripted chronyd;
  - an optional live chronyd and chronyc.
- **CI:** the whole suite in Docker against chrony 4.0 to 4.9, and a weekly check of new chrony releases that opens a pull request (passing) or an issue (failing).
