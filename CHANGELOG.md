# Changelog

## 0.1.0

First release.

- **Protocol:** chronyd's command and monitoring protocol, version 6 (chrony 4.x). Every command chronyd 4.8 accepts (60 requests) and every reply it sends (16 kinds), encoded and decoded without I/O.
- **Client:** an async client over chronyd's Unix socket (tokio), with retries and a method for each `chronyc` report and command.
- **Tests:**
  - against chronyc 4.8's own packets (byte for byte);
  - against chronyd 4.8's replies (as chronyc prints them);
  - property tests;
  - a scripted chronyd;
  - an optional live chronyd.
