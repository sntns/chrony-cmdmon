#!/bin/sh
# Runs the test suite against the chrony of the container (see Dockerfile):
# a chronyd serving NTP on port 12300, a second one synchronized to it whose
# command socket the tests use, and its chronyc for the interoperability
# tests. chronyd never touches the clock (-x).
set -eu

# chronyd refuses a socket directory others can read.
mkdir -p -m 750 /run/chrony
chmod 750 /run/chrony
mkdir -p /var/lib/chrony
cat > /tmp/server.conf <<CONF
port 12300
local stratum 5
allow 127.0.0.1
cmdport 0
bindcmdaddress /run/chrony/server.sock
pidfile /run/chrony/server.pid
CONF
cat > /tmp/client.conf <<CONF
server 127.0.0.1 port 12300 iburst minpoll 0 maxpoll 1
port 0
cmdport 0
bindcmdaddress /run/chrony/chronyd.sock
pidfile /run/chrony/chronyd.pid
CONF
chronyd -x -f /tmp/server.conf
chronyd -x -f /tmp/client.conf

# Until the client chronyd is synchronized to the server.
for _ in $(seq 60); do
    chronyc -n tracking | grep -q "Leap status *: Normal" && break
    sleep 1
done
chronyc --version
chronyc -n tracking
chronyc -n sources

export CHRONY_CMDMON_SOCKET=/run/chrony/chronyd.sock
export CHRONY_CMDMON_PRIVILEGED=1
export CHRONY_CMDMON_CHRONYC="$(command -v chronyc)"
cargo test --locked --all-targets --all-features --no-fail-fast -- --nocapture "$@"
