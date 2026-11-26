# A Rust toolchain and chrony built from its release tarball: the test
# environment for one chrony version.
#   docker build --build-arg CHRONY_VERSION=4.8 -t chrony-cmdmon-ci:4.8 ci
ARG RUST_VERSION=1
FROM rust:${RUST_VERSION}-bookworm

# NTS and the hashes of authenticated sources, for every command to exist.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgnutls28-dev nettle-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

ARG CHRONY_VERSION
RUN test -n "$CHRONY_VERSION" \
    && curl -fsSL "https://chrony-project.org/releases/chrony-${CHRONY_VERSION}.tar.gz" -o /tmp/chrony.tar.gz \
    && mkdir /tmp/chrony && tar -xzf /tmp/chrony.tar.gz -C /tmp/chrony --strip-components 1 \
    && cd /tmp/chrony \
    && ./configure --prefix=/usr/local --sysconfdir=/etc --with-rundir=/run/chrony --disable-readline \
    && make -j"$(nproc)" chronyd chronyc \
    && install -m 755 chronyd /usr/local/sbin/chronyd \
    && install -m 755 chronyc /usr/local/bin/chronyc \
    && rm -rf /tmp/chrony /tmp/chrony.tar.gz \
    && chronyc --version

ENV CHRONY_VERSION=${CHRONY_VERSION}
