#!/bin/sh
# Runs the test suite against one chrony version, in Docker:
#   ci/docker-test.sh 4.8 [cargo test filters...]
set -eu
version="$1"
shift
cd "$(dirname "$0")/.."
docker build -q --build-arg CHRONY_VERSION="$version" -t "chrony-cmdmon-ci:$version" ci >/dev/null
docker run --rm \
    -v "$PWD":/src -w /src \
    -v chrony-cmdmon-cargo:/usr/local/cargo/registry \
    -e CARGO_TARGET_DIR="/src/target/docker-$version" \
    "chrony-cmdmon-ci:$version" ci/test-chrony.sh "$@"
