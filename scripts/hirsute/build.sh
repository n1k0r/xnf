#!/usr/bin/env bash
SCRIPT_DIR="$(dirname "$0")"
docker build \
    -t xnf-env-focal \
    - <$SCRIPT_DIR/Dockerfile &&
docker run -it --rm \
    -v `pwd`:/xnf \
    -w /xnf \
    -e CARGO_TARGET_DIR=target-hirsute \
    xnf-env-focal \
    cargo deb
