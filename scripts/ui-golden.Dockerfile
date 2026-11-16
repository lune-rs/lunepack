# Reference image for the UI's golden frames (scripts/ui-golden.sh, M6-D9): the gate's pinned Rust
# image plus Mesa's Vulkan drivers, so the software adapter (lavapipe) is the same one on every
# machine that generates or compares the goldens. Built once; ui-golden.sh tags it with this file's
# hash, so editing this file (including the digest) triggers one rebuild. The Mesa version it
# installs is printed by every run and recorded in crates/lunepack-ui-luneui/tests/golden/README.md.
# Base: the same digest as scripts/gate.Dockerfile (rust:1.99.1-slim-trixie, resolved 2026-11-12
# with `docker pull` + `docker inspect`; a multi-platform index, so it serves amd64 and arm64, whose
# lavapipe output was found byte-identical).
FROM rust:1.99.1-slim-trixie@sha256:f6c4a35d21dbb3c89d7a8d056c193e94fc09037f2b58dd858b09c39a47dd02d7
LABEL org.lunepack-rs.purpose="ui-golden"
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends mesa-vulkan-drivers \
 && rm -rf /var/lib/apt/lists/*
