# Image for the end-to-end suite (scripts/e2e.sh, M5-D13): the pinned Rust image of the gate plus
# what the suite needs and the Rust image lacks: the musl C compiler and the musl target of its own
# architecture (the static runtime, scripts/build-runtime.sh), binutils (readelf, which that script
# uses to check the runtime is static) and desktop-file-utils (desktop-file-validate, which checks
# the desktop entries the suite writes). Built once; e2e.sh tags it with this file's hash, so
# editing this file (including the digest) triggers one rebuild.
# Base: the same digest as scripts/gate.Dockerfile (rust:1.99.1-slim-trixie, resolved 2026-11-12
# with `docker pull` + `docker inspect`; a multi-platform index, so it serves amd64 and arm64).
FROM rust:1.99.1-slim-trixie@sha256:f6c4a35d21dbb3c89d7a8d056c193e94fc09037f2b58dd858b09c39a47dd02d7
LABEL org.lunepack-rs.purpose="e2e"
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends binutils desktop-file-utils musl-tools \
 && rm -rf /var/lib/apt/lists/* \
 && rustup target add "$(uname -m)-unknown-linux-musl"
