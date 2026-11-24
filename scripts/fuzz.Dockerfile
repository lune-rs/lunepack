# Image for the fuzz campaign (scripts/fuzz.sh, M13-D9): the pinned Rust image of the gate plus a
# C++ compiler (libfuzzer-sys builds libFuzzer from source), one dated nightly toolchain (the
# sanitizer flags need nightly) and cargo-fuzz at an exact version. Built once; fuzz.sh tags it with
# this file's hash, so editing this file (the digest, the nightly date, the version) triggers one
# rebuild. Nothing is installed on the host.
# Base: the same digest as scripts/gate.Dockerfile (rust:1.99.1-slim-trixie, resolved 2026-11-12
# with `docker pull` + `docker inspect`; a multi-platform index, so it serves amd64 and arm64).
# Nightly: nightly-2026-11-20 (rustc 1.102.0-nightly, 2026-11-19), minimal profile. cargo-fuzz
# 0.13.2 is built with the image's stable 1.99.1 and run with that nightly (RUSTUP_TOOLCHAIN, set
# by fuzz.sh), so a new nightly never changes the tool that drives it.
# It holds an unprivileged user `fuzz` (uid 1000) and the two folders fuzz.sh keeps its build output
# in (named volumes of their own), owned by it.
FROM rust:1.99.1-slim-trixie@sha256:f6c4a35d21dbb3c89d7a8d056c193e94fc09037f2b58dd858b09c39a47dd02d7
LABEL org.lunepack-rs.purpose="fuzz"
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends g++ \
 && rm -rf /var/lib/apt/lists/* \
 && rustup toolchain install nightly-2026-11-20 --profile minimal \
 && cargo install --locked --version 0.13.2 cargo-fuzz \
 && rm -rf /usr/local/cargo/registry /usr/local/cargo/git \
 && useradd --create-home --uid 1000 --shell /bin/bash fuzz \
 && install -d -o fuzz -g fuzz /target /cargo-home
