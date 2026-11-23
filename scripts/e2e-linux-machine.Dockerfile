# Image for the Linux per-machine end-to-end suite (scripts/e2e-linux-machine.sh, M11-D16): a
# system with systemd as PID 1, polkit and pkexec, and what the rows use (python3 for the fake
# socket and the byte flips, desktop-file-utils to validate desktop entries, util-linux's
# `runuser`). The release binaries are not in it: the suite builds them in the e2e image and
# mounts them. Built once; the script tags it with this file's hash, so editing this file
# (including the digest) triggers one rebuild. No user is made here: the suite makes its own.
# Base: debian:trixie-slim, resolved 2026-11-23 with `docker pull` + `docker inspect` (RepoDigests;
# a multi-platform index, so it serves amd64 and arm64). The tag alone is not trusted; the digest is.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
LABEL org.lunepack-rs.purpose="e2e-linux-machine"
ENV container=docker
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends \
      systemd systemd-sysv dbus polkitd pkexec util-linux procps iproute2 \
      python3-minimal desktop-file-utils jq ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && systemctl mask getty.target console-getty.service \
      systemd-udevd.service systemd-udev-trigger.service systemd-timesyncd.service \
      apt-daily.timer apt-daily-upgrade.timer dpkg-db-backup.timer e2scrub_all.timer \
      fstrim.timer systemd-tmpfiles-clean.timer 2>/dev/null || true
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
