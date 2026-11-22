# probes

Throwaway scripts and small probe crates that test platform premises the design relies on
(runner admin rights, Windows service start, socket-activated daemons, transport behavior).
They are not part of the product:

- Not in the Cargo workspace (`exclude = ["probes"]`); never published; ignored by the boundary check.
- Run only on GitHub-hosted runners by `.github/workflows/probes.yml`. Every script refuses to
  run (exit 3, nothing touched) unless `GITHUB_ACTIONS=true` and `RUNNER_ENVIRONMENT=github-hosted`
  (fallback if the runner does not set it: `GITHUB_ACTIONS=true` plus a non-empty `ImageOS`).
  They change runner security settings (services, launchd, systemd, trust stores), so they never
  run on a developer machine. The one local probe (P-X1) changes nothing.
- Each probe writes `probe-results/<id>.json` with `verdict` (PASS, FAIL or INVALID) and `control`
  (ok or failed). A control is an instrument check that must behave in a known way; if it does
  not, the verdict is forced to INVALID. The workflow uploads the file as artifact `probe-<id>`.
- Result details carry named fields only: never an environment, a registry hive, a keychain or a
  file dump. Passwords for users a probe creates are generated at run time and never printed.

Helpers: `lib/result.sh` and `lib/result.ps1` (guard and result writer; `--self-test` /
`-SelfTest` exercise them in a temp dir). `runner-facts/` is P-R0 (admin rights and runner facts
on all three OSes).

## P-U1: LuneUI on hosted runners

`luneui/run.sh` (Linux, macOS) and `luneui/run.ps1` (Windows) clone `lune-rs/luneui-rs` at commit
`ec17ff0` (v0.5.1) into `RUNNER_TEMP` (no Cargo dependency, lock or path in this repo refers to it),
build the gallery `--release` with the runner's stable toolchain, run `gallery --dump` headless
(PNG count; adapter name and backend from the gallery's `--bench` line), then open the window for
about 5 s and take one screenshot (details only). Controls: the clone is at the pin; the binary
lists its scenes; on Linux `--dump` must fail to find an adapter before Mesa is installed; at least
one dumped PNG has more than one colour. PASS: the dump rendered and the controls hold. FAIL: no
adapter or no PNG with the controls ok. INVALID otherwise. Results: `probe-results/P-U1-<os>.json`.

## P-M3: macOS root premises of the per-machine install

`macos/p-m3-pkg-daemon.sh` (job `p-m3`, `macos-latest`) builds two throwaway packages with
`pkgbuild` and `productbuild` and installs them with `installer` under the names
`/Library/Application Support/lunepack-probe-m3`, label `lunepack-probe-m3`,
`/var/run/lunepack-probe-m3.sock` and `/Applications/LpProbeM3.app` (the probe refuses, touching
nothing, when any of them exists). **V1** stages the folders from `/` with a `postinstall`: as root it
copies an ad-hoc-signed daemon out of the payload bundle, links it, swaps two folders with
`renamex_np`, writes a LaunchDaemon plist (`Sockets`, `SockPathMode` 438, no `RunAtLoad`) and runs
`launchctl bootstrap system`. **V2** stages only the leaf folder with it as the install location and
no scripts. A standard user (random password made at run time, never printed) connects through
python3. Control: with `SockPathMode` 384 the user must get `EACCES` and no daemon may start.

PASS needs all of:

- A1: the socket is root-owned `srw-rw-rw-`; two connections are served by one pid with euid 0, the
  user's uid as peer credential and euid 0 read by the client with `getpeereid`; a connection after the
  idle exit gets a new pid.
- A3: the postinstall ran as uid 0 and `installer` exited 0.
- A6: `renamex_np(RENAME_SWAP)` returned 0 from the postinstall and from the daemon, and the marker
  files changed places each time.
- A7: `codesign --verify --strict` of the copied daemon passes and the daemon answered from that file
  through the link.
- P4 and P8 together, for V1 or V2: `installer` exited 0, owner, group, mode and ACL of `/Library` and
  `/Library/Application Support` are unchanged, the machine home is root-owned with no group or other
  write and with search for other, and `.installer` and its leaf are root-owned with no bits for group
  or other and no ACL. When neither variant qualifies the verdict is FAIL (the macOS design is revised).

Recorded, not judged: `sw_vers`, whether the daemon answered with no approval prompt (A2, headless
half) and whether `sfltool dumpbtm` lists the label, the postinstall's umask, working directory,
environment size and whether `HOME` was set, every folder's owner, group, mode and ACL after V1, after
V1 again over a home set to 0711, and after V2, the `lsbom` rows of the staged folders in both
packages, and the number of daemon starts. Result: `probe-results/P-M3.json`.
