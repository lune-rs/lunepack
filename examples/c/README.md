# The C example app

A C99 console app that does what the shell app of the end-to-end suite and the .NET example do, through
the C API (`../../crates/lunepack-ffi/include/lunepack.h`): `lunepack_startup` first, then the marker file
`e2e-flags` (`crash-on-start`, `exit-without-confirm`, `slow-confirm <secs>`, `hold <secs>`),
`lunepack_confirm_healthy`, and with `--update` the calls `lunepack_updater_check`,
`lunepack_updater_download`, `lunepack_updater_stage` and `lunepack_apply_and_restart`. It writes one line
`<tree version> <outcome>` per step to the file named by `LUNEPACK_E2E_OUT` and its real path to
`LUNEPACK_E2E_DETAIL` (nothing is written when a variable is unset).

The library finds the runtime and the app's tree itself, from the app's own executable, so the app names
neither. `example --selftest` needs no install: it checks the library against its header and prints
`selftest ok`.

The source is one file, plain C99 (it also compiles as C++), and uses nothing but the C library, the
header and two OS calls: the executable's own path and a sleep.

## Build

```
cargo run -p xtask -- build-example-c --out <dir> [--target <lunepack target id>]
```

builds `lunepack-ffi` (release) and the example with the C compiler the `cc` crate finds for the target
(`CC` and `CFLAGS` apply; MSVC on Windows), and places `example` (`example.exe` on Windows) and the
library beside it in `<dir>`: `liblunepack_ffi.so` (rpath `$ORIGIN`), `liblunepack_ffi.dylib` (rpath
`@executable_path`) or `lunepack_ffi.dll`. `<dir>` must be absent or empty. Targets: `linux-x86_64`,
`linux-aarch64`, `windows-x86_64`, `macos-aarch64`, `macos-x86_64`; with none, the host's.

To use the library in an app of your own, build it from a checkout (`cargo build --release -p
lunepack-ffi`; it is not distributed yet), include `lunepack.h` and link `lunepack_ffi`. Pack the folder
with `example` (`example.exe` on Windows) as the entry; `lunepack-runtime` sits beside it once packed.

`crates/lunepack-ffi/tests/c_example.rs` compiles the example with `-std=c99 -Wall -Wextra -Werror`
(`/W4 /WX` on MSVC) against the library of the test build and runs its self-test.
