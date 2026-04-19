# Changelog

All notable changes to the `openssh-pkcs11` connector are documented in this
file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

### Changed

- **Relocated into `pqctoday-hsm` as `openssh-pkcs11/`.** Previously maintained
  in the standalone `pqctoday/pqctoday-openssh` repo; consolidated alongside
  the other PKCS#11 connectors (`strongswan-pkcs11/`, `JavaJCE/`, `openpgp/`,
  `webrpc/`). Build now runs from the hsm root:
  `bash openssh-pkcs11/scripts/build-wasm.sh`.
- **`scripts/build-wasm.sh` — major Emscripten-portability fixes (partial):**
  - Dropped `-s SHARED_MEMORY=1` / `-s PTHREAD_POOL_SIZE=2`. softhsmv3 and
    OpenSSL WASM archives were compiled single-threaded (no `+atomics` Wasm
    feature), so pthread-enabled linkage was refused by wasm-ld. JS-side
    `SharedArrayBuffer` transport via `socket_wasm.c` still works through
    asyncify imports.
  - Added `--host=wasm32-unknown-emscripten` and `--without-openssl-header-check`.
  - Post-autoreconf Python patch injects `cross_compiling=yes` into `configure`
    right before the OpenSSL header/library version tests. Needed because
    emcc's node fallback lets autoconf's probes "run" (reading/writing
    MEMFS, not host FS), which confuses the version-detection conftest.
  - Expanded CFLAGS with `-Wno-error=` for clang 15+ default-errors:
    `implicit-function-declaration`, `int-conversion`,
    `incompatible-pointer-types`, `incompatible-function-pointer-types`,
    `implicit-int`, `deprecated-declarations`.
  - Added 18 `ac_cv_func_*=no` / `ac_cv_header_*=no` autoconf-cache
    overrides so OpenSSH routes BSD functions (`arc4random`, `bcrypt_pbkdf`,
    `recallocarray`, `strtonum`, `fmt_scaled`, `readpassphrase`, `closefrom`,
    `freezero`, `timingsafe_bcmp`, `nlist`, `getrrsetbyname`) through
    `openbsd-compat/` instead of linking to Emscripten's header-less musl
    symbols.

### Known Issues

- **Full WASM build does not complete yet.** Build gets through sshd
  `emconfigure` cleanly and into `emmake`, but stops with `dns.c` errors
  complaining that `struct rrsetinfo`, `ERRSET_*`, and `RRSET_VALIDATED` are
  undeclared. The `ac_cv_func_getrrsetbyname=no` cache override was silently
  ignored by autoconf (`config.h` still shows `HAVE_GETRRSETBYNAME 1`) — the
  check is gated by a non-cached probe that needs further investigation.
  Possible follow-ups: patch `dns.c` to unconditionally include
  `openbsd-compat/getrrsetbyname.h`, or compile with `-DHAVE_GETRRSETBYNAME=0`
  and adjust the `openbsd-compat/Makefile.in` to include the replacement.
  Additional BSD-specific quirks may surface once `dns.c` compiles. Artifacts
  in `pqctoday-hub/public/wasm/openssh-{client,server}.{js,wasm}` are still
  the pre-move build; hub UI shows "Build in progress" notice.

### Added

- **Initial release** — ML-DSA-65 patches and WASM build scaffolding for
  OpenSSH, implementing
  [draft-sfluhrer-ssh-mldsa-06](https://datatracker.ietf.org/doc/draft-sfluhrer-ssh-mldsa/).
- **`patches/ssh-mldsa.c`** — new OpenSSH key-type module implementing the
  `ssh-mldsa-65` algorithm (NIST Category 3, FIPS 204). Public-key format is
  the raw 1,952-byte ML-DSA pk; signing is PKCS#11-only and delegates to
  `pqctoday-hsm` softhsmv3 via `CKM_ML_DSA` (0x1d).
- **`patches/apply_mldsa_patches.py`** — Python driver that applies the full
  set of source-tree patches to an extracted `openssh-portable` tree
  (`sshkey.c`, `ssh-pkcs11.c`, `Makefile.in`, etc.).
- **`wasm-shims/sshd_wasm_main.c`** — privsep-free `sshd` entry point for the
  WASM build. Replaces `fork()` / PAM / PTY / `setuid()` with a single-transport
  handshake running over a SharedArrayBuffer socket shim.
- **`wasm-shims/pkcs11_static.c`** — static `C_GetFunctionList` linkage against
  softhsmv3 so the WASM bundle ships self-contained without `dlopen`.
- **`wasm-shims/{posix_stubs,socket_wasm}.c`** — POSIX/networking stubs for
  Emscripten, bridging OpenSSH's file-descriptor I/O to the browser's
  SharedArrayBuffer transport.
- **`scripts/build-wasm.sh`** — end-to-end Emscripten build driver producing
  `openssh-client.{js,wasm}` and `openssh-server.{js,wasm}` bundles.
- **`scripts/copy-to-hub.sh`** — deploys built WASM bundles into the
  `pqctoday-hub` repo for the SSH ML-DSA-65 learning scenario.
