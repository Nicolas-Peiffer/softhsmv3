# Using PKCS #&#8203;11 hardware security devices for OpenPGP operations

[![status-badge](https://ci.codeberg.org/api/badges/heiko/openpgp-pkcs11/status.svg)](https://ci.codeberg.org/heiko/openpgp-pkcs11)
[![Mastodon](https://img.shields.io/badge/mastodon-read-5da168.svg)](https://fosstodon.org/@hko)
[![Matrix: #openpgp-card:matrix.org](https://matrix.to/img/matrix-badge.svg)](https://matrix.to/#/#openpgp-card:matrix.org)

**NOTE: This project is a work in progress, it is not yet intended for production use!**

This repository contains two Rust crates:

- In [`lib` (openpgp-pkcs11-sequoia)](https://codeberg.org/heiko/openpgp-pkcs11/src/branch/main/lib):
  a library for using PKCS #&#8203;11 devices in an OpenPGP context.  
  [![crates.io openpgp-pkcs11-sequoia](https://img.shields.io/crates/v/openpgp-pkcs11-sequoia.svg)](https://crates.io/crates/openpgp-pkcs11-sequoia)
  [![docs.rs openpgp-pkcs11-sequoia](https://img.shields.io/badge/docs.rs-openpgp--pkcs11--sequoia-66c2a5?logo=docs.rs)](https://docs.rs/openpgp-pkcs11-sequoia)

- In [`cli` (openpgp-pkcs11-tools)](https://codeberg.org/heiko/openpgp-pkcs11/src/branch/main/cli):
  the experimental `opgpkcs11` CLI tool for performing OpenPGP operations on PKCS #&#8203;11 devices.  
  [![crates.io openpgp-pkcs11-tools](https://img.shields.io/crates/v/openpgp-pkcs11-tools.svg)](https://crates.io/crates/openpgp-pkcs11-tools)

See https://codeberg.org/heiko/pkcs11-openpgp-notes for more context.
