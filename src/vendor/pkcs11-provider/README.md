[![Build](https://github.com/latchset/pkcs11-provider/actions/workflows/build.yml/badge.svg)](https://github.com/latchset/pkcs11-provider/actions/workflows/build.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# pkcs11-provider

This is an OpenSSL 3.x provider to access Hardware and Software Tokens using
the PKCS#11 Cryptographic Token Interface. Access to tokens depends
on loading an appropriate PKCS#11 driver that knows how to talk to the specific
token. The PKCS#11 provider is a connector that allows OpenSSL to make proper
use of such drivers. This code targets PKCS#11 version 3.2 but is backwards
compatible to version 3.1, 3.0 and 2.40 as well.

To report Security Vulnerabilities, please use the "Report a Security
Vulnerability" template in the issues reporting page.

### Installation

See [BUILD](BUILD.md) for more details about building and installing the provider.

### Usage

Configuration directives for the provider are documented in [provider-pkcs11(7)](docs/provider-pkcs11.7.md)
man page. Example configurations and basic use cases can be found in [HOWTO](HOWTO.md).

### Post-Quantum Cryptography & SoftHSMv3 Support

This vendored provider has been inherently upgraded to support the `SoftHSMv3` implementation of the PKCS#11 v3.2 standard.
- **ML-KEM**: Fully dispatches `OSSL_OP_KEM` encapsulations using FIPS 203 sizes (512, 768, 1024) natively through `C_EncapsulateKey`/`C_DecapsulateKey`.
- **ML-DSA**: Directly maps the FIPS 204 signatures (44, 65, 87) natively down to the HSM via `C_Sign`/`C_Verify`.
- **PKCS#11 v3.x Asynchronous Integrations**: Supports the simulated `CKF_ASYNC_SESSION` mode to decouple blocking threads and unblock asynchronous API network gateways utilizing `C_AsyncComplete` routines natively natively via `CKR_OPERATION_NOT_INITIALIZED`.

### Notes

 * [PKCS #11 Specification Version 3.2](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html)
