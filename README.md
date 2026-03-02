# SoftHSMv3

A modernized fork of [SoftHSM2](https://github.com/softhsm/SoftHSMv2) with **OpenSSL 3.x**, **PKCS#11 v3.2**, and **post-quantum cryptography** support.

## What's New vs SoftHSM2

| Feature | SoftHSM2 (v2.7.0) | SoftHSMv3 |
|---|---|---|
| OpenSSL backend | 1.x (deprecated APIs) | 3.6 (EVP-only) |
| PKCS#11 version | 3.0 | **3.2** (CSD01, April 2025) |
| ML-KEM (FIPS 203) | Not supported | **ML-KEM-512/768/1024** |
| ML-DSA (FIPS 204) | PR only (#809) | **ML-DSA-44/65/87** |
| C_EncapsulateKey | Not supported | **Implemented** |
| C_DecapsulateKey | Not supported | **Implemented** |
| GOST/DES/DSA/DH | Included | Removed (focused codebase) |
| WASM build | Not supported | **Emscripten target** |
| npm package | N/A | **@pqctoday/softhsm-wasm** |

## PQC Algorithms

### ML-KEM (Key Encapsulation Mechanism) - FIPS 203

| Variant | Public Key | Private Key | Ciphertext | Shared Secret | NIST Level |
|---|---|---|---|---|---|
| ML-KEM-512 | 800 B | 1,632 B | 768 B | 32 B | 1 |
| ML-KEM-768 | 1,184 B | 2,400 B | 1,088 B | 32 B | 3 |
| ML-KEM-1024 | 1,568 B | 3,168 B | 1,568 B | 32 B | 5 |

### ML-DSA (Digital Signature Algorithm) - FIPS 204

| Variant | Public Key | Private Key | Signature | NIST Level |
|---|---|---|---|---|
| ML-DSA-44 | 1,312 B | 2,560 B | 2,420 B | 2 |
| ML-DSA-65 | 1,952 B | 4,032 B | 3,293 B | 3 |
| ML-DSA-87 | 2,592 B | 4,896 B | 4,627 B | 5 |

## PKCS#11 v3.2 Mechanisms

```c
// ML-KEM
CKM_ML_KEM_KEY_PAIR_GEN  // Key pair generation
CKM_ML_KEM               // Encapsulate / Decapsulate
C_EncapsulateKey()        // NEW in v3.2: KEM encapsulation
C_DecapsulateKey()        // NEW in v3.2: KEM decapsulation

// ML-DSA
CKM_ML_DSA_KEY_PAIR_GEN  // Key pair generation
CKM_ML_DSA               // Pure ML-DSA sign/verify
CKM_HASH_ML_DSA_*        // Pre-hash ML-DSA variants (SHA-256/384/512, SHA3, SHAKE)
```

## Roadmap

- [ ] Phase 0: Import SoftHSM2 + PKCS#11 v3.2 headers + strip legacy ([#1](https://github.com/pqctoday/softhsmv3/issues/1))
- [ ] Phase 1: OpenSSL 3.x API migration ([#2](https://github.com/pqctoday/softhsmv3/issues/2))
- [ ] Phase 2: ML-DSA support ([#3](https://github.com/pqctoday/softhsmv3/issues/3))
- [ ] Phase 3: ML-KEM + C_EncapsulateKey/C_DecapsulateKey ([#4](https://github.com/pqctoday/softhsmv3/issues/4))
- [ ] Phase 4: Emscripten WASM build ([#5](https://github.com/pqctoday/softhsmv3/issues/5))
- [ ] Phase 5: npm package `@pqctoday/softhsm-wasm` ([#6](https://github.com/pqctoday/softhsmv3/issues/6))
- [ ] Phase 6: PQC Timeline App integration ([#7](https://github.com/pqctoday/softhsmv3/issues/7))

## Building (Native)

```bash
# Requires OpenSSL >= 3.5
mkdir build && cd build
cmake .. -DWITH_CRYPTO_BACKEND=openssl -DENABLE_MLKEM=ON -DENABLE_MLDSA=ON
make
make check
```

## Building (WASM)

```bash
# Requires Emscripten SDK + OpenSSL 3.6 cross-compiled for WASM
mkdir build-wasm && cd build-wasm
emcmake cmake .. -DWITH_CRYPTO_BACKEND=openssl -DENABLE_MLKEM=ON -DENABLE_MLDSA=ON
emmake make
```

## References

- [PKCS#11 v3.2 Specification (CSD01)](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/csd01/pkcs11-spec-v3.2-csd01.html)
- [FIPS 203: ML-KEM Standard](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204: ML-DSA Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [OpenSSL 3.5 ML-KEM Documentation](https://docs.openssl.org/3.5/man7/EVP_PKEY-ML-KEM/)
- [OpenSSL 3.5 ML-DSA Documentation](https://docs.openssl.org/3.5/man7/EVP_PKEY-ML-DSA/)
- [Original SoftHSM2](https://github.com/softhsm/SoftHSMv2)

## License

BSD-2-Clause (same as SoftHSM2). See [LICENSE](LICENSE).

## Acknowledgments

This project is a fork of [SoftHSM2](https://github.com/softhsm/SoftHSMv2) by the OpenDNSSEC project. PQC implementation references Mozilla NSS (Bug 1965329) and Thales Luna HSM documentation.

Maintained by [PQC Today](https://pqctoday.com).
