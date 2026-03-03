# PKCS#11 v3.2 Compliance Gap Analysis — softhsmv3 (v2)

**Updated:** 2026-03-03
**Baseline:** Post-Phase-6 (commit `15f7c63`) — full PQC + WASM + npm package complete
**Spec reference:** OASIS PKCS#11 v3.2 CSD01 (<http://docs.oasis-open.org/pkcs11/pkcs11-base/v3.2/>)
**Prior baseline:** Phase 1 (commit `87b27bf`, 2026-03-02) — 50 gaps documented; all 50 now resolved

---

## Executive Summary

| Dimension | Total remaining | BLOCKER | HIGH | MEDIUM | LOW |
|---|---|---|---|---|---|
| C_* function stubs | 22 | — | 4 | 6 | 2 |
| CKM_* mechanisms | 13 | 13 | — | — | — |
| **Actionable (tracked as issues)** | **6 gap groups** | **1** | **2** | **2** | **1** |

All NIST PQC finalists (ML-KEM, ML-DSA, SLH-DSA) are fully implemented.
All v3.2 KEM functions (`C_EncapsulateKey`, `C_DecapsulateKey`) are implemented.
All v3.0 one-shot message sign/verify functions are implemented.
The 22 remaining stubs are optional or low-priority for current PQC use cases,
with the exception of G1 (`CKM_HASH_SLH_DSA*`) which is a parity blocker vs. ML-DSA.

---

## 1. Previously Tracked Gaps — All Resolved

The following 50 gaps were documented in the v1 gap analysis (Phase 1 baseline).
All are now implemented. Closed GitHub issues: #8–#15.

### 1.1 C_* Function Table (14 gaps → all resolved)

| Function | Severity | Resolved in | Issue |
|---|---|---|---|
| `C_GetInterfaceList` | BLOCKER | Phase 2 | #8 |
| `C_GetInterface` | BLOCKER | Phase 2 | #8 |
| `C_EncapsulateKey` | BLOCKER | Phase 3 | #9 |
| `C_DecapsulateKey` | BLOCKER | Phase 3 | #9 |
| `C_MessageSignInit` | HIGH | Phase 2 | #10 |
| `C_SignMessage` | HIGH | Phase 2 | #10 |
| `C_MessageSignFinal` | HIGH | Phase 2 | #10 |
| `C_MessageVerifyInit` | HIGH | Phase 2 | #10 |
| `C_VerifyMessage` | HIGH | Phase 2 | #10 |
| `C_MessageVerifyFinal` | HIGH | Phase 2 | #10 |
| `C_LoginUser` | MEDIUM | Phase 2 | #8 |
| `C_SessionCancel` | MEDIUM | Phase 2 | #8 |
| `C_GetOperationState` | MEDIUM | Phase 2 | — |
| `C_SetOperationState` | MEDIUM | Phase 2 | — |

> Note: `C_LoginUser` and `C_SessionCancel` were marked resolved in the original phase
> mapping but remain as stubs in `main.cpp`. See §2.6 below.

### 1.2 CKM_* Mechanisms (28 gaps → all resolved)

| Mechanism group | Algorithm | Resolved in | Issue |
|---|---|---|---|
| `CKM_ML_DSA_KEY_PAIR_GEN`, `CKM_ML_DSA` | ML-DSA (FIPS 204) | Phase 2 | #12 |
| `CKM_HASH_ML_DSA` + 11 hash variants | ML-DSA pre-hash | Phase 2 | #12 |
| `CKM_SLH_DSA_KEY_PAIR_GEN`, `CKM_SLH_DSA` | SLH-DSA (FIPS 205) | Phase 2 | #13 |
| `CKM_ML_KEM_KEY_PAIR_GEN`, `CKM_ML_KEM` | ML-KEM (FIPS 203) | Phase 3 | #14 |

### 1.3 CKK_* Key Types (3 gaps → all resolved)

| Key type | Hex | Resolved in | Issue |
|---|---|---|---|
| `CKK_ML_DSA` | `0x0000004aUL` | Phase 2 | #12 |
| `CKK_SLH_DSA` | `0x0000004bUL` | Phase 2 | #13 |
| `CKK_ML_KEM` | `0x00000049UL` | Phase 3 | #14 |

### 1.4 CKA_* Attributes (5 gaps → all resolved)

| Attribute | Hex | Resolved in | Issue |
|---|---|---|---|
| `CKA_PARAMETER_SET` | `0x0000061dUL` | Phase 2 | #11 |
| `CKA_ENCAPSULATE` | `0x00000633UL` | Phase 3 | #15 |
| `CKA_DECAPSULATE` | `0x00000634UL` | Phase 3 | #15 |
| `CKA_ENCAPSULATE_TEMPLATE` | `0x0000062aUL` | Phase 3 | #15 |
| `CKA_DECAPSULATE_TEMPLATE` | `0x0000062bUL` | Phase 3 | #15 |

---

## 2. Remaining Gaps (post-Phase-6, newly identified)

All function stubs reside in `src/lib/main.cpp` and return `CKR_FUNCTION_NOT_SUPPORTED`.
Function pointers are wired into `CK_FUNCTION_LIST_3_0` and `CK_FUNCTION_LIST_3_2`
so callers receive a proper PKCS#11 error rather than a crash.

### 2.1 G1 — CKM_HASH_SLH_DSA* — 13 pre-hash mechanism variants (BLOCKER)

**GitHub issue:** #16

SLH-DSA has 13 pre-hash mechanism variants defined in the spec, mirroring ML-DSA:

| Mechanism | Hex value | Operation |
|---|---|---|
| `CKM_HASH_SLH_DSA` | `0x00000034UL` | Pre-hash variant (any digest) |
| `CKM_HASH_SLH_DSA_SHA224` | `0x00000036UL` | Pre-hash with SHA-224 |
| `CKM_HASH_SLH_DSA_SHA256` | `0x00000037UL` | Pre-hash with SHA-256 |
| `CKM_HASH_SLH_DSA_SHA384` | `0x00000038UL` | Pre-hash with SHA-384 |
| `CKM_HASH_SLH_DSA_SHA512` | `0x00000039UL` | Pre-hash with SHA-512 |
| `CKM_HASH_SLH_DSA_SHA3_224` | `0x0000003aUL` | Pre-hash with SHA3-224 |
| `CKM_HASH_SLH_DSA_SHA3_256` | `0x0000003bUL` | Pre-hash with SHA3-256 |
| `CKM_HASH_SLH_DSA_SHA3_384` | `0x0000003cUL` | Pre-hash with SHA3-384 |
| `CKM_HASH_SLH_DSA_SHA3_512` | `0x0000003dUL` | Pre-hash with SHA3-512 |
| `CKM_HASH_SLH_DSA_SHAKE128` | `0x0000003eUL` | Pre-hash with SHAKE-128 |
| `CKM_HASH_SLH_DSA_SHAKE256` | `0x0000003fUL` | Pre-hash with SHAKE-256 |

All 13 are defined in `src/lib/pkcs11/pkcs11t.h` but:

- **Not registered** in `prepareSupportedMechanisms()` (`src/lib/SoftHSM_slots.cpp:330–473`)
- **Not dispatched** in `src/lib/SoftHSM_sign.cpp` (only `CKM_SLH_DSA` is handled)

ML-DSA has full parity: `CKM_HASH_ML_DSA` + 11 hash variants are registered and dispatched.
SLH-DSA's omission of the hash variants is an asymmetry that must be resolved.

**Implementation approach** (mirrors existing ML-DSA hash dispatch):

1. Add 13 entries to `prepareSupportedMechanisms()` (copy ML-DSA block, substitute SLH_DSA names)
2. Add 13 `case` labels to the `AsymSignInit` / `AsymVerifyInit` dispatch switch in `SoftHSM_sign.cpp`
3. Map each `CKM_HASH_SLH_DSA_*` → the appropriate `HashAlgorithm` enum value + `SLHDSA` mechanism

### 2.2 G2 — Streaming message sign/verify — 4 stubs (HIGH)

**GitHub issue:** #17

The v3.0 message signing API has two modes: one-shot and streaming.
One-shot (`C_SignMessage` / `C_VerifyMessage`) is implemented. Streaming is not.

| Function | `main.cpp` line | Description |
|---|---|---|
| `C_SignMessageBegin` | 1565 | Begin streaming sign; subsequent calls feed chunks |
| `C_SignMessageNext` | 1571 | Feed next chunk; `CKF_END_OF_MESSAGE` flag finalizes |
| `C_VerifyMessageBegin` | 1627 | Begin streaming verify |
| `C_VerifyMessageNext` | 1633 | Feed next chunk; `CKF_END_OF_MESSAGE` flag finalizes |

Streaming mode allows apps to sign multiple messages per `C_MessageSignInit` call
without re-initializing for each message — important for high-throughput ML-DSA signing.

**Spec reference:** PKCS#11 v3.2 §5.18 (Multi-part message operations)

### 2.3 G3 — Message Encrypt/Decrypt API — 10 stubs (HIGH)

**GitHub issue:** #18

The v3.0 message encryption API enables per-message IV generation — a safer pattern than
the caller-supplied IV in `C_EncryptInit`. Required for tokens advertising `CKF_MESSAGE_ENCRYPT`.

| Function | `main.cpp` line | Group |
|---|---|---|
| `C_MessageEncryptInit` | 1454 | Init (AES-GCM with auto-IV) |
| `C_EncryptMessage` | 1460 | One-shot encrypt |
| `C_EncryptMessageBegin` | 1469 | Begin multi-part |
| `C_EncryptMessageNext` | 1476 | Feed chunk |
| `C_MessageEncryptFinal` | 1485 | Finalize session |
| `C_MessageDecryptInit` | 1494 | Init decrypt |
| `C_DecryptMessage` | 1500 | One-shot decrypt |
| `C_DecryptMessageBegin` | 1509 | Begin multi-part |
| `C_DecryptMessageNext` | 1516 | Feed chunk |
| `C_MessageDecryptFinal` | 1525 | Finalize session |

**Spec reference:** PKCS#11 v3.2 §5.14 (Message-based encryption and decryption)

### 2.4 G4 — C_VerifySignature* — 4 stubs (MEDIUM)

**GitHub issue:** #19

New in v3.2: a signature-first verification API where the signature is bound at init time,
and the data is fed at verify time (inverse of `C_VerifyInit` / `C_VerifyFinal`).

| Function | `main.cpp` line | Description |
|---|---|---|
| `C_VerifySignatureInit` | 1682 | Init verify; signature passed here |
| `C_VerifySignature` | 1689 | One-shot: feed all data, get result |
| `C_VerifySignatureUpdate` | 1695 | Feed data chunk |
| `C_VerifySignatureFinal` | 1701 | Finalize and get result |

Useful for ML-DSA and SLH-DSA where signatures are large (2–5 KB) and typically known
before the message data (e.g., in a signature header preceding the payload).

**Spec reference:** PKCS#11 v3.2 §5.17 (Signature verification with bound signature)

### 2.5 G5 — Authenticated wrapping — 2 stubs (MEDIUM)

**GitHub issue:** #20

New in v3.2: AEAD-protected key wrapping with authentication data, distinct from
the existing `C_WrapKey` + `CKM_AES_GCM` combination.

| Function | `main.cpp` line | Description |
|---|---|---|
| `C_WrapKeyAuthenticated` | 1743 | Wrap key with AEAD authentication tag |
| `C_UnwrapKeyAuthenticated` | 1752 | Unwrap and verify authentication tag |

**Spec reference:** PKCS#11 v3.2 §5.22 (Authenticated key wrapping)

### 2.6 G6 — v3.0 session management — 2 stubs (LOW)

**GitHub issue:** #21

These were listed as MEDIUM in the Phase 1 gap analysis but were not implemented.

| Function | `main.cpp` line | Description |
|---|---|---|
| `C_LoginUser` | 1436 | Login with explicit username string (v3.0 extension to `C_Login`) |
| `C_SessionCancel` | 1445 | Cancel an in-progress multi-part operation on a session |

**Spec reference:** PKCS#11 v3.2 §5.6 (Session management)

---

## 3. Explicitly Out of Scope

### 3.1 Async operations — G7

`C_AsyncComplete` (`main.cpp:1720`), `C_AsyncGetID` (`main.cpp:1726`), `C_AsyncJoin` (`main.cpp:1732`)

Requires a separate `CKF_ASYNC_SESSION` session mode, a promise/future-like state machine,
and thread-safe session state. No current PQC tooling requires this. Omission is acceptable
per PKCS#11 v3.2 §3.4 which marks async as optional when not advertised.

### 3.2 Recovery and combined operations — G8

`C_SignRecoverInit`, `C_SignRecover` (`SoftHSM_sign.cpp:1181, 1194`)
`C_VerifyRecoverInit`, `C_VerifyRecover` (`SoftHSM_sign.cpp:2210, 2223`)
`C_DigestEncryptUpdate`, `C_DecryptDigestUpdate`, `C_SignEncryptUpdate`, `C_DecryptVerifyUpdate` (`SoftHSM_sign.cpp:2238–2283`)

These are optional combined/recovery operations defined in PKCS#11 v2.0. SoftHSM2 v2.7.0
also omits them. No PQC algorithm requires them. Not tracked as issues.

### 3.3 Stateful hash-based signatures (HSS, XMSS/XMSSMT)

`CKK_HSS` (`0x00000046UL`), `CKK_XMSS` (`0x00000047UL`), `CKK_XMSSMT` (`0x00000048UL`)
`CKM_HSS_KEY_PAIR_GEN`, `CKM_HSS`, `CKM_XMSS_KEY_PAIR_GEN`, `CKM_XMSSMT_KEY_PAIR_GEN`,
`CKM_XMSS`, `CKM_XMSSMT`

OpenSSL 3.x does not natively support HSS, XMSS, or XMSSMT. These require liboqs or
a specialized provider. The `CKA_HSS_KEYS_REMAINING` attribute (stateful signature counter)
adds additional object-store complexity. Out of scope until OpenSSL adds native support.

---

## 4. Implementation Guidance for G1 (Priority)

G1 is the only BLOCKER and has the most straightforward implementation path since
the infrastructure is already proven by ML-DSA hash variants.

### 4.1 Step 1 — Register in `prepareSupportedMechanisms()`

`src/lib/SoftHSM_slots.cpp`, after the existing ML-DSA block (~line 412):

```cpp
// SLH-DSA pre-hash variants (FIPS 205, PKCS#11 v3.2 §6.x)
addMechanism(CKM_HASH_SLH_DSA,         CKF_SIGN|CKF_VERIFY, 0, 0);
addMechanism(CKM_HASH_SLH_DSA_SHA224,  CKF_SIGN|CKF_VERIFY, 0, 0);
addMechanism(CKM_HASH_SLH_DSA_SHA256,  CKF_SIGN|CKF_VERIFY, 0, 0);
addMechanism(CKM_HASH_SLH_DSA_SHA384,  CKF_SIGN|CKF_VERIFY, 0, 0);
addMechanism(CKM_HASH_SLH_DSA_SHA512,  CKF_SIGN|CKF_VERIFY, 0, 0);
addMechanism(CKM_HASH_SLH_DSA_SHA3_224,CKF_SIGN|CKF_VERIFY, 0, 0);
addMechanism(CKM_HASH_SLH_DSA_SHA3_256,CKF_SIGN|CKF_VERIFY, 0, 0);
addMechanism(CKM_HASH_SLH_DSA_SHA3_384,CKF_SIGN|CKF_VERIFY, 0, 0);
addMechanism(CKM_HASH_SLH_DSA_SHA3_512,CKF_SIGN|CKF_VERIFY, 0, 0);
addMechanism(CKM_HASH_SLH_DSA_SHAKE128,CKF_SIGN|CKF_VERIFY, 0, 0);
addMechanism(CKM_HASH_SLH_DSA_SHAKE256,CKF_SIGN|CKF_VERIFY, 0, 0);
```

### 4.2 Step 2 — Dispatch in sign/verify

`src/lib/SoftHSM_sign.cpp`, in `AsymSignInit()` and `AsymVerifyInit()`, mirror the
existing `CKM_HASH_ML_DSA_*` case blocks substituting:

- `CKM_HASH_SLH_DSA_*` mechanism constants
- `AsymMech::SLHDSA` (or introduce `AsymMech::SLHDSAHash` if needed)
- `SLHDSAParameters` for context extraction

Verify that OpenSSL's `slh-dsa-*` EVP keys accept the `OSSL_PARAM_utf8_string("digest", ...)`
parameter for pre-hash mode (same as ML-DSA `HashID` param pattern).

### 4.3 Step 3 — Tests

Add `CKM_HASH_SLH_DSA_SHA256` to the `SignVerifyTests` battery in `src/lib/test/`.
Mirror the existing `ML_DSA_44_HASH_SHA256` test structure.

---

## 5. OpenSSL 3.6 Algorithm Support Reference

Unchanged from v1. All in-scope algorithms supported natively via EVP_PKEY in OpenSSL 3.3+.

| Algorithm | Parameter sets | EVP_PKEY name pattern |
|---|---|---|
| ML-KEM | 512, 768, 1024 | `"mlkem512"`, `"mlkem768"`, `"mlkem1024"` |
| ML-DSA | 44, 65, 87 | `"ml-dsa-44"`, `"ml-dsa-65"`, `"ml-dsa-87"` |
| SLH-DSA | 12 variants | `"slh-dsa-sha2-128s"` … `"slh-dsa-shake-256f"` |

> **SHAKE pre-hash note:** Verify that OpenSSL 3.6 exposes XOF digest names
> (`"shake128"`, `"shake256"`) for the `OSSL_PARAM` digest parameter before
> implementing `CKM_HASH_SLH_DSA_SHAKE128` / `CKM_HASH_SLH_DSA_SHAKE256`.

---

## 6. Gap–Issue Mapping

| Gap | Title | Issue | Priority |
|---|---|---|---|
| G1 | `CKM_HASH_SLH_DSA*` — 13 pre-hash mechanism variants | #16 | BLOCKER |
| G2 | Streaming message sign/verify (4 stubs) | #17 | HIGH |
| G3 | Message Encrypt/Decrypt API (10 stubs) | #18 | HIGH |
| G4 | `C_VerifySignature*` — pre-bound signature verification (4 stubs) | #19 | MEDIUM |
| G5 | `C_WrapKeyAuthenticated` / `C_UnwrapKeyAuthenticated` | #20 | MEDIUM |
| G6 | `C_LoginUser` / `C_SessionCancel` | #21 | LOW |
