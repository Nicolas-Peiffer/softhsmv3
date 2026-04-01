# Utimaco HSM Simulator vs softhsmv3 — Feature Gap Analysis

## Context

Comparing the **Utimaco Quantum Protect HSM Simulator** (free, proprietary, native desktop) against **softhsmv3** (open-source, PKCS#11 v3.2, dual WASM) to identify feature gaps where softhsmv3 falls short, and areas where softhsmv3 leads.

---

## 1. PQC Algorithm Coverage

| Algorithm | Utimaco QP Sim | softhsmv3 | Gap |
|-----------|---------------|-----------|-----|
| **ML-KEM** (FIPS 203) | 512/768/1024 | 512/768/1024 | **Parity** |
| **ML-DSA** (FIPS 204) | 44/65/87 | 44/65/87 + 10 pre-hash variants | **softhsmv3 leads** (pre-hash) |
| **SLH-DSA** (FIPS 205) | Not yet (roadmap) | All 12 param sets + 10 pre-hash | **softhsmv3 leads** |
| **LMS** (SP 800-208) | Yes | No | **GAP: softhsmv3 missing** |
| **HSS** (hierarchical LMS) | Yes | No | **GAP: softhsmv3 missing** |
| **XMSS** | Yes | No | **GAP: softhsmv3 missing** |
| **XMSS-MT** | Yes | No | **GAP: softhsmv3 missing** |
| **HQC** | Roadmap | No | Neither has it |
| **FrodoKEM** | Roadmap | No | Neither has it |
| **Classic McEliece** | Roadmap | No | Neither has it |

### Summary
- **Utimaco advantage**: Stateful hash-based signatures (LMS/HSS/XMSS/XMSS-MT) — these are NIST-standardized (SP 800-208) and critical for firmware signing, code signing, and long-lived key scenarios
- **softhsmv3 advantage**: SLH-DSA (Utimaco doesn't have it yet), plus pre-hash variants for ML-DSA/SLH-DSA (PKCS#11 v3.2 compliance)

---

## 2. PKCS#11 Version & Compliance

| Feature | Utimaco QP Sim | softhsmv3 | Gap |
|---------|---------------|-----------|-----|
| PKCS#11 version | v2/v3 (not v3.2) | **v3.2** | softhsmv3 leads |
| `C_EncapsulateKey` / `C_DecapsulateKey` | Unknown (likely proprietary API) | Yes (v3.2 standard) | softhsmv3 likely leads |
| Pre-hash sign mechanisms (`CKM_HASH_ML_DSA_*`) | Unknown | 22 variants (11 ML-DSA + 11 SLH-DSA) | softhsmv3 leads |
| `C_SignMessageBegin/Next` (streaming) | Unknown | Yes (C++ engine) | softhsmv3 leads |
| `C_VerifySignatureInit` (pre-bound) | Unknown | Yes (C++ engine) | softhsmv3 leads |
| `C_WrapKeyAuthenticated` (AAD) | Unknown | Yes (C++ engine) | softhsmv3 leads |
| ECDSA-SHA3 variants | Unknown | Yes (4 variants) | softhsmv3 likely leads |

---

## 3. Enterprise / HSM Management Features

| Feature | Utimaco QP Sim | softhsmv3 | Gap |
|---------|---------------|-----------|-----|
| **Multi-token / partitions** | Up to 31 containers | Single slot | **GAP: softhsmv3 missing** |
| **RBAC** (role-based access) | Full RBAC with custom roles | SO + User only | **GAP: softhsmv3 limited** |
| **MFA** | Supported | No | **GAP: softhsmv3 missing** |
| **Segregation of Duty** | Enforced | No | **GAP: softhsmv3 missing** |
| **Audit logging** | Full audit trail | No audit trail | **GAP: softhsmv3 missing** |
| **Remote monitoring** | u.trust 360 integration | No | **GAP: softhsmv3 missing** |
| **Firmware simulation** | Full firmware emulation | No (software-only) | **GAP: softhsmv3 missing** |
| **Key backup/restore** | Wrapped export via KEK | Manual via CKA_VALUE | **GAP: softhsmv3 limited** |
| **Session timeout** | Configurable (30min–2 days) | No timeout | **GAP: softhsmv3 missing** |
| **Multi-tenant isolation** | Per-partition isolation | Single tenant | **GAP: softhsmv3 missing** |
| **Cluster/failover** | Multi-instance support | Single instance | **GAP: softhsmv3 missing** |

---

## 4. Classical Crypto Coverage

| Feature | Utimaco QP Sim | softhsmv3 | Gap |
|---------|---------------|-----------|-----|
| RSA | Full | Full | Parity |
| ECDSA (NIST curves) | P-256/384/521 + Brainpool | P-256/384/521 + secp256k1 | Different curve sets |
| EdDSA | Ed25519, Ed448 | Ed25519 only | **GAP: Ed448 missing** |
| ECDH | Yes | Yes | Parity |
| AES modes | CBC/ECB/CTR/OFB/CFB | CBC/ECB/CTR/GCM + wrap | Different mode sets |
| DES/3DES | Yes (legacy) | Removed (by design) | N/A (intentional) |
| Brainpool curves | Yes | No | **GAP: softhsmv3 missing** |

---

## 5. Key Derivation & KDF

| KDF | Utimaco QP Sim | softhsmv3 | Gap |
|-----|---------------|-----------|-----|
| PBKDF2 | Unknown | Yes | softhsmv3 likely leads |
| HKDF | Unknown | Yes (full 3-mode) | softhsmv3 likely leads |
| SP 800-108 Counter | Yes (KBKDF with KAT) | Yes | Parity |
| SP 800-108 Feedback | Unknown | Yes | softhsmv3 likely leads |
| SP 800-56Cr1 One-Step | Yes | No | **GAP: softhsmv3 missing** |
| X9.63 KDF | Unknown | Yes (via ECDH derive) | softhsmv3 likely leads |

---

## 6. Platform & Deployment

| Feature | Utimaco QP Sim | softhsmv3 | Gap |
|---------|---------------|-----------|-----|
| **Browser/WASM** | No | **Yes** (dual C++/Rust) | **softhsmv3 leads** |
| Windows/Linux | Yes | No native binary | Utimaco leads |
| macOS | Limited | WASM only | - |
| API languages | C/C++, Java, .NET, Python, Rust | TypeScript/JavaScript (WASM) | Different targets |
| No-install usage | Requires download + approval | Runs in any browser | **softhsmv3 leads** |
| Licensing | Free but closed-source | Open-source (Apache 2.0) | **softhsmv3 leads** |
| Export compliance | 48-hour approval required | No restrictions | **softhsmv3 leads** |

---

## 7. Certification & Compliance

| Feature | Utimaco QP Sim | softhsmv3 | Gap |
|---------|---------------|-----------|-----|
| FIPS 140-2 Level 3 | Yes (hardware HSM) | No (simulator) | N/A (both are simulators) |
| FIPS 140-3 | In progress | No | N/A |
| NIST CAVP validation | ML-KEM, ML-DSA, LMS | No (educational) | **GAP: softhsmv3 not validated** |
| ACVP test vectors | Unknown | Yes (deterministic RNG) | softhsmv3 has testing infra |

---

## 8. Critical Gaps for softhsmv3 (Priority Order)

### HIGH — Missing from softhsmv3 that Utimaco has

1. **LMS/HSS stateful hash-based signatures** (SP 800-208)
   - Used for firmware signing, code signing, long-lived credentials
   - NIST-standardized, required by NSA CNSA 2.0 suite
   - OpenSSL 3.x has no native support — would need liboqs or custom implementation
   - Relevant PKCS#11 v3.2 types: `CKK_HSS`, `CKM_HSS`, `CKM_HSS_KEY_PAIR_GEN`

2. **XMSS/XMSS-MT stateful hash-based signatures** (RFC 8391)
   - Similar use case to LMS; preferred by some European standards bodies
   - OpenSSL 3.x has no native support
   - Relevant PKCS#11 v3.2 types: `CKK_XMSS`, `CKK_XMSSMT`, `CKM_XMSS_KEY_PAIR_GEN`

3. **Ed448 curve support** (EdDSA)
   - Commonly supported alongside Ed25519
   - OpenSSL 3.x supports it — straightforward addition

### MEDIUM — Enterprise features softhsmv3 could add for educational value

4. **Multi-slot/partition support**
   - Currently single slot — could add configurable slot count
   - Would enable teaching partition isolation, multi-tenant HSM

5. **Audit logging**
   - Log all PKCS#11 operations with timestamps
   - Valuable for teaching HSM compliance workflows

6. **Session timeout**
   - Add configurable session timeout to demonstrate real HSM behavior

### LOW — Nice-to-have but not critical

7. **Brainpool curves** (used primarily in German/European standards)
8. **AES OFB/CFB modes** (rarely used in modern applications)
9. **SP 800-56Cr1 One-Step KDF** (limited use in PKCS#11 context)
10. **RBAC / MFA simulation** (complex, limited educational value in browser)

---

## 9. softhsmv3 Advantages Over Utimaco

| Advantage | Detail |
|-----------|--------|
| **SLH-DSA support** | Full 12-parameter-set support; Utimaco has none yet |
| **PKCS#11 v3.2** | Latest standard; Utimaco is v3 (not v3.2) |
| **Pre-hash signing** | 22 pre-hash variants for ML-DSA/SLH-DSA |
| **Browser/WASM** | Zero-install, runs anywhere; Utimaco is desktop-only |
| **Open source** | Fully inspectable; Utimaco is proprietary |
| **No export restrictions** | Immediate access; Utimaco requires 48-hour approval |
| **Dual WASM engines** | C++ + Rust cross-check for verification |
| **ACVP test infrastructure** | Deterministic RNG for Known Answer Tests |
| **Comprehensive KDF support** | PBKDF2, HKDF, SP 800-108 (counter + feedback) |
| **Educational UI** | Interactive playground with step-by-step operations |

---

## 10. Recommendation

**Focus areas for closing gaps (if desired):**

1. **LMS/HSS** — Highest-value gap. Required by CNSA 2.0. Would need liboqs integration or a standalone WASM implementation (conflicts with OpenSSL-only design philosophy). Consider as a Phase 7+ feature.

2. **XMSS** — Same category as LMS. Consider bundling with LMS work.

3. **Ed448** — Low-hanging fruit. OpenSSL supports it. Quick win.

4. **Multi-slot** — Moderate effort. Would enhance the educational HSM simulation significantly.

5. **Audit log** — Simple feature. Log PKCS#11 calls to a buffer. Display in UI.

**Do NOT pursue:** RBAC/MFA, firmware simulation, multi-tenant isolation, cluster support — these are enterprise features that add complexity without educational value in a browser HSM simulator.
