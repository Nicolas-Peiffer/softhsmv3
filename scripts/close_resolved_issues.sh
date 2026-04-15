#!/usr/bin/env bash
# close_resolved_issues.sh
# Closes all resolved / won't-fix tracking issues on pqctoday/softhsmv3 via gh CLI.
# Usage: bash scripts/close_resolved_issues.sh

REPO="pqctoday/softhsmv3"
set -e

echo "Closing issue #29 — Rust Message Encrypt/Decrypt (G3)..."
gh issue close 29 --repo "$REPO" --comment \
'Resolved. C_MessageEncryptInit, C_EncryptMessage, C_EncryptMessageBegin, C_EncryptMessageNext, C_MessageEncryptFinal and full decrypt equivalents were implemented in the Rust engine in v0.2.0 (2026-03-22) and pass all compliance tests. Closing.'

echo "Closing issue #30 — Rust Pre-bound Signature Verify (G4)..."
gh issue close 30 --repo "$REPO" --comment \
'Resolved. C_VerifySignatureInit / C_VerifySignature (one-shot) and C_VerifySignatureUpdate / C_VerifySignatureFinal (multi-part) were implemented in the Rust engine in v0.3.0/v0.4.10. All pass ACVP validation. Closing.'

echo "Closing issue #32 — Recovery and Combined Ops (G8)..."
gh issue close 32 --repo "$REPO" --comment \
'Partially resolved in v0.4.24. C_SignRecoverInit, C_SignRecover, C_VerifyRecoverInit, C_VerifyRecover are now fully implemented for RSA (PKCS and X.509 raw modes). Combined multi-part operations (C_DigestEncryptUpdate, C_DecryptDigestUpdate, C_SignEncryptUpdate, C_DecryptVerifyUpdate) remain stubbed as CKR_FUNCTION_NOT_SUPPORTED — these are optional per spec and have no PQC consumers. Closing.'

echo "Closing issue #33 — Session Validation Flags (G9)..."
gh issue close 33 --repo "$REPO" --comment \
'Resolved. C_GetSessionValidationFlags returns CKR_FUNCTION_NOT_SUPPORTED (PKCS#11 v3.2 §5.6.9 — optional). C_SessionCancel is fully implemented in SoftHSM_sessions.cpp — it resets the active session operation state for the given session handle. All session compliance tests pass. Closing.'

echo "Closing issue #34 — Stateful HBS: HSS/XMSS/XMSS-MT (G10)..."
gh issue close 34 --repo "$REPO" --comment \
'Resolved. Full HSS/LMS (RFC 8554, SP 800-208) implemented in both C++ and Rust engines in v0.4.4. XMSS/XMSS-MT added in v0.4.7. All 20 LMS x 16 LMOTS parameter sets supported including SHAKE-256 variants (v0.4.20). 320/320 NIST ACVP LMS sigVer vectors pass. CKA_HSS_KEYS_REMAINING tracking implemented. Compliance suite passes. Closing.'

echo "Closing issue #36 — RIPEMD160 legacy provider (G-DA-X)..."
gh issue close 36 --repo "$REPO" --comment \
'Resolved in v0.4.24. CKM_RIPEMD160 in C_DigestInit now falls through to default -> CKR_MECHANISM_INVALID instead of referencing the non-existent HashAlgo::RIPEMD160 (OpenSSL legacy provider intentionally disabled in this build). Compliance test passes this check. Closing.'

echo "Closing issue #31 — Async Operations (G7) — won-t-fix..."
gh issue close 31 --repo "$REPO" --comment \
"Won't implement. PKCS#11 v3.2 §3.4 marks async operations as optional when CKF_ASYNC_SESSION is not advertised. C_AsyncComplete, C_AsyncGetID, and C_AsyncJoin return CKR_FUNCTION_NOT_SUPPORTED. No PQC tooling or compliance test requires async sessions. Tracked as G7 in gap analysis. Closing as won't-fix."

echo "Closing issue #35 — Session-State Serialization (G11) — won-t-fix..."
gh issue close 35 --repo "$REPO" --comment \
"Won't implement. C_GetOperationState and C_SetOperationState return CKR_FUNCTION_NOT_SUPPORTED. Snapshotting all in-flight EVP contexts is significant engineering effort with no current consumer. SoftHSM2 v2.7.0 also omits this. Tracked as G11 in gap analysis. Closing as won't-fix."

echo "Closing issue #39 — Secure Memory WASM — won-t-fix..."
gh issue close 39 --repo "$REPO" --comment \
"Won't implement — inherent WASM constraint. WebAssembly linear memory is fully visible to the host JS runtime; no OS-backed secure memory (mlock/mprotect) is available in the WASM sandbox. Documented as accepted risk (CWE-316) in docs/security_audit_04132026.md. Closing as won't-fix by design."

echo ""
echo "Done. Check remaining open issues:"
gh issue list --repo "$REPO" --state open
