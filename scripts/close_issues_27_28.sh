#!/usr/bin/env bash
# close_issues_27_28.sh
# Closes issues #27 and #28
REPO="pqctoday/softhsmv3"
set -e

echo "Closing issue #28 — Rust Engine: Implement Streaming Sign/Verify (G2)..."
gh issue close 28 --repo "$REPO" --comment \
'Resolved. PKCS#11 v3.0 streaming message sign/verify operations (C_SignMessageBegin, C_SignMessageNext, C_VerifyMessageBegin, C_VerifyMessageNext) were successfully implemented in both C++ and Rust engines in v0.2.0 / v0.3.0. All streaming ACVP tests pass. Closing.'

echo "Closing issue #27 — Rust Engine: Implement proper FIPS-204 pre-hash for ML-DSA and SLH-DSA..."
gh issue close 27 --repo "$REPO" --comment \
'Resolved. HashML-DSA and HashSLH-DSA mechanisms (10 variants each, e.g., CKM_HASH_ML_DSA_SHA256, CKM_HASH_SLH_DSA_SHA512) were completely implemented for both C++ and Rust engines in v0.4.16. All ACVP functional sign/verify bounds pass. Closing.'

echo ""
echo "Remaining open issues:"
gh issue list --repo "$REPO" --state open
