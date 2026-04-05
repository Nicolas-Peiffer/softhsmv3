#!/usr/bin/env python3
"""
NIST ACVP LMS sigVer validation — calls hss_validate_signature() directly.

Loads NIST ACVP demo vectors and validates against the hash-sigs C library
without going through PKCS#11 (since C_CreateObject doesn't support HSS key import).

Source: https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/LMS-sigVer-1.0
"""

import json
import ctypes
import os
import sys

# Map ACVP mode names to supported param_set_t values
SUPPORTED_LMS = {
    "LMS_SHA256_M32_H5", "LMS_SHA256_M32_H10", "LMS_SHA256_M32_H15",
    "LMS_SHA256_M32_H20", "LMS_SHA256_M32_H25",
    "LMS_SHA256_M24_H5", "LMS_SHA256_M24_H10", "LMS_SHA256_M24_H15",
    "LMS_SHA256_M24_H20", "LMS_SHA256_M24_H25",
    "LMS_SHAKE_M32_H5", "LMS_SHAKE_M32_H10", "LMS_SHAKE_M32_H15",
    "LMS_SHAKE_M32_H20", "LMS_SHAKE_M32_H25",
    "LMS_SHAKE_M24_H5", "LMS_SHAKE_M24_H10", "LMS_SHAKE_M24_H15",
    "LMS_SHAKE_M24_H20", "LMS_SHAKE_M24_H25",
}

SUPPORTED_LMOTS = {
    "LMOTS_SHA256_N32_W1", "LMOTS_SHA256_N32_W2", "LMOTS_SHA256_N32_W4",
    "LMOTS_SHA256_N32_W8",
    "LMOTS_SHA256_N24_W1", "LMOTS_SHA256_N24_W2", "LMOTS_SHA256_N24_W4",
    "LMOTS_SHA256_N24_W8",
    "LMOTS_SHAKE_N32_W1", "LMOTS_SHAKE_N32_W2", "LMOTS_SHAKE_N32_W4",
    "LMOTS_SHAKE_N32_W8",
    "LMOTS_SHAKE_N24_W1", "LMOTS_SHAKE_N24_W2", "LMOTS_SHAKE_N24_W4",
    "LMOTS_SHAKE_N24_W8",
}

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_dir = os.path.dirname(script_dir)
    lib_path = os.path.join(repo_dir, "build", "src", "lib", "libsofthsmv3.dylib")

    # Load test vectors
    with open(os.path.join(script_dir, "acvp", "lms_sigver_test.json")) as f:
        prompt = json.load(f)
    with open(os.path.join(script_dir, "acvp", "lms_sigver_expected.json")) as f:
        expected = json.load(f)

    # Build expected results lookup
    exp_lookup = {}
    for g in expected["testGroups"]:
        for t in g["tests"]:
            exp_lookup[(g["tgId"], t["tcId"])] = t["testPassed"]

    # Load library and get lm_validate_signature (single-level LMS verify)
    lib = ctypes.cdll.LoadLibrary(lib_path)

    # bool lm_validate_signature(
    #     const unsigned char *public_key,
    #     const void *message, size_t message_len, bool prehashed,
    #     const unsigned char *signature, size_t signature_len);
    lm_validate = lib.lm_validate_signature
    lm_validate.restype = ctypes.c_bool
    lm_validate.argtypes = [
        ctypes.c_char_p,        # public_key
        ctypes.c_char_p,        # message
        ctypes.c_size_t,        # message_len
        ctypes.c_bool,          # prehashed
        ctypes.c_char_p,        # signature
        ctypes.c_size_t,        # signature_len
    ]

    total = 0
    match = 0
    mismatch = 0
    skip = 0

    for group in prompt["testGroups"]:
        tg_id = group["tgId"]
        lms_mode = group["lmsMode"]
        lmots_mode = group["lmOtsMode"]

        if lms_mode not in SUPPORTED_LMS or lmots_mode not in SUPPORTED_LMOTS:
            skip += len(group["tests"])
            continue

        pk_bytes = bytes.fromhex(group["publicKey"])

        for test in group["tests"]:
            tc_id = test["tcId"]
            msg_bytes = bytes.fromhex(test["message"])
            sig_bytes = bytes.fromhex(test["signature"])
            expected_pass = exp_lookup.get((tg_id, tc_id))

            if expected_pass is None:
                skip += 1
                continue

            total += 1

            result = lm_validate(pk_bytes, msg_bytes, len(msg_bytes),
                                False, sig_bytes, len(sig_bytes))

            if result == expected_pass:
                match += 1
            else:
                mismatch += 1
                print(f"[MISMATCH] tgId={tg_id} tcId={tc_id} {lms_mode}/{lmots_mode} "
                      f"expected={'PASS' if expected_pass else 'FAIL'} "
                      f"got={'PASS' if result else 'FAIL'}")

    print(f"\n{'='*60}")
    print(f"NIST ACVP LMS sigVer — lm_validate_signature() direct call")
    print(f"  Total:    {total}")
    print(f"  Match:    {match}")
    print(f"  Mismatch: {mismatch}")
    print(f"  Skip:     {skip}")
    print(f"{'='*60}")

    return 0 if mismatch == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
