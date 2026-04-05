/*
 * test_stateful_verify.cpp — Validates C_VerifyInit/C_Verify for HSS and XMSS
 *
 * Tests the StatefulVerifyInit/StatefulVerify dispatch added to fix GAP-1.
 * Also validates the PKCS#11 v3.2 compliant XMSS sign output (sig-only, no msg).
 *
 * Usage: g++ -o test_stateful_verify test_stateful_verify.cpp -ldl -I src/lib/pkcs11 -std=c++17
 *        SOFTHSM2_CONF=/path/to/softhsm2.conf ./test_stateful_verify
 */

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "src/lib/pkcs11/pkcs11.h"

static int failures = 0;
static int passes = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("[FAIL] %s\n", msg); failures++; return; } \
    else { printf("[PASS] %s\n", msg); passes++; } \
} while(0)

#define CHECK_RV(rv, expected, msg) do { \
    if ((rv) != (expected)) { printf("[FAIL] %s: got 0x%08lX, expected 0x%08lX\n", msg, (unsigned long)(rv), (unsigned long)(expected)); failures++; return; } \
    else { printf("[PASS] %s\n", msg); passes++; } \
} while(0)

static CK_FUNCTION_LIST_PTR fl;
static CK_SESSION_HANDLE hSess;

void test_hss_sign_verify()
{
    printf("\n── HSS Sign + Verify ──────────────────────────────\n");

    CK_MECHANISM mech = { 0x00004032, NULL_PTR, 0 }; // CKM_HSS_KEY_PAIR_GEN
    CK_BBOOL bTrue = CK_TRUE;
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE hssKT = 0x00000046UL; // CKK_HSS
    CK_UTF8CHAR label[] = "HSS-Verify-Test";

    CK_ATTRIBUTE pubT[] = {
        { CKA_CLASS, &pubClass, sizeof(pubClass) },
        { CKA_KEY_TYPE, &hssKT, sizeof(hssKT) },
        { CKA_TOKEN, &bTrue, sizeof(bTrue) },
        { CKA_VERIFY, &bTrue, sizeof(bTrue) },
        { CKA_LABEL, label, sizeof(label)-1 }
    };
    CK_ATTRIBUTE privT[] = {
        { CKA_CLASS, &privClass, sizeof(privClass) },
        { CKA_KEY_TYPE, &hssKT, sizeof(hssKT) },
        { CKA_TOKEN, &bTrue, sizeof(bTrue) },
        { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
        { CKA_SIGN, &bTrue, sizeof(bTrue) },
        { CKA_LABEL, label, sizeof(label)-1 }
    };

    CK_OBJECT_HANDLE hPub, hPriv;
    CK_RV rv = fl->C_GenerateKeyPair(hSess, &mech, pubT, 5, privT, 6, &hPub, &hPriv);
    CHECK_RV(rv, CKR_OK, "HSS C_GenerateKeyPair");

    // Sign
    CK_BYTE msg[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04 };
    CK_MECHANISM signMech = { 0x00004033, NULL_PTR, 0 }; // CKM_HSS
    rv = fl->C_SignInit(hSess, &signMech, hPriv);
    CHECK_RV(rv, CKR_OK, "HSS C_SignInit");

    CK_BYTE sig[8192];
    CK_ULONG sigLen = sizeof(sig);
    rv = fl->C_Sign(hSess, msg, sizeof(msg), sig, &sigLen);
    CHECK_RV(rv, CKR_OK, "HSS C_Sign");
    printf("       HSS signature: %lu bytes\n", sigLen);

    // Verify (this is the new StatefulVerify path)
    rv = fl->C_VerifyInit(hSess, &signMech, hPub);
    CHECK_RV(rv, CKR_OK, "HSS C_VerifyInit");

    rv = fl->C_Verify(hSess, msg, sizeof(msg), sig, sigLen);
    CHECK_RV(rv, CKR_OK, "HSS C_Verify (valid signature)");

    // Tamper detection: flip a byte in signature
    rv = fl->C_VerifyInit(hSess, &signMech, hPub);
    CHECK_RV(rv, CKR_OK, "HSS C_VerifyInit (tamper test)");

    sig[10] ^= 0xFF;
    rv = fl->C_Verify(hSess, msg, sizeof(msg), sig, sigLen);
    CHECK_RV(rv, CKR_SIGNATURE_INVALID, "HSS C_Verify (tampered → CKR_SIGNATURE_INVALID)");
}

void test_xmss_sign_verify()
{
    printf("\n── XMSS Sign + Verify ─────────────────────────────\n");

    CK_ULONG paramSet = 0x00000001UL; // XMSS_SHA2_10_256
    CK_MECHANISM mech = { 0x00004034, &paramSet, sizeof(paramSet) }; // CKM_XMSS_KEY_PAIR_GEN
    CK_BBOOL bTrue = CK_TRUE;
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE xmssKT = 0x00000047UL; // CKK_XMSS
    CK_UTF8CHAR label[] = "XMSS-Verify-Test";

    CK_ATTRIBUTE pubT[] = {
        { CKA_CLASS, &pubClass, sizeof(pubClass) },
        { CKA_KEY_TYPE, &xmssKT, sizeof(xmssKT) },
        { CKA_TOKEN, &bTrue, sizeof(bTrue) },
        { CKA_VERIFY, &bTrue, sizeof(bTrue) },
        { CKA_LABEL, label, sizeof(label)-1 }
    };
    CK_ATTRIBUTE privT[] = {
        { CKA_CLASS, &privClass, sizeof(privClass) },
        { CKA_KEY_TYPE, &xmssKT, sizeof(xmssKT) },
        { CKA_TOKEN, &bTrue, sizeof(bTrue) },
        { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
        { CKA_SIGN, &bTrue, sizeof(bTrue) },
        { CKA_LABEL, label, sizeof(label)-1 }
    };

    CK_OBJECT_HANDLE hPub, hPriv;
    CK_RV rv = fl->C_GenerateKeyPair(hSess, &mech, pubT, 5, privT, 6, &hPub, &hPriv);
    CHECK_RV(rv, CKR_OK, "XMSS C_GenerateKeyPair (SHA2_10_256)");

    // Sign
    CK_BYTE msg[] = { 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x11, 0x22, 0x33 };
    CK_MECHANISM signMech = { 0x00004036, NULL_PTR, 0 }; // CKM_XMSS
    rv = fl->C_SignInit(hSess, &signMech, hPriv);
    CHECK_RV(rv, CKR_OK, "XMSS C_SignInit");

    CK_BYTE sig[8192];
    CK_ULONG sigLen = sizeof(sig);
    rv = fl->C_Sign(hSess, msg, sizeof(msg), sig, &sigLen);
    CHECK_RV(rv, CKR_OK, "XMSS C_Sign");
    printf("       XMSS signature: %lu bytes (should be sig-only, no msg appended)\n", sigLen);

    // Verify
    rv = fl->C_VerifyInit(hSess, &signMech, hPub);
    CHECK_RV(rv, CKR_OK, "XMSS C_VerifyInit");

    rv = fl->C_Verify(hSess, msg, sizeof(msg), sig, sigLen);
    CHECK_RV(rv, CKR_OK, "XMSS C_Verify (valid signature)");

    // Tamper detection
    rv = fl->C_VerifyInit(hSess, &signMech, hPub);
    CHECK_RV(rv, CKR_OK, "XMSS C_VerifyInit (tamper test)");

    sig[20] ^= 0xFF;
    rv = fl->C_Verify(hSess, msg, sizeof(msg), sig, sigLen);
    CHECK_RV(rv, CKR_SIGNATURE_INVALID, "XMSS C_Verify (tampered → CKR_SIGNATURE_INVALID)");
}

void test_mechanism_info()
{
    printf("\n── C_GetMechanismInfo ──────────────────────────────\n");

    CK_SLOT_ID slots[10];
    CK_ULONG ulCount = 10;
    fl->C_GetSlotList(CK_TRUE, slots, &ulCount);

    CK_MECHANISM_INFO info;
    CK_RV rv;

    rv = fl->C_GetMechanismInfo(slots[0], 0x00004032, &info); // CKM_HSS_KEY_PAIR_GEN
    CHECK_RV(rv, CKR_OK, "C_GetMechanismInfo(CKM_HSS_KEY_PAIR_GEN)");
    CHECK(info.flags & CKF_GENERATE_KEY_PAIR, "  CKF_GENERATE_KEY_PAIR set");

    rv = fl->C_GetMechanismInfo(slots[0], 0x00004033, &info); // CKM_HSS
    CHECK_RV(rv, CKR_OK, "C_GetMechanismInfo(CKM_HSS)");
    CHECK((info.flags & CKF_SIGN) && (info.flags & CKF_VERIFY), "  CKF_SIGN | CKF_VERIFY set");

    rv = fl->C_GetMechanismInfo(slots[0], 0x00004034, &info); // CKM_XMSS_KEY_PAIR_GEN
    CHECK_RV(rv, CKR_OK, "C_GetMechanismInfo(CKM_XMSS_KEY_PAIR_GEN)");
    CHECK(info.flags & CKF_GENERATE_KEY_PAIR, "  CKF_GENERATE_KEY_PAIR set");

    rv = fl->C_GetMechanismInfo(slots[0], 0x00004036, &info); // CKM_XMSS
    CHECK_RV(rv, CKR_OK, "C_GetMechanismInfo(CKM_XMSS)");
    CHECK((info.flags & CKF_SIGN) && (info.flags & CKF_VERIFY), "  CKF_SIGN | CKF_VERIFY set");

    rv = fl->C_GetMechanismInfo(slots[0], 0x00004035, &info); // CKM_XMSSMT_KEY_PAIR_GEN
    CHECK_RV(rv, CKR_OK, "C_GetMechanismInfo(CKM_XMSSMT_KEY_PAIR_GEN)");
    CHECK(info.flags & CKF_GENERATE_KEY_PAIR, "  CKF_GENERATE_KEY_PAIR set");

    rv = fl->C_GetMechanismInfo(slots[0], 0x00004037, &info); // CKM_XMSSMT
    CHECK_RV(rv, CKR_OK, "C_GetMechanismInfo(CKM_XMSSMT)");
    CHECK((info.flags & CKF_SIGN) && (info.flags & CKF_VERIFY), "  CKF_SIGN | CKF_VERIFY set");
}

int main()
{
    // Set up a fresh token directory
    system("rm -rf /tmp/softhsm-verify-test && mkdir -p /tmp/softhsm-verify-test/tokens");

    FILE* f = fopen("/tmp/softhsm-verify-test/softhsm2.conf", "w");
    fprintf(f, "directories.tokendir = /tmp/softhsm-verify-test/tokens/\n"
               "objectstore.backend = file\n"
               "log.level = ERROR\n"
               "slots.removable = false\n");
    fclose(f);
    setenv("SOFTHSM2_CONF", "/tmp/softhsm-verify-test/softhsm2.conf", 1);

    void* handle = dlopen("./build/src/lib/libsofthsmv3.dylib", RTLD_NOW);
    if (!handle) {
        printf("[FAIL] Cannot load libsofthsmv3.dylib: %s\n", dlerror());
        return 1;
    }

    CK_C_GetFunctionList C_GetFunctionList = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
    C_GetFunctionList(&fl);

    CK_RV rv = fl->C_Initialize(NULL_PTR);
    if (rv != CKR_OK) { printf("[FAIL] C_Initialize: 0x%08lX\n", rv); return 1; }

    // Initialize token
    CK_SLOT_ID slots[10];
    CK_ULONG ulCount = 10;
    fl->C_GetSlotList(CK_FALSE, NULL, &ulCount);
    ulCount = 10;
    fl->C_GetSlotList(CK_FALSE, slots, &ulCount);

    CK_UTF8CHAR label[32];
    memset(label, ' ', 32);
    memcpy(label, "test", 4);
    rv = fl->C_InitToken(slots[0], (CK_UTF8CHAR_PTR)"5678", 4, label);
    if (rv != CKR_OK) { printf("[FAIL] C_InitToken: 0x%08lX\n", rv); return 1; }

    rv = fl->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSess);
    if (rv != CKR_OK) { printf("[FAIL] C_OpenSession: 0x%08lX\n", rv); return 1; }

    rv = fl->C_Login(hSess, CKU_SO, (CK_UTF8CHAR_PTR)"5678", 4);
    if (rv != CKR_OK) { printf("[FAIL] C_Login SO: 0x%08lX\n", rv); return 1; }
    rv = fl->C_InitPIN(hSess, (CK_UTF8CHAR_PTR)"1234", 4);
    if (rv != CKR_OK) { printf("[FAIL] C_InitPIN: 0x%08lX\n", rv); return 1; }
    fl->C_Logout(hSess);

    rv = fl->C_Login(hSess, CKU_USER, (CK_UTF8CHAR_PTR)"1234", 4);
    if (rv != CKR_OK) { printf("[FAIL] C_Login USER: 0x%08lX\n", rv); return 1; }

    // Run tests
    test_mechanism_info();
    test_hss_sign_verify();
    test_xmss_sign_verify();

    printf("\n══════════════════════════════════════════════════\n");
    printf("Results: %d PASS, %d FAIL\n", passes, failures);

    fl->C_Finalize(NULL);
    return failures > 0 ? 1 : 0;
}
