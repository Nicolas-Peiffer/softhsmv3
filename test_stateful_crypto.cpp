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

// Constants
#define CKM_HSS_KEY_PAIR_GEN   0x00004032UL
#define CKM_HSS                0x00004033UL
#define CKK_HSS                0x00000046UL

typedef struct CK_HSS_KEY_PAIR_GEN_PARAMS {
    CK_ULONG ulLevels;
    CK_ULONG ulLmsParamSet[8];
    CK_ULONG ulLmotsParamSet[8];
} CK_HSS_KEY_PAIR_GEN_PARAMS;

int main() {
    void *handle = dlopen("./build/src/lib/libsofthsmv3.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        printf("Failed to load libsofthsmv3.dylib: %s\n", dlerror());
        return 1;
    }

    CK_C_GetFunctionList getFunctionList;
    *(void **)(&getFunctionList) = dlsym(handle, "C_GetFunctionList");
    if (!getFunctionList) {
        printf("Could not find C_GetFunctionList\n");
        return 1;
    }

    CK_FUNCTION_LIST_PTR pFunctionList;
    getFunctionList(&pFunctionList);

    CK_RV rv = pFunctionList->C_Initialize(NULL);
    if (rv != CKR_OK) {
        printf("C_Initialize failed: 0x%08lX\n", rv);
        return 1;
    }

    CK_ULONG ulCount = 0;
    rv = pFunctionList->C_GetSlotList(CK_TRUE, NULL, &ulCount);
    if (rv != CKR_OK || ulCount == 0) {
        printf("C_GetSlotList failed or no slots\n");
        return 1;
    }
    
    CK_SLOT_ID slots[10];
    ulCount = 10;
    rv = pFunctionList->C_GetSlotList(CK_TRUE, slots, &ulCount);
    CK_SLOT_ID slotID = slots[0];

    CK_SESSION_HANDLE hSession;
    rv = pFunctionList->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSession);
    if (rv != CKR_OK) {
        printf("C_OpenSession failed: 0x%08lX\n", rv);
        return 1;
    }

    rv = pFunctionList->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)"1234", 4);
    if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
        printf("C_Login failed: 0x%08lX\n", rv);
        return 1;
    }

    CK_HSS_KEY_PAIR_GEN_PARAMS params;
    params.ulLevels = 1;
    params.ulLmsParamSet[0] = 5; // LMS_SHA256_M32_H10
    params.ulLmotsParamSet[0] = 4; // LMOTS_SHA256_N32_W8

    CK_MECHANISM mechanism = { CKM_HSS_KEY_PAIR_GEN, &params, sizeof(params) };

    CK_BBOOL bTrue = CK_TRUE;
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_UTF8CHAR label[] = "HSS Test Key";

    CK_ATTRIBUTE pubTemplate[] = {
        { CKA_CLASS, &pubClass, sizeof(pubClass) },
        { CKA_TOKEN, &bTrue, sizeof(bTrue) },
        { CKA_VERIFY, &bTrue, sizeof(bTrue) },
        { CKA_LABEL, label, sizeof(label)-1 }
    };
    CK_ATTRIBUTE privTemplate[] = {
        { CKA_CLASS, &privClass, sizeof(privClass) },
        { CKA_TOKEN, &bTrue, sizeof(bTrue) },
        { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
        { CKA_SIGN, &bTrue, sizeof(bTrue) },
        { CKA_LABEL, label, sizeof(label)-1 }
    };

    CK_OBJECT_HANDLE hPublicKey = CK_INVALID_HANDLE, hPrivateKey = CK_INVALID_HANDLE;
    printf("Generating HSS KeyPair...\n");
    rv = pFunctionList->C_GenerateKeyPair(hSession, &mechanism,
                                          pubTemplate, 4,
                                          privTemplate, 5,
                                          &hPublicKey, &hPrivateKey);

    if (rv != CKR_OK) {
        printf("C_GenerateKeyPair failed: 0x%08lX\n", rv);
        return 1;
    }
    printf("HSS KeyPair Generated. Pub: %lu, Priv: %lu\n", hPublicKey, hPrivateKey);

    // Get number of signatures remaining
    CK_ULONG keysRemaining = 0;
    CK_ATTRIBUTE remainingAttr = { 0x0000061cUL, &keysRemaining, sizeof(keysRemaining) };
    pFunctionList->C_GetAttributeValue(hSession, hPublicKey, &remainingAttr, 1);
    printf("Initial Keys Remaining: %lu\n", keysRemaining);

    // Sign message
    printf("Signing message...\n");
    CK_MECHANISM signMech = { CKM_HSS, NULL, 0 };
    rv = pFunctionList->C_SignInit(hSession, &signMech, hPrivateKey);
    if (rv != CKR_OK) {
        printf("C_SignInit failed: 0x%08lX\n", rv);
        return 1;
    }

    CK_BYTE data[] = "Hello Stateful World!";
    CK_ULONG dataLen = sizeof(data) - 1;
    CK_BYTE signature[4000];
    CK_ULONG signatureLen = sizeof(signature);

    rv = pFunctionList->C_Sign(hSession, data, dataLen, signature, &signatureLen);
    if (rv != CKR_OK) {
        printf("C_Sign failed: 0x%08lX\n", rv);
        return 1;
    }
    printf("Successfully signed message! Signature length: %lu\n", signatureLen);

    // Get number of signatures remaining
    pFunctionList->C_GetAttributeValue(hSession, hPublicKey, &remainingAttr, 1);
    printf("Final Keys Remaining (should be 1 less): %lu\n", keysRemaining); // Actually we didn't hook exactly the decrement logically in attribute reading but let's check!

    pFunctionList->C_CloseSession(hSession);
    pFunctionList->C_Finalize(NULL);
    printf("Done.\n");
    return 0;
}
