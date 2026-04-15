#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include "src/lib/pkcs11/cryptoki.h"

// Macro helper for returning error info
#define TEST_ASSERT(cond, msg) \
    if (!(cond)) { \
        fprintf(stderr, "[FAIL] %s\n", msg); \
        return 1; \
    }

int main() {
    printf("[*] Starting Asynchronous Mode Validation Test...\n");

    // Load SoftHSMv3 module
    void *module = dlopen("./build/src/lib/libsofthsmv3.dylib", RTLD_NOW);
    TEST_ASSERT(module != NULL, "Failed to load libsofthsmv3.dylib");

    CK_C_GetFunctionList getFunctionList = (CK_C_GetFunctionList)dlsym(module, "C_GetFunctionList");
    TEST_ASSERT(getFunctionList != NULL, "C_GetFunctionList not found");

    CK_FUNCTION_LIST_PTR pFunctionList = NULL;
    CK_RV rv = getFunctionList(&pFunctionList);
    TEST_ASSERT(rv == CKR_OK, "C_GetFunctionList failed");

    printf("[*] Initializing PKCS#11...\n");
    rv = pFunctionList->C_Initialize(NULL);
    TEST_ASSERT(rv == CKR_OK, "C_Initialize failed");

    // Get a slot
    CK_ULONG slotCount = 0;
    rv = pFunctionList->C_GetSlotList(CK_TRUE, NULL, &slotCount);
    TEST_ASSERT(rv == CKR_OK && slotCount > 0, "C_GetSlotList failed or no slots available. Ensure token is initialized.");

    CK_SLOT_ID slotList[10];
    rv = pFunctionList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    TEST_ASSERT(rv == CKR_OK, "C_GetSlotList data failed");

    CK_SLOT_ID slot = slotList[0];
    printf("[*] Using Slot ID: %lu\n", slot);

    // Test 1: Open an Asynchronous Session
    printf("[*] Test 1: Opening Session with CKF_ASYNC_SESSION...\n");
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    
    // PKCS#11 CKF_ASYNC_SESSION = 0x00000008, CKF_SERIAL_SESSION = 0x00000004
    CK_FLAGS sessionFlags = CKF_SERIAL_SESSION | CKF_ASYNC_SESSION; 
    
    rv = pFunctionList->C_OpenSession(slot, sessionFlags, NULL, NULL, &hSession);
    TEST_ASSERT(rv == CKR_OK, "C_OpenSession with CKF_ASYNC_SESSION failed. Did SoftHSM reject it?");
    printf("    [PASS] Session successfully opened (Handle: %lu).\n", hSession);

    // Test 2: Verify Info returns CKF_ASYNC_SESSION
    printf("[*] Test 2: Verifying Session Info reflects Asynchronous State...\n");
    CK_SESSION_INFO sessionInfo;
    rv = pFunctionList->C_GetSessionInfo(hSession, &sessionInfo);
    TEST_ASSERT(rv == CKR_OK, "C_GetSessionInfo failed");

    if ((sessionInfo.flags & CKF_ASYNC_SESSION) == CKF_ASYNC_SESSION) {
        printf("    [PASS] C_GetSessionInfo explicitly confirmed CKF_ASYNC_SESSION (%lu).\n", sessionInfo.flags);
    } else {
        printf("    [FAIL] C_GetSessionInfo did NOT contain CKF_ASYNC_SESSION.\n");
        return 1;
    }

    // Test 3: Test C_AsyncComplete Stub Return
    // If the token natively processes everything synchronously, calling C_AsyncComplete should 
    // now yield CKR_OPERATION_NOT_INITIALIZED (0x91) instead of CKR_FUNCTION_NOT_SUPPORTED (0x54).
    printf("[*] Test 3: Verifying C_AsyncComplete gracefully replies with no jobs...\n");
    /* C_AsyncComplete is a PKCS#11 v3.x addition, so we query it via C_GetInterfaceList.
       Alternatively, since it operates at ABI layer, we can load C_AsyncComplete if we grab Interface 3.2. */
       
    // Grab C_AsyncComplete using raw dlsym to bypass header version bounds mapping
    CK_RV (*C_AsyncComplete)(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ASYNC_DATA_PTR) = 
        (CK_RV (*)(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ASYNC_DATA_PTR)) dlsym(module, "C_AsyncComplete");
    
    if (C_AsyncComplete == NULL) {
        printf("    [FAIL] Could not map C_AsyncComplete symbol out of library.\n");
        return 1;
    }

    CK_UTF8CHAR_PTR dummyFunc = (CK_UTF8CHAR_PTR)"C_Sign";
    CK_ASYNC_DATA dummyData;
    rv = C_AsyncComplete(hSession, dummyFunc, &dummyData);
    
    // CKR_OPERATION_NOT_INITIALIZED == 0x00000091
    if (rv == CKR_OPERATION_NOT_INITIALIZED) {
        printf("    [PASS] C_AsyncComplete successfully returned CKR_OPERATION_NOT_INITIALIZED (0x%02lx).\n", rv);
    } else {
        printf("    [FAIL] C_AsyncComplete returned an unexpected code: 0x%02lx\n", rv);
        return 1;
    }

    // Cleanup
    pFunctionList->C_CloseSession(hSession);
    pFunctionList->C_Finalize(NULL);
    dlclose(module);

    printf("\n[SUCCESS] Asynchronous Integration Architecture passed all sanity tests!\n");
    return 0;
}
