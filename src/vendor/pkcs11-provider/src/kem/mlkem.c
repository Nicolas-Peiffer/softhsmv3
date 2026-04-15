/*
 * Copyright (c) 2026 SoftHSMv3 Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "src/provider.h"
#include <string.h>

#ifndef CKM_ML_KEM
#define CKM_ML_KEM 0x00000017UL
#endif

typedef struct p11prov_kem_ctx {
    P11PROV_CTX *provctx;
    P11PROV_OBJ *key;
    CK_MECHANISM_TYPE mechtype;
    P11PROV_SESSION *session;
} P11PROV_KEM_CTX;

static void *p11prov_kem_newctx(void *provctx)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    P11PROV_KEM_CTX *kemctx;

    kemctx = OPENSSL_zalloc(sizeof(P11PROV_KEM_CTX));
    if (kemctx == NULL) {
        return NULL;
    }

    kemctx->provctx = ctx;
    kemctx->mechtype = CKM_ML_KEM;
    return kemctx;
}

static void p11prov_kem_freectx(void *ctx)
{
    P11PROV_KEM_CTX *kemctx = (P11PROV_KEM_CTX *)ctx;

    if (kemctx == NULL) {
        return;
    }

    p11prov_obj_free(kemctx->key);
    p11prov_return_session(kemctx->session);
    OPENSSL_free(kemctx);
}

static int p11prov_kem_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    P11PROV_KEM_CTX *kemctx = (P11PROV_KEM_CTX *)ctx;
    (void)params;

    if (kemctx == NULL || provkey == NULL) {
        return 0;
    }

    p11prov_obj_free(kemctx->key);
    kemctx->key = p11prov_obj_ref((P11PROV_OBJ *)provkey);
    
    return 1;
}

static int p11prov_kem_encapsulate(void *ctx, unsigned char *out, size_t *outlen,
                                   unsigned char *secret, size_t *secretlen)
{
    P11PROV_KEM_CTX *kemctx = (P11PROV_KEM_CTX *)ctx;
    CK_RV ret;
    CK_MECHANISM mech = { kemctx->mechtype, NULL, 0 };
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE hKey;
    CK_OBJECT_HANDLE hSecretHandle = CK_INVALID_HANDLE;

    if (kemctx->key == NULL) {
        return 0;
    }

    if (kemctx->session == NULL) {
        ret = p11prov_try_session_ref(kemctx->key, kemctx->mechtype, false, false, &kemctx->session);
        if (ret != CKR_OK || kemctx->session == NULL) {
            return 0;
        }
    }

    session = p11prov_session_handle(kemctx->session);
    hKey = p11prov_obj_get_handle(kemctx->key);

    /* 
     * PKCS#11 v3.2 C_EncapsulateKey Size querying:
     * If out is NULL, returns required length of ciphertext in outlen
     */
    if (out == NULL) {
        CK_ULONG ctlen = 0;
        ret = p11prov_EncapsulateKey(kemctx->provctx, session, &mech, hKey, NULL, 0, NULL, &ctlen, &hSecretHandle);
        if (ret != CKR_OK) {
            P11PROV_raise(kemctx->provctx, ret, "Failed to query KEM encapsulation sizes");
            return 0;
        }
        *outlen = ctlen;
        return 1;
    }

    /* Actually Encapsulate */
    CK_ULONG out_len_ck = *outlen;
    CK_ATTRIBUTE ts[3];
    CK_ULONG tlen = 0;
    CK_OBJECT_CLASS class = CKO_SECRET_KEY;
    CK_KEY_TYPE type = CKK_GENERIC_SECRET;
    CK_BBOOL extractable = CK_TRUE;

    ts[0].type = CKA_CLASS;
    ts[0].pValue = &class;
    ts[0].ulValueLen = sizeof(class);
    ts[1].type = CKA_KEY_TYPE;
    ts[1].pValue = &type;
    ts[1].ulValueLen = sizeof(type);
    ts[2].type = CKA_EXTRACTABLE;
    ts[2].pValue = &extractable;
    ts[2].ulValueLen = sizeof(extractable);
    tlen = 3;

    ret = p11prov_EncapsulateKey(kemctx->provctx, session, &mech, hKey, ts, tlen, out, &out_len_ck, &hSecretHandle);
    if (ret != CKR_OK) {
        P11PROV_raise(kemctx->provctx, ret, "C_EncapsulateKey failed");
        return 0;
    }
    *outlen = out_len_ck;

    /* Now extract the secret value from the returned token session object */
    if (secret != NULL) {
        CK_ATTRIBUTE get_ts[] = {
            { CKA_VALUE, NULL, 0 }
        };
        
        ret = p11prov_GetAttributeValue(kemctx->provctx, session, hSecretHandle, get_ts, 1);
        if (ret != CKR_OK) {
            p11prov_DestroyObject(kemctx->provctx, session, hSecretHandle);
            P11PROV_raise(kemctx->provctx, ret, "Failed to query KEM secret size");
            return 0;
        }

        if (get_ts[0].ulValueLen > *secretlen) {
            p11prov_DestroyObject(kemctx->provctx, session, hSecretHandle);
            P11PROV_raise(kemctx->provctx, CKR_BUFFER_TOO_SMALL, "KEM secretlen buffer too small");
            return 0;
        }

        get_ts[0].pValue = secret;
        ret = p11prov_GetAttributeValue(kemctx->provctx, session, hSecretHandle, get_ts, 1);
        if (ret != CKR_OK) {
            p11prov_DestroyObject(kemctx->provctx, session, hSecretHandle);
            P11PROV_raise(kemctx->provctx, ret, "Failed to retrieve KEM secret value");
            return 0;
        }
        *secretlen = get_ts[0].ulValueLen;
    }

    p11prov_DestroyObject(kemctx->provctx, session, hSecretHandle);
    return 1;
}

static int p11prov_kem_decapsulate(void *ctx, unsigned char *out, size_t *outlen,
                                   const unsigned char *in, size_t inlen)
{
    P11PROV_KEM_CTX *kemctx = (P11PROV_KEM_CTX *)ctx;
    CK_RV ret;
    CK_MECHANISM mech = { kemctx->mechtype, NULL, 0 };
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE hKey;
    CK_OBJECT_HANDLE hSecretHandle = CK_INVALID_HANDLE;

    if (kemctx->key == NULL) {
        return 0;
    }

    if (kemctx->session == NULL) {
        ret = p11prov_try_session_ref(kemctx->key, kemctx->mechtype, false, false, &kemctx->session);
        if (ret != CKR_OK || kemctx->session == NULL) {
            return 0;
        }
    }

    /* Out handles the shared secret, in handles the ciphertext */

    /* If out is NULL, query the size of the shared secret */
    /* But unfortunately, PKCS11 C_DecapsulateKey requires generating an object first! */
    /* OpenSSL expects us to just return the max size of the secret if out == NULL */
    /* ML-KEM shared secrets are exactly 32 bytes */
    if (out == NULL) {
        *outlen = 32;
        return 1;
    }

    session = p11prov_session_handle(kemctx->session);
    hKey = p11prov_obj_get_handle(kemctx->key);

    CK_ATTRIBUTE ts[3];
    CK_ULONG tlen = 0;
    CK_OBJECT_CLASS class = CKO_SECRET_KEY;
    CK_KEY_TYPE type = CKK_GENERIC_SECRET;
    CK_BBOOL extractable = CK_TRUE;

    ts[0].type = CKA_CLASS;
    ts[0].pValue = &class;
    ts[0].ulValueLen = sizeof(class);
    ts[1].type = CKA_KEY_TYPE;
    ts[1].pValue = &type;
    ts[1].ulValueLen = sizeof(type);
    ts[2].type = CKA_EXTRACTABLE;
    ts[2].pValue = &extractable;
    ts[2].ulValueLen = sizeof(extractable);
    tlen = 3;

    ret = p11prov_DecapsulateKey(kemctx->provctx, session, &mech, hKey, ts, tlen, (unsigned char*)in, inlen, &hSecretHandle);
    if (ret != CKR_OK) {
        P11PROV_raise(kemctx->provctx, ret, "C_DecapsulateKey failed");
        return 0;
    }

    /* Extract the secret value */
    CK_ATTRIBUTE get_ts[] = {
        { CKA_VALUE, NULL, 0 }
    };
    
    ret = p11prov_GetAttributeValue(kemctx->provctx, session, hSecretHandle, get_ts, 1);
    if (ret != CKR_OK) {
        p11prov_DestroyObject(kemctx->provctx, session, hSecretHandle);
        P11PROV_raise(kemctx->provctx, ret, "Failed to query KEM decapsulated secret size");
        return 0;
    }

    if (get_ts[0].ulValueLen > *outlen) {
        p11prov_DestroyObject(kemctx->provctx, session, hSecretHandle);
        P11PROV_raise(kemctx->provctx, CKR_BUFFER_TOO_SMALL, "KEM secret output buffer too small");
        return 0;
    }

    get_ts[0].pValue = out;
    ret = p11prov_GetAttributeValue(kemctx->provctx, session, hSecretHandle, get_ts, 1);
    if (ret != CKR_OK) {
        p11prov_DestroyObject(kemctx->provctx, session, hSecretHandle);
        P11PROV_raise(kemctx->provctx, ret, "Failed to retrieve KEM decapsulated secret value");
        return 0;
    }
    *outlen = get_ts[0].ulValueLen;

    p11prov_DestroyObject(kemctx->provctx, session, hSecretHandle);
    return 1;
}

const OSSL_DISPATCH p11prov_mlkem_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))p11prov_kem_newctx },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void))p11prov_kem_freectx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))p11prov_kem_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))p11prov_kem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))p11prov_kem_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))p11prov_kem_decapsulate },
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_mlkem_keymgmt_functions[] = {
    { 0, NULL },
};
