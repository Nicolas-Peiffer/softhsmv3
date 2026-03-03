/*
 * Copyright (c) 2010 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 OSSLSLHDSAPublicKey.cpp

 OpenSSL SLH-DSA public key class (FIPS 205)
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLSLHDSAPublicKey.h"
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/err.h>
#include <string.h>

/*static*/ const char* OSSLSLHDSAPublicKey::type = "OpenSSL SLH-DSA Public Key";

/*static*/ const char* OSSLSLHDSAPublicKey::paramSetToName(CK_ULONG ps)
{
	switch (ps)
	{
		case CKP_SLH_DSA_SHA2_128S:  return "slh-dsa-sha2-128s";
		case CKP_SLH_DSA_SHAKE_128S: return "slh-dsa-shake-128s";
		case CKP_SLH_DSA_SHA2_128F:  return "slh-dsa-sha2-128f";
		case CKP_SLH_DSA_SHAKE_128F: return "slh-dsa-shake-128f";
		case CKP_SLH_DSA_SHA2_192S:  return "slh-dsa-sha2-192s";
		case CKP_SLH_DSA_SHAKE_192S: return "slh-dsa-shake-192s";
		case CKP_SLH_DSA_SHA2_192F:  return "slh-dsa-sha2-192f";
		case CKP_SLH_DSA_SHAKE_192F: return "slh-dsa-shake-192f";
		case CKP_SLH_DSA_SHA2_256S:  return "slh-dsa-sha2-256s";
		case CKP_SLH_DSA_SHAKE_256S: return "slh-dsa-shake-256s";
		case CKP_SLH_DSA_SHA2_256F:  return "slh-dsa-sha2-256f";
		case CKP_SLH_DSA_SHAKE_256F: return "slh-dsa-shake-256f";
		default:                     return NULL;
	}
}

// Helper: detect CKP_SLH_DSA_* from OpenSSL key name
static CK_ULONG slhdsaNameToParamSet(const EVP_PKEY* pkey)
{
	if (EVP_PKEY_is_a(pkey, "slh-dsa-sha2-128s"))  return CKP_SLH_DSA_SHA2_128S;
	if (EVP_PKEY_is_a(pkey, "slh-dsa-shake-128s")) return CKP_SLH_DSA_SHAKE_128S;
	if (EVP_PKEY_is_a(pkey, "slh-dsa-sha2-128f"))  return CKP_SLH_DSA_SHA2_128F;
	if (EVP_PKEY_is_a(pkey, "slh-dsa-shake-128f")) return CKP_SLH_DSA_SHAKE_128F;
	if (EVP_PKEY_is_a(pkey, "slh-dsa-sha2-192s"))  return CKP_SLH_DSA_SHA2_192S;
	if (EVP_PKEY_is_a(pkey, "slh-dsa-shake-192s")) return CKP_SLH_DSA_SHAKE_192S;
	if (EVP_PKEY_is_a(pkey, "slh-dsa-sha2-192f"))  return CKP_SLH_DSA_SHA2_192F;
	if (EVP_PKEY_is_a(pkey, "slh-dsa-shake-192f")) return CKP_SLH_DSA_SHAKE_192F;
	if (EVP_PKEY_is_a(pkey, "slh-dsa-sha2-256s"))  return CKP_SLH_DSA_SHA2_256S;
	if (EVP_PKEY_is_a(pkey, "slh-dsa-shake-256s")) return CKP_SLH_DSA_SHAKE_256S;
	if (EVP_PKEY_is_a(pkey, "slh-dsa-sha2-256f"))  return CKP_SLH_DSA_SHA2_256F;
	if (EVP_PKEY_is_a(pkey, "slh-dsa-shake-256f")) return CKP_SLH_DSA_SHAKE_256F;
	return 0;  // unknown
}

OSSLSLHDSAPublicKey::OSSLSLHDSAPublicKey() : pkey(NULL)
{
	parameterSet = CKP_SLH_DSA_SHA2_128S;
}

OSSLSLHDSAPublicKey::OSSLSLHDSAPublicKey(const EVP_PKEY* inPKEY) : pkey(NULL)
{
	parameterSet = CKP_SLH_DSA_SHA2_128S;
	setFromOSSL(inPKEY);
}

OSSLSLHDSAPublicKey::~OSSLSLHDSAPublicKey()
{
	EVP_PKEY_free(pkey);
}

bool OSSLSLHDSAPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

void OSSLSLHDSAPublicKey::setParameterSet(CK_ULONG inParamSet)
{
	SLHDSAPublicKey::setParameterSet(inParamSet);
	if (pkey) { EVP_PKEY_free(pkey); pkey = NULL; }
}

void OSSLSLHDSAPublicKey::setValue(const ByteString& inValue)
{
	SLHDSAPublicKey::setValue(inValue);
	if (pkey) { EVP_PKEY_free(pkey); pkey = NULL; }
}

void OSSLSLHDSAPublicKey::setFromOSSL(const EVP_PKEY* inPKEY)
{
	if (inPKEY == NULL) return;

	CK_ULONG ps = slhdsaNameToParamSet(inPKEY);
	if (ps == 0)
	{
		ERROR_MSG("Unknown SLH-DSA parameter set in setFromOSSL");
		return;
	}
	SLHDSAPublicKey::setParameterSet(ps);

	EVP_PKEY* key = const_cast<EVP_PKEY*>(inPKEY);
	size_t pubLen = 0;
	if (!EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &pubLen) || pubLen == 0)
	{
		ERROR_MSG("Could not determine SLH-DSA public key length (0x%08X)", ERR_get_error());
		return;
	}
	ByteString pub;
	pub.resize(pubLen);
	if (!EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, &pub[0], pubLen, &pubLen))
	{
		ERROR_MSG("Could not extract SLH-DSA public key (0x%08X)", ERR_get_error());
		return;
	}
	SLHDSAPublicKey::setValue(pub);

	if (pkey) EVP_PKEY_free(pkey);
	pkey = EVP_PKEY_dup(key);
}

EVP_PKEY* OSSLSLHDSAPublicKey::getOSSLKey()
{
	if (pkey == NULL) createOSSLKey();
	return pkey;
}

void OSSLSLHDSAPublicKey::createOSSLKey()
{
	if (pkey != NULL) return;
	if (value.size() == 0) return;

	const char* keyName = paramSetToName(parameterSet);
	if (keyName == NULL)
	{
		ERROR_MSG("Unknown SLH-DSA parameter set %lu in createOSSLKey", parameterSet);
		return;
	}

	OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
	if (bld == NULL) { ERROR_MSG("OSSL_PARAM_BLD_new failed"); return; }

	if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
	                                       value.const_byte_str(), value.size()))
	{
		OSSL_PARAM_BLD_free(bld);
		ERROR_MSG("OSSL_PARAM_BLD_push_octet_string failed");
		return;
	}
	OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
	OSSL_PARAM_BLD_free(bld);
	if (params == NULL) { ERROR_MSG("OSSL_PARAM_BLD_to_param failed"); return; }

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, keyName, NULL);
	if (ctx == NULL)
	{
		OSSL_PARAM_free(params);
		ERROR_MSG("EVP_PKEY_CTX_new_from_name(%s) failed (0x%08X)", keyName, ERR_get_error());
		return;
	}
	if (EVP_PKEY_fromdata_init(ctx) <= 0)
	{
		OSSL_PARAM_free(params);
		EVP_PKEY_CTX_free(ctx);
		ERROR_MSG("EVP_PKEY_fromdata_init failed (0x%08X)", ERR_get_error());
		return;
	}
	if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
	{
		OSSL_PARAM_free(params);
		EVP_PKEY_CTX_free(ctx);
		ERROR_MSG("EVP_PKEY_fromdata (SLH-DSA public) failed (0x%08X)", ERR_get_error());
		return;
	}
	OSSL_PARAM_free(params);
	EVP_PKEY_CTX_free(ctx);
}
