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
 OSSLRSAPublicKey.cpp

 OpenSSL RSA public key class — EVP_PKEY throughout (OpenSSL 3.x)
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLRSAPublicKey.h"
#include "OSSLUtil.h"
#include <string.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/param_build.h>

// Constructors
OSSLRSAPublicKey::OSSLRSAPublicKey()
{
	pkey = NULL;
}

OSSLRSAPublicKey::OSSLRSAPublicKey(const EVP_PKEY* inPKEY)
{
	pkey = NULL;

	setFromOSSL(inPKEY);
}

// Destructor
OSSLRSAPublicKey::~OSSLRSAPublicKey()
{
	EVP_PKEY_free(pkey);
}

// The type
/*static*/ const char* OSSLRSAPublicKey::type = "OpenSSL RSA Public Key";

// Check if the key is of the given type
bool OSSLRSAPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Set from OpenSSL EVP_PKEY representation
void OSSLRSAPublicKey::setFromOSSL(const EVP_PKEY* inPKEY)
{
	BIGNUM* bn_n = NULL;
	BIGNUM* bn_e = NULL;

	if (EVP_PKEY_get_bn_param(inPKEY, OSSL_PKEY_PARAM_RSA_N, &bn_n) && bn_n)
	{
		ByteString inN = OSSL::bn2ByteString(bn_n);
		setN(inN);
		BN_free(bn_n);
	}
	if (EVP_PKEY_get_bn_param(inPKEY, OSSL_PKEY_PARAM_RSA_E, &bn_e) && bn_e)
	{
		ByteString inE = OSSL::bn2ByteString(bn_e);
		setE(inE);
		BN_free(bn_e);
	}
}

// Setters for the RSA public key components
void OSSLRSAPublicKey::setN(const ByteString& inN)
{
	RSAPublicKey::setN(inN);

	if (pkey)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
}

void OSSLRSAPublicKey::setE(const ByteString& inE)
{
	RSAPublicKey::setE(inE);

	if (pkey)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
}

// Retrieve the OpenSSL EVP_PKEY representation of the key (built lazily)
EVP_PKEY* OSSLRSAPublicKey::getOSSLKey()
{
	if (pkey != NULL)
		return pkey;

	if (n.size() == 0 || e.size() == 0)
		return NULL;

	BIGNUM* bn_n = OSSL::byteString2bn(n);
	BIGNUM* bn_e = OSSL::byteString2bn(e);

	if (bn_n == NULL || bn_e == NULL)
	{
		BN_free(bn_n);
		BN_free(bn_e);
		return NULL;
	}

	OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
	if (bld == NULL)
	{
		BN_free(bn_n);
		BN_free(bn_e);
		return NULL;
	}

	if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, bn_n) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, bn_e))
	{
		OSSL_PARAM_BLD_free(bld);
		BN_free(bn_n);
		BN_free(bn_e);
		return NULL;
	}

	OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
	OSSL_PARAM_BLD_free(bld);
	BN_free(bn_n);
	BN_free(bn_e);

	if (params == NULL)
		return NULL;

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (ctx == NULL)
	{
		OSSL_PARAM_free(params);
		return NULL;
	}

	if (EVP_PKEY_fromdata_init(ctx) <= 0 ||
	    EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
	{
		ERROR_MSG("Could not build EVP_PKEY for RSA public key (0x%08X)", ERR_get_error());
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}

	EVP_PKEY_CTX_free(ctx);
	OSSL_PARAM_free(params);

	return pkey;
}
