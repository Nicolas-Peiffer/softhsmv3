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
 OSSLMLDSA.cpp

 OpenSSL ML-DSA (FIPS 204) asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLMLDSA.h"
#include "MLDSAParameters.h"
#include "OSSLMLDSAKeyPair.h"
#include "OSSLMLDSAPublicKey.h"
#include "OSSLMLDSAPrivateKey.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

// ─── Signing ─────────────────────────────────────────────────────────────────

bool OSSLMLDSA::sign(PrivateKey* privateKey, const ByteString& dataToSign,
                     ByteString& signature, const AsymMech::Type mechanism,
                     const void* /* param */, const size_t /* paramLen */)
{
	if (mechanism != AsymMech::MLDSA)
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
		return false;
	}
	if (!privateKey->isOfType(OSSLMLDSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied for ML-DSA sign");
		return false;
	}

	OSSLMLDSAPrivateKey* pk = (OSSLMLDSAPrivateKey*)privateKey;
	EVP_PKEY* pkey = pk->getOSSLKey();
	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL ML-DSA private key");
		return false;
	}

	// Pre-size the output buffer to the maximum signature length
	size_t sigLen = pk->getOutputLength();
	signature.resize(sigLen);

	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
	{
		ERROR_MSG("EVP_MD_CTX_new failed");
		return false;
	}
	if (!EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey))
	{
		ERROR_MSG("ML-DSA sign init failed (0x%08X)", ERR_get_error());
		EVP_MD_CTX_free(ctx);
		return false;
	}
	if (!EVP_DigestSign(ctx, &signature[0], &sigLen,
	                    dataToSign.const_byte_str(), dataToSign.size()))
	{
		ERROR_MSG("ML-DSA sign failed (0x%08X)", ERR_get_error());
		EVP_MD_CTX_free(ctx);
		return false;
	}
	EVP_MD_CTX_free(ctx);
	signature.resize(sigLen);
	return true;
}

bool OSSLMLDSA::signInit(PrivateKey* /*pk*/, const AsymMech::Type /*mech*/,
                          const void* /*param*/, const size_t /*paramLen*/)
{
	ERROR_MSG("ML-DSA does not support multi-part signing");
	return false;
}

bool OSSLMLDSA::signUpdate(const ByteString& /*data*/)
{
	ERROR_MSG("ML-DSA does not support multi-part signing");
	return false;
}

bool OSSLMLDSA::signFinal(ByteString& /*sig*/)
{
	ERROR_MSG("ML-DSA does not support multi-part signing");
	return false;
}

// ─── Verification ────────────────────────────────────────────────────────────

bool OSSLMLDSA::verify(PublicKey* publicKey, const ByteString& originalData,
                       const ByteString& signature, const AsymMech::Type mechanism,
                       const void* /* param */, const size_t /* paramLen */)
{
	if (mechanism != AsymMech::MLDSA)
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
		return false;
	}
	if (!publicKey->isOfType(OSSLMLDSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied for ML-DSA verify");
		return false;
	}

	OSSLMLDSAPublicKey* pk = (OSSLMLDSAPublicKey*)publicKey;
	EVP_PKEY* pkey = pk->getOSSLKey();
	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL ML-DSA public key");
		return false;
	}

	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
	{
		ERROR_MSG("EVP_MD_CTX_new failed");
		return false;
	}
	if (!EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey))
	{
		ERROR_MSG("ML-DSA verify init failed (0x%08X)", ERR_get_error());
		EVP_MD_CTX_free(ctx);
		return false;
	}
	int ret = EVP_DigestVerify(ctx,
	                           signature.const_byte_str(), signature.size(),
	                           originalData.const_byte_str(), originalData.size());
	EVP_MD_CTX_free(ctx);
	if (ret != 1)
	{
		if (ret < 0)
			ERROR_MSG("ML-DSA verify failed (0x%08X)", ERR_get_error());
		return false;
	}
	return true;
}

bool OSSLMLDSA::verifyInit(PublicKey* /*pk*/, const AsymMech::Type /*mech*/,
                            const void* /*param*/, const size_t /*paramLen*/)
{
	ERROR_MSG("ML-DSA does not support multi-part verifying");
	return false;
}

bool OSSLMLDSA::verifyUpdate(const ByteString& /*data*/)
{
	ERROR_MSG("ML-DSA does not support multi-part verifying");
	return false;
}

bool OSSLMLDSA::verifyFinal(const ByteString& /*sig*/)
{
	ERROR_MSG("ML-DSA does not support multi-part verifying");
	return false;
}

// ─── Encryption / decryption (not supported) ─────────────────────────────────

bool OSSLMLDSA::encrypt(PublicKey* /*pk*/, const ByteString& /*data*/,
                         ByteString& /*enc*/, const AsymMech::Type /*pad*/)
{
	ERROR_MSG("ML-DSA does not support encryption");
	return false;
}

bool OSSLMLDSA::decrypt(PrivateKey* /*pk*/, const ByteString& /*enc*/,
                         ByteString& /*data*/, const AsymMech::Type /*pad*/)
{
	ERROR_MSG("ML-DSA does not support decryption");
	return false;
}

// ─── Key factory ─────────────────────────────────────────────────────────────

bool OSSLMLDSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair,
                                 AsymmetricParameters* parameters, RNG* /*rng*/)
{
	if (ppKeyPair == NULL || parameters == NULL) return false;

	if (!parameters->areOfType(MLDSAParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for ML-DSA key generation");
		return false;
	}

	MLDSAParameters* params = (MLDSAParameters*)parameters;
	const char* keyName;
	switch (params->getParameterSet())
	{
		case CKP_ML_DSA_44: keyName = "ml-dsa-44"; break;
		case CKP_ML_DSA_65: keyName = "ml-dsa-65"; break;
		case CKP_ML_DSA_87: keyName = "ml-dsa-87"; break;
		default:
			ERROR_MSG("Unknown ML-DSA parameter set %lu", params->getParameterSet());
			return false;
	}

	EVP_PKEY* pkey = NULL;
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, keyName, NULL);
	if (ctx == NULL)
	{
		ERROR_MSG("EVP_PKEY_CTX_new_from_name(%s) failed (0x%08X)", keyName, ERR_get_error());
		return false;
	}
	if (EVP_PKEY_keygen_init(ctx) != 1)
	{
		ERROR_MSG("ML-DSA keygen init failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	if (EVP_PKEY_keygen(ctx, &pkey) != 1)
	{
		ERROR_MSG("ML-DSA keygen failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	EVP_PKEY_CTX_free(ctx);

	OSSLMLDSAKeyPair* kp = new OSSLMLDSAKeyPair();
	((OSSLMLDSAPublicKey*)kp->getPublicKey())->setFromOSSL(pkey);
	((OSSLMLDSAPrivateKey*)kp->getPrivateKey())->setFromOSSL(pkey);
	EVP_PKEY_free(pkey);

	*ppKeyPair = kp;
	return true;
}

unsigned long OSSLMLDSA::getMinKeySize()
{
	return 128;  // ML-DSA-44 security strength
}

unsigned long OSSLMLDSA::getMaxKeySize()
{
	return 256;  // ML-DSA-87 security strength
}

bool OSSLMLDSA::deriveKey(SymmetricKey** /*ppKey*/, PublicKey* /*pub*/, PrivateKey* /*priv*/)
{
	ERROR_MSG("ML-DSA does not support key derivation");
	return false;
}

bool OSSLMLDSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	if (ppKeyPair == NULL || serialisedData.size() == 0) return false;

	ByteString dPub  = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	OSSLMLDSAKeyPair* kp = new OSSLMLDSAKeyPair();
	bool rv = true;
	if (!((MLDSAPublicKey*)kp->getPublicKey())->deserialise(dPub))   rv = false;
	if (!((MLDSAPrivateKey*)kp->getPrivateKey())->deserialise(dPriv)) rv = false;
	if (!rv) { delete kp; return false; }
	*ppKeyPair = kp;
	return true;
}

bool OSSLMLDSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	if (ppPublicKey == NULL || serialisedData.size() == 0) return false;
	OSSLMLDSAPublicKey* pub = new OSSLMLDSAPublicKey();
	if (!pub->deserialise(serialisedData)) { delete pub; return false; }
	*ppPublicKey = pub;
	return true;
}

bool OSSLMLDSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	if (ppPrivateKey == NULL || serialisedData.size() == 0) return false;
	OSSLMLDSAPrivateKey* priv = new OSSLMLDSAPrivateKey();
	if (!priv->deserialise(serialisedData)) { delete priv; return false; }
	*ppPrivateKey = priv;
	return true;
}

bool OSSLMLDSA::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	if (ppParams == NULL || serialisedData.size() == 0) return false;
	MLDSAParameters* params = new MLDSAParameters();
	if (!params->deserialise(serialisedData)) { delete params; return false; }
	*ppParams = params;
	return true;
}

PublicKey* OSSLMLDSA::newPublicKey()
{
	return (PublicKey*) new OSSLMLDSAPublicKey();
}

PrivateKey* OSSLMLDSA::newPrivateKey()
{
	return (PrivateKey*) new OSSLMLDSAPrivateKey();
}

AsymmetricParameters* OSSLMLDSA::newParameters()
{
	return (AsymmetricParameters*) new MLDSAParameters();
}
