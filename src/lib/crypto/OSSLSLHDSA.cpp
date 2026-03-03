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
 OSSLSLHDSA.cpp

 OpenSSL SLH-DSA (FIPS 205) asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLSLHDSA.h"
#include "SLHDSAParameters.h"
#include "OSSLSLHDSAKeyPair.h"
#include "OSSLSLHDSAPublicKey.h"
#include "OSSLSLHDSAPrivateKey.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

// Map CKP_SLH_DSA_* → OpenSSL name string (used only in generateKeyPair)
static const char* slhdsaParamSetToName(CK_ULONG ps)
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

// ─── Signing ─────────────────────────────────────────────────────────────────

bool OSSLSLHDSA::sign(PrivateKey* privateKey, const ByteString& dataToSign,
                      ByteString& signature, const AsymMech::Type mechanism,
                      const void* /* param */, const size_t /* paramLen */)
{
	if (mechanism != AsymMech::SLHDSA)
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
		return false;
	}
	if (!privateKey->isOfType(OSSLSLHDSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied for SLH-DSA sign");
		return false;
	}

	OSSLSLHDSAPrivateKey* pk = (OSSLSLHDSAPrivateKey*)privateKey;
	EVP_PKEY* pkey = pk->getOSSLKey();
	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL SLH-DSA private key");
		return false;
	}

	size_t sigLen = pk->getOutputLength();
	signature.resize(sigLen);

	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if (ctx == NULL) { ERROR_MSG("EVP_MD_CTX_new failed"); return false; }

	if (!EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey))
	{
		ERROR_MSG("SLH-DSA sign init failed (0x%08X)", ERR_get_error());
		EVP_MD_CTX_free(ctx);
		return false;
	}
	if (!EVP_DigestSign(ctx, &signature[0], &sigLen,
	                    dataToSign.const_byte_str(), dataToSign.size()))
	{
		ERROR_MSG("SLH-DSA sign failed (0x%08X)", ERR_get_error());
		EVP_MD_CTX_free(ctx);
		return false;
	}
	EVP_MD_CTX_free(ctx);
	signature.resize(sigLen);
	return true;
}

bool OSSLSLHDSA::signInit(PrivateKey* /*pk*/, const AsymMech::Type /*mech*/,
                           const void* /*param*/, const size_t /*paramLen*/)
{
	ERROR_MSG("SLH-DSA does not support multi-part signing");
	return false;
}

bool OSSLSLHDSA::signUpdate(const ByteString& /*data*/)
{
	ERROR_MSG("SLH-DSA does not support multi-part signing");
	return false;
}

bool OSSLSLHDSA::signFinal(ByteString& /*sig*/)
{
	ERROR_MSG("SLH-DSA does not support multi-part signing");
	return false;
}

// ─── Verification ────────────────────────────────────────────────────────────

bool OSSLSLHDSA::verify(PublicKey* publicKey, const ByteString& originalData,
                        const ByteString& signature, const AsymMech::Type mechanism,
                        const void* /* param */, const size_t /* paramLen */)
{
	if (mechanism != AsymMech::SLHDSA)
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
		return false;
	}
	if (!publicKey->isOfType(OSSLSLHDSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied for SLH-DSA verify");
		return false;
	}

	OSSLSLHDSAPublicKey* pk = (OSSLSLHDSAPublicKey*)publicKey;
	EVP_PKEY* pkey = pk->getOSSLKey();
	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL SLH-DSA public key");
		return false;
	}

	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if (ctx == NULL) { ERROR_MSG("EVP_MD_CTX_new failed"); return false; }

	if (!EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey))
	{
		ERROR_MSG("SLH-DSA verify init failed (0x%08X)", ERR_get_error());
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
			ERROR_MSG("SLH-DSA verify failed (0x%08X)", ERR_get_error());
		return false;
	}
	return true;
}

bool OSSLSLHDSA::verifyInit(PublicKey* /*pk*/, const AsymMech::Type /*mech*/,
                             const void* /*param*/, const size_t /*paramLen*/)
{
	ERROR_MSG("SLH-DSA does not support multi-part verifying");
	return false;
}

bool OSSLSLHDSA::verifyUpdate(const ByteString& /*data*/)
{
	ERROR_MSG("SLH-DSA does not support multi-part verifying");
	return false;
}

bool OSSLSLHDSA::verifyFinal(const ByteString& /*sig*/)
{
	ERROR_MSG("SLH-DSA does not support multi-part verifying");
	return false;
}

// ─── Encryption / decryption (not supported) ─────────────────────────────────

bool OSSLSLHDSA::encrypt(PublicKey* /*pk*/, const ByteString& /*data*/,
                          ByteString& /*enc*/, const AsymMech::Type /*pad*/)
{
	ERROR_MSG("SLH-DSA does not support encryption");
	return false;
}

bool OSSLSLHDSA::decrypt(PrivateKey* /*pk*/, const ByteString& /*enc*/,
                          ByteString& /*data*/, const AsymMech::Type /*pad*/)
{
	ERROR_MSG("SLH-DSA does not support decryption");
	return false;
}

// ─── Key factory ─────────────────────────────────────────────────────────────

bool OSSLSLHDSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair,
                                  AsymmetricParameters* parameters, RNG* /*rng*/)
{
	if (ppKeyPair == NULL || parameters == NULL) return false;

	if (!parameters->areOfType(SLHDSAParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for SLH-DSA key generation");
		return false;
	}

	SLHDSAParameters* params = (SLHDSAParameters*)parameters;
	const char* keyName = slhdsaParamSetToName(params->getParameterSet());
	if (keyName == NULL)
	{
		ERROR_MSG("Unknown SLH-DSA parameter set %lu", params->getParameterSet());
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
		ERROR_MSG("SLH-DSA keygen init failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	if (EVP_PKEY_keygen(ctx, &pkey) != 1)
	{
		ERROR_MSG("SLH-DSA keygen failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	EVP_PKEY_CTX_free(ctx);

	OSSLSLHDSAKeyPair* kp = new OSSLSLHDSAKeyPair();
	((OSSLSLHDSAPublicKey*)kp->getPublicKey())->setFromOSSL(pkey);
	((OSSLSLHDSAPrivateKey*)kp->getPrivateKey())->setFromOSSL(pkey);
	EVP_PKEY_free(pkey);

	*ppKeyPair = kp;
	return true;
}

unsigned long OSSLSLHDSA::getMinKeySize()
{
	return 128;  // SHA2-128s / SHAKE-128s security strength
}

unsigned long OSSLSLHDSA::getMaxKeySize()
{
	return 256;  // SHA2-256f / SHAKE-256f security strength
}

bool OSSLSLHDSA::deriveKey(SymmetricKey** /*ppKey*/, PublicKey* /*pub*/, PrivateKey* /*priv*/)
{
	ERROR_MSG("SLH-DSA does not support key derivation");
	return false;
}

bool OSSLSLHDSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	if (ppKeyPair == NULL || serialisedData.size() == 0) return false;

	ByteString dPub  = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	OSSLSLHDSAKeyPair* kp = new OSSLSLHDSAKeyPair();
	bool rv = true;
	if (!((SLHDSAPublicKey*)kp->getPublicKey())->deserialise(dPub))    rv = false;
	if (!((SLHDSAPrivateKey*)kp->getPrivateKey())->deserialise(dPriv)) rv = false;
	if (!rv) { delete kp; return false; }
	*ppKeyPair = kp;
	return true;
}

bool OSSLSLHDSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	if (ppPublicKey == NULL || serialisedData.size() == 0) return false;
	OSSLSLHDSAPublicKey* pub = new OSSLSLHDSAPublicKey();
	if (!pub->deserialise(serialisedData)) { delete pub; return false; }
	*ppPublicKey = pub;
	return true;
}

bool OSSLSLHDSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	if (ppPrivateKey == NULL || serialisedData.size() == 0) return false;
	OSSLSLHDSAPrivateKey* priv = new OSSLSLHDSAPrivateKey();
	if (!priv->deserialise(serialisedData)) { delete priv; return false; }
	*ppPrivateKey = priv;
	return true;
}

bool OSSLSLHDSA::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	if (ppParams == NULL || serialisedData.size() == 0) return false;
	SLHDSAParameters* params = new SLHDSAParameters();
	if (!params->deserialise(serialisedData)) { delete params; return false; }
	*ppParams = params;
	return true;
}

PublicKey* OSSLSLHDSA::newPublicKey()
{
	return (PublicKey*) new OSSLSLHDSAPublicKey();
}

PrivateKey* OSSLSLHDSA::newPrivateKey()
{
	return (PrivateKey*) new OSSLSLHDSAPrivateKey();
}

AsymmetricParameters* OSSLSLHDSA::newParameters()
{
	return (AsymmetricParameters*) new SLHDSAParameters();
}
