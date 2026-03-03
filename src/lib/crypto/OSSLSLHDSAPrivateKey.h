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
 OSSLSLHDSAPrivateKey.h

 OpenSSL SLH-DSA private key class (FIPS 205)
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLSLHDSAPRIVATEKEY_H
#define _SOFTHSM_V2_OSSLSLHDSAPRIVATEKEY_H

#include "config.h"
#include "SLHDSAPrivateKey.h"
#include <openssl/evp.h>

class OSSLSLHDSAPrivateKey : public SLHDSAPrivateKey
{
public:
	// Constructors
	OSSLSLHDSAPrivateKey();
	OSSLSLHDSAPrivateKey(const EVP_PKEY* inPKEY);

	// Destructor
	virtual ~OSSLSLHDSAPrivateKey();

	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* inType);

	// Override setters to invalidate cached pkey
	virtual void setParameterSet(CK_ULONG inParamSet);
	virtual void setValue(const ByteString& inValue);

	// Set from OpenSSL representation (encodes to PKCS#8 DER → value)
	void setFromOSSL(const EVP_PKEY* inPKEY);

	// PKCS#8 encode/decode (for key wrapping/unwrapping)
	ByteString PKCS8Encode();
	bool PKCS8Decode(const ByteString& ber);

	// Retrieve the OpenSSL representation of the key (lazy-initialised)
	EVP_PKEY* getOSSLKey();

private:
	EVP_PKEY* pkey;
	void createOSSLKey();
};

#endif // !_SOFTHSM_V2_OSSLSLHDSAPRIVATEKEY_H
