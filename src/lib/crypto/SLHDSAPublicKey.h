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
 SLHDSAPublicKey.h

 SLH-DSA (FIPS 205) public key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SLHDSAPUBLICKEY_H
#define _SOFTHSM_V2_SLHDSAPUBLICKEY_H

#include "config.h"
#include "PublicKey.h"
#include "../pkcs11/pkcs11t.h"

// SLH-DSA public key sizes by parameter set (bytes):
//   128s/128f: pub=32, 192s/192f: pub=48, 256s/256f: pub=64
// SLH-DSA signature sizes by parameter set (bytes):
//   SHA2-128s/SHAKE-128s: 7856, SHA2-128f/SHAKE-128f: 17088
//   SHA2-192s/SHAKE-192s: 16224, SHA2-192f/SHAKE-192f: 35664
//   SHA2-256s/SHAKE-256s: 29792, SHA2-256f/SHAKE-256f: 49856

class SLHDSAPublicKey : public PublicKey
{
public:
	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* inType);

	// Get the bit length (security strength in bits)
	virtual unsigned long getBitLength() const;

	// Get the output length (maximum signature length in bytes)
	virtual unsigned long getOutputLength() const;

	// Setters
	virtual void setParameterSet(CK_ULONG inParamSet);
	virtual void setValue(const ByteString& inValue);

	// Getters
	virtual CK_ULONG getParameterSet() const;
	virtual const ByteString& getValue() const;

	// Serialisation
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

protected:
	CK_ULONG parameterSet;   // CKP_SLH_DSA_SHA2_128S … CKP_SLH_DSA_SHAKE_256F
	ByteString value;        // Raw public key bytes (FIPS 205 encoding)
};

#endif // !_SOFTHSM_V2_SLHDSAPUBLICKEY_H
