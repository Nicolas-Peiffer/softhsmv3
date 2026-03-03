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

#include "config.h"
#include "SLHDSAPrivateKey.h"
#include <string.h>

const char* SLHDSAPrivateKey::type = "SLH-DSA Private Key";

bool SLHDSAPrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

unsigned long SLHDSAPrivateKey::getBitLength() const
{
	switch (parameterSet)
	{
		case CKP_SLH_DSA_SHA2_128S:
		case CKP_SLH_DSA_SHAKE_128S:
		case CKP_SLH_DSA_SHA2_128F:
		case CKP_SLH_DSA_SHAKE_128F: return 128;
		case CKP_SLH_DSA_SHA2_192S:
		case CKP_SLH_DSA_SHAKE_192S:
		case CKP_SLH_DSA_SHA2_192F:
		case CKP_SLH_DSA_SHAKE_192F: return 192;
		case CKP_SLH_DSA_SHA2_256S:
		case CKP_SLH_DSA_SHAKE_256S:
		case CKP_SLH_DSA_SHA2_256F:
		case CKP_SLH_DSA_SHAKE_256F: return 256;
		default:                     return 0;
	}
}

unsigned long SLHDSAPrivateKey::getOutputLength() const
{
	switch (parameterSet)
	{
		case CKP_SLH_DSA_SHA2_128S:
		case CKP_SLH_DSA_SHAKE_128S: return 7856;
		case CKP_SLH_DSA_SHA2_128F:
		case CKP_SLH_DSA_SHAKE_128F: return 17088;
		case CKP_SLH_DSA_SHA2_192S:
		case CKP_SLH_DSA_SHAKE_192S: return 16224;
		case CKP_SLH_DSA_SHA2_192F:
		case CKP_SLH_DSA_SHAKE_192F: return 35664;
		case CKP_SLH_DSA_SHA2_256S:
		case CKP_SLH_DSA_SHAKE_256S: return 29792;
		case CKP_SLH_DSA_SHA2_256F:
		case CKP_SLH_DSA_SHAKE_256F: return 49856;
		default:                     return 0;
	}
}

void SLHDSAPrivateKey::setParameterSet(CK_ULONG inParamSet)
{
	parameterSet = inParamSet;
}

void SLHDSAPrivateKey::setValue(const ByteString& inValue)
{
	value = inValue;
}

CK_ULONG SLHDSAPrivateKey::getParameterSet() const
{
	return parameterSet;
}

const ByteString& SLHDSAPrivateKey::getValue() const
{
	return value;
}

ByteString SLHDSAPrivateKey::serialise() const
{
	ByteString s;
	CK_ULONG ps = parameterSet;
	s += ByteString((unsigned char*)&ps, sizeof(ps));
	s += value.serialise();
	return s;
}

bool SLHDSAPrivateKey::deserialise(ByteString& serialised)
{
	if (serialised.size() < sizeof(CK_ULONG)) return false;
	memcpy(&parameterSet, serialised.byte_str(), sizeof(CK_ULONG));
	serialised = serialised.substr(sizeof(CK_ULONG));

	ByteString val = ByteString::chainDeserialise(serialised);
	setValue(val);
	return true;
}
