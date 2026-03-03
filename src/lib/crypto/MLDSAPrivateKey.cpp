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
#include "MLDSAPrivateKey.h"
#include <string.h>

const char* MLDSAPrivateKey::type = "ML-DSA Private Key";

bool MLDSAPrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

unsigned long MLDSAPrivateKey::getBitLength() const
{
	switch (parameterSet)
	{
		case CKP_ML_DSA_44: return 128;
		case CKP_ML_DSA_65: return 192;
		case CKP_ML_DSA_87: return 256;
		default:            return 0;
	}
}

unsigned long MLDSAPrivateKey::getOutputLength() const
{
	switch (parameterSet)
	{
		case CKP_ML_DSA_44: return 2420;
		case CKP_ML_DSA_65: return 3309;
		case CKP_ML_DSA_87: return 4627;
		default:            return 0;
	}
}

void MLDSAPrivateKey::setParameterSet(CK_ULONG inParamSet)
{
	parameterSet = inParamSet;
}

void MLDSAPrivateKey::setValue(const ByteString& inValue)
{
	value = inValue;
}

CK_ULONG MLDSAPrivateKey::getParameterSet() const
{
	return parameterSet;
}

const ByteString& MLDSAPrivateKey::getValue() const
{
	return value;
}

ByteString MLDSAPrivateKey::serialise() const
{
	ByteString s;
	CK_ULONG ps = parameterSet;
	s += ByteString((unsigned char*)&ps, sizeof(ps));
	s += value.serialise();
	return s;
}

bool MLDSAPrivateKey::deserialise(ByteString& serialised)
{
	if (serialised.size() < sizeof(CK_ULONG)) return false;
	memcpy(&parameterSet, serialised.byte_str(), sizeof(CK_ULONG));
	serialised = serialised.substr(sizeof(CK_ULONG));

	ByteString val = ByteString::chainDeserialise(serialised);
	setValue(val);
	return true;
}
