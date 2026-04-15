/*
 * Copyright (c) 2026 SoftHSMv3 Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "provider.h"

// TODO: Implement parsing for CKK_SLH_DSA parameter sets and wrap PKCS#11 signing primitives
const OSSL_DISPATCH p11prov_slhdsa_signature_functions[] = {
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_slhdsa_keymgmt_functions[] = {
    { 0, NULL },
};
