/*
 *   Copyright (C) 2022, 2023 SUSE LLC
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Written by Olaf Kirch <okir@suse.com>
 */

#include "pcr-policy.h"

TPM2B_PUBLIC RSA_SRK_template = {
    .size = sizeof(TPMT_PUBLIC),
    .publicArea = {
        .type = TPM2_ALG_RSA,
        .nameAlg = TPM2_ALG_SHA256,
        /* Per "Storage Primary Key (SRK) Templates" in section 7.5.1 of
         * TCG TPM v2.0 Provisioning Guidance 1.0 Revision 1.0, the
         * template for shared SRKs sets USERWITHAUTH and NODA. */
        .objectAttributes = TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT |
                            TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                            TPMA_OBJECT_SENSITIVEDATAORIGIN |
                            TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_NODA,
        .parameters = {.rsaDetail = {.symmetric =
                                         {
                                             .algorithm = TPM2_ALG_AES,
                                             .keyBits = {.sym = 128},
                                             .mode = {.sym = TPM2_ALG_CFB},
                                         },
                                     .scheme = {TPM2_ALG_NULL},
                                     .keyBits = 2048}}}};

TPM2B_PUBLIC ECC_SRK_template = {
    .size = sizeof(TPMT_PUBLIC),
    .publicArea = {
        .type = TPM2_ALG_ECC,
        .nameAlg = TPM2_ALG_SHA256,
        /* Per "Storage Primary Key (SRK) Templates" in section 7.5.1 of
         * TCG TPM v2.0 Provisioning Guidance 1.0 Revision 1.0, the
         * template for shared SRKs sets USERWITHAUTH and NODA. */
        .objectAttributes = TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT |
                            TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                            TPMA_OBJECT_SENSITIVEDATAORIGIN |
                            TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_NODA,
        .parameters = {.eccDetail = {.symmetric =
                                         {
                                             .algorithm = TPM2_ALG_AES,
                                             .keyBits = {.sym = 128},
                                             .mode = {.sym = TPM2_ALG_CFB},
                                         },
                                     .scheme = {TPM2_ALG_NULL},
                                     .curveID = TPM2_ECC_NIST_P256,
                                     .kdf.scheme = TPM2_ALG_NULL}}}};

const TPM2B_PUBLIC seal_public_template = {
    .size = sizeof(TPMT_PUBLIC),
    .publicArea = {.type = TPM2_ALG_KEYEDHASH,
                   .nameAlg = TPM2_ALG_SHA256,
                   .objectAttributes =
                       TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT,
                   .parameters = {.keyedHashDetail =
                                      {
                                          .scheme = {TPM2_ALG_NULL},
                                      }},
                   .unique = {.keyedHash = {.size = 32}}}};
