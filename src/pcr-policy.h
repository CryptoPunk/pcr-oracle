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

#ifndef PCR_POLICY_H
#define PCR_POLICY_H

#include <tss2_esys.h>
#include <tss2_mu.h>
#include "types.h"

struct target_platform {
  const char *name;
  unsigned int unseal_flags;

  bool (*write_sealed_secret)(const char *pathname,
                              const TPML_PCR_SELECTION *pcr_sel,
                              const TPM2B_PRIVATE *sealed_private,
                              const TPM2B_PUBLIC *sealed_public);
  bool (*write_signed_policy)(const char *input_path, const char *output_path,
                              const char *policy_name,
                              const tpm_pcr_bank_t *bank,
                              const TPM2B_DIGEST *pcr_policy,
                              const tpm_key_t *signing_key,
                              const TPMT_SIGNATURE *signed_policy);
  bool (*unseal_secret)(const char *input_path, const char *output_path,
                        const tpm_pcr_selection_t *pcr_selection,
                        const char *signed_policy_path,
                        const stored_key_t *public_key_file);
};

extern TPM2B_PUBLIC RSA_SRK_template;
extern TPM2B_PUBLIC ECC_SRK_template;
extern const TPM2B_PUBLIC seal_public_template;

extern void set_srk_alg(const char *alg);
extern void set_srk_rsa_bits(const unsigned int rsa_bits);

#endif /* PCR_POLICY_H */
