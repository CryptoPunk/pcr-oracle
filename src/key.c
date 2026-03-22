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

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h> /* for umask */

#include <openssl/pem.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <tss2_esys.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#endif

#include "util.h"
#include "key.h"
#include "digest.h"

struct tpm_key {
	bool		is_private;
	char *		path;
	EVP_PKEY *	pkey;
};

static tpm_key_t *
tpm_key_alloc(const char *path, EVP_PKEY *pkey, bool priv)
{
	tpm_key_t *key = calloc(1, sizeof(*key));
	key->is_private = priv;
	key->pkey = pkey;
	key->path = strdup(path);
	return key;
}

void
tpm_key_free(tpm_key_t *key)
{
	drop_string(&key->path);
	if (key->pkey) {
		EVP_PKEY_free(key->pkey);
		key->pkey = NULL;
	}
	free(key);
}

tpm_key_t *
tpm_key_read_public(const char *pathname)
{
	EVP_PKEY *pkey = NULL;
	FILE *fp;

	if (!(fp = fopen(pathname, "r"))) {
		error("Cannot read public key from %s: %m\n", pathname);
		goto fail;
	}
	pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
	fclose(fp);

	if (pkey == NULL) {
		error("Failed to parse public key from %s\n", pathname);
		goto fail;
	}

	if (EVP_PKEY_id(pkey) != EVP_PKEY_RSA && EVP_PKEY_id(pkey) != EVP_PKEY_EC) {
		error("Unsupported public key type: %s\n", pathname);
		goto fail;
	}

	return tpm_key_alloc(pathname, pkey, false);

fail:
	if (pkey)
		EVP_PKEY_free(pkey);
	return NULL;
}

bool
tpm_key_write_private(const char *pathname, const tpm_key_t *key)
{
	bool ok = false;
	mode_t omask;
	FILE *fp;

	omask = umask(077);

	if (!(fp = fopen(pathname, "w"))) {
		error("Cannot open private key file %s: %m\n", pathname);
		goto fail;
	}

	if (!PEM_write_PrivateKey(fp, key->pkey, NULL, NULL, 0, 0, NULL)) {
		error("Unable to write private key to %s\n", pathname);
		goto fail;
	}

	ok = true;

fail:
	umask(omask);
	if (fp) fclose(fp);
	return ok;
}

bool
tpm_key_write_public(const char *pathname, const tpm_key_t *key)
{
	bool ok = false;
	FILE *fp;

	if (!(fp = fopen(pathname, "w"))) {
		error("Cannot open public key file %s: %m\n", pathname);
		goto fail;
	}

	if (!PEM_write_PUBKEY(fp, key->pkey)) {
		error("Unable to write public key to %s\n", pathname);
		goto fail;
	}

	ok = true;

fail:
	if (fp) fclose(fp);
	return ok;
}

tpm_key_t *
tpm_key_read_private(const char *pathname)
{
	EVP_PKEY *pkey = NULL;
	FILE *fp;

	if (!(fp = fopen(pathname, "r"))) {
		error("Cannot read private key from %s: %m\n", pathname);
		goto fail;
	}
	pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);

	if (pkey == NULL) {
		error("Failed to parse private key from %s\n", pathname);
		goto fail;
	}

	if (EVP_PKEY_id(pkey) != EVP_PKEY_RSA && EVP_PKEY_id(pkey) != EVP_PKEY_EC) {
		error("Unsupported private key type: %s\n", pathname);
		goto fail;
	}

	return tpm_key_alloc(pathname, pkey, true);

fail:
	if (pkey)
		EVP_PKEY_free(pkey);
	return NULL;
}

tpm_key_t *
tpm_key_generate(const char *algorithm, unsigned int bits)
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	int algo = EVP_PKEY_RSA;

	if (algorithm && strcasecmp(algorithm, "ecc") == 0)
		algo = EVP_PKEY_EC;

	ctx = EVP_PKEY_CTX_new_id(algo, NULL);
	if (!ctx)
		goto failed;

	if (EVP_PKEY_keygen_init(ctx) <= 0)
		goto failed;

	if (algo == EVP_PKEY_RSA) {
		if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
			goto failed;
	} else if (algo == EVP_PKEY_EC) {
		if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0)
			goto failed;
	}

	if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
		goto failed;

	EVP_PKEY_CTX_free(ctx);

	return tpm_key_alloc("<generated>", pkey, true);

failed:
	error("Failed to generate %s key\n", algorithm ? algorithm : "rsa");
	if (pkey)
		EVP_PKEY_free(pkey);
	if (ctx)
		EVP_PKEY_CTX_free(ctx);
	return NULL;
}

bool
tpm_key_sign(const tpm_key_t *key,
			const void *tbs_data, size_t tbs_len,
			TPMT_SIGNATURE *sig)
{
	EVP_MD_CTX *ctx;
	unsigned char sig_buf[1024];
	size_t sig_len = sizeof(sig_buf);

	if (!key->is_private) {
		error("Cannot use %s for signing - not a private key\n", key->path);
		return false;
	}

	ctx = EVP_MD_CTX_new();

	if (!EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key->pkey)) {
		error("EVP_DigestSignInit failed\n");
		EVP_MD_CTX_free(ctx);
		return false;
	}

	if (!EVP_DigestSign(ctx, sig_buf, &sig_len, (const unsigned char *) tbs_data, tbs_len)) {
		error("EVP_DigestSign failed\n");
		EVP_MD_CTX_free(ctx);
		return false;
	}

	EVP_MD_CTX_free(ctx);

	if (EVP_PKEY_id(key->pkey) == EVP_PKEY_RSA) {
		sig->signature.rsassa.sig.size = sig_len;
		memcpy(sig->signature.rsassa.sig.buffer, sig_buf, sig_len);
		return true;
	} else if (EVP_PKEY_id(key->pkey) == EVP_PKEY_EC) {
		const unsigned char *p = sig_buf;
		ECDSA_SIG *ecdsa_sig = d2i_ECDSA_SIG(NULL, &p, sig_len);
		if (!ecdsa_sig) {
			error("Failed to decode ECDSA signature\n");
			return false;
		}

		const BIGNUM *r, *s;
		ECDSA_SIG_get0(ecdsa_sig, &r, &s);

		sig->signature.ecdsa.signatureR.size = BN_num_bytes(r);
		BN_bn2bin(r, sig->signature.ecdsa.signatureR.buffer);

		sig->signature.ecdsa.signatureS.size = BN_num_bytes(s);
		BN_bn2bin(s, sig->signature.ecdsa.signatureS.buffer);

		ECDSA_SIG_free(ecdsa_sig);
		return true;
	}

	return false;
}

static inline TPM2B_PUBLIC *
__rsa_pubkey_alloc(void)
{
	TPM2B_PUBLIC *result;

	result = calloc(1, sizeof(*result));
	result->size = sizeof(result->publicArea);
	result->publicArea.type = TPM2_ALG_RSA;
	result->publicArea.nameAlg = TPM2_ALG_SHA256;
	result->publicArea.objectAttributes = TPMA_OBJECT_DECRYPT | TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_USERWITHAUTH;

	TPMS_RSA_PARMS *rsaDetail = &result->publicArea.parameters.rsaDetail;
	rsaDetail->scheme.scheme = TPM2_ALG_NULL;
	rsaDetail->symmetric.algorithm = TPM2_ALG_NULL;
	rsaDetail->scheme.details.anySig.hashAlg = TPM2_ALG_NULL;

	TPMT_SYM_DEF_OBJECT *sym = &rsaDetail->symmetric;
	sym->algorithm = TPM2_ALG_NULL;
	sym->keyBits.sym = 0;
	sym->mode.sym = TPM2_ALG_NULL;

	return result;
}

static inline TPM2B_PUBLIC *
rsa_pubkey_alloc(const BIGNUM *n, const BIGNUM *e, const char *pathname)
{
	TPM2B_PUBLIC *result;
	unsigned int key_bits;

	key_bits = BN_num_bytes(n) * 8;
	if (key_bits != 1024 && key_bits != 2048 && key_bits != 3072 && key_bits != 4096) {
		error("%s: unsupported RSA key size (%u bits)\n", pathname, key_bits);
		return NULL;
	}

	if (BN_num_bytes(e) > sizeof(((TPMS_RSA_PARMS *) 0)->exponent)) {
		error("%s: unsupported RSA modulus size (%u bits)\n", pathname, BN_num_bytes(e) * 8);
		return NULL;
	}

	if (!(result = __rsa_pubkey_alloc()))
		return NULL;

	TPMS_RSA_PARMS *rsaDetail = &result->publicArea.parameters.rsaDetail;
	rsaDetail->keyBits = key_bits;

	TPM2B_PUBLIC_KEY_RSA *rsaPublic = &result->publicArea.unique.rsa;
	rsaPublic->size = BN_num_bytes(n);

	if (!BN_bn2bin(n, rsaPublic->buffer))
		goto failed;

	if (!BN_bn2bin(e, (void *) &rsaDetail->exponent))
		goto failed;

	return result;

failed:
	free(result);
	return NULL;
}

static inline TPM2B_PUBLIC *
ecc_pubkey_alloc(const BIGNUM *x, const BIGNUM *y, const char *pathname)
{
	TPM2B_PUBLIC *result = calloc(1, sizeof(*result));
	result->size = sizeof(result->publicArea);
	result->publicArea.type = TPM2_ALG_ECC;
	result->publicArea.nameAlg = TPM2_ALG_SHA256;
	result->publicArea.objectAttributes = TPMA_OBJECT_DECRYPT | TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_USERWITHAUTH;

	TPMS_ECC_PARMS *eccDetail = &result->publicArea.parameters.eccDetail;
	eccDetail->symmetric.algorithm = TPM2_ALG_NULL;
	eccDetail->scheme.scheme = TPM2_ALG_NULL;
	eccDetail->curveID = TPM2_ECC_NIST_P256;
	eccDetail->kdf.scheme = TPM2_ALG_NULL;

	TPMS_ECC_POINT *eccPublic = &result->publicArea.unique.ecc;
	eccPublic->x.size = BN_num_bytes(x);
	BN_bn2bin(x, eccPublic->x.buffer);
	eccPublic->y.size = BN_num_bytes(y);
	BN_bn2bin(y, eccPublic->y.buffer);

	return result;
}

TPM2B_PUBLIC *
tpm_key_to_tss2(const tpm_key_t *key)
{
	if (EVP_PKEY_id(key->pkey) == EVP_PKEY_RSA) {
#if OPENSSL_VERSION_NUMBER < 0x30000000L
		RSA *rsa;
		const BIGNUM *n, *e;
		if (!(rsa = EVP_PKEY_get0_RSA(key->pkey))) return NULL;
		RSA_get0_key(rsa, &n, &e, NULL);
#else
		BIGNUM *n = NULL, *e = NULL;
		if (!EVP_PKEY_get_bn_param(key->pkey, OSSL_PKEY_PARAM_RSA_N, &n)) return NULL;
		if (!EVP_PKEY_get_bn_param(key->pkey, OSSL_PKEY_PARAM_RSA_E, &e)) return NULL;
#endif
		TPM2B_PUBLIC *res = rsa_pubkey_alloc(n, e, key->path);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		BN_free(n); BN_free(e);
#endif
		return res;
	} else if (EVP_PKEY_id(key->pkey) == EVP_PKEY_EC) {
#if OPENSSL_VERSION_NUMBER < 0x30000000L
		EC_KEY *ec = EVP_PKEY_get0_EC_KEY(key->pkey);
		if (!ec) return NULL;
		const EC_GROUP *group = EC_KEY_get0_group(ec);
		const EC_POINT *pub = EC_KEY_get0_public_key(ec);
		BIGNUM *x = BN_new(), *y = BN_new();
		if (!EC_POINT_get_affine_coordinates_GFp(group, pub, x, y, NULL)) {
			BN_free(x); BN_free(y); return NULL;
		}
		TPM2B_PUBLIC *res = ecc_pubkey_alloc(x, y, key->path);
		BN_free(x); BN_free(y);
		return res;
#else
		BIGNUM *x = NULL, *y = NULL;
		if (!EVP_PKEY_get_bn_param(key->pkey, OSSL_PKEY_PARAM_EC_PUB_X, &x)) return NULL;
		if (!EVP_PKEY_get_bn_param(key->pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &y)) return NULL;
		TPM2B_PUBLIC *res = ecc_pubkey_alloc(x, y, key->path);
		BN_free(x);
		BN_free(y);
		return res;
#endif
	}
	return NULL;
}

const tpm_evdigest_t *
tpm_key_public_digest(const tpm_key_t *pubkey)
{
	unsigned int der_size;
	unsigned char *der, *bder = NULL;
	const tpm_algo_info_t *algo;
	const tpm_evdigest_t *digest = NULL;

	der_size = i2d_PublicKey(pubkey->pkey, NULL);
	if (der_size < 0) {
		error("%s: cannot convert public key into DER format", pubkey->path);
		return NULL;
	}

	der = bder = malloc(der_size);
	der_size = i2d_PublicKey(pubkey->pkey, &der);
	if (der_size < 0) {
		error("%s: cannot convert public key into DER format", pubkey->path);
		goto out;
	}

	algo = digest_by_name("sha256");
	digest = digest_compute(algo, bder, der_size);

 out:
	if (bder)
		free(bder);

	return digest;
}
