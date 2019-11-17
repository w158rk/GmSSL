/* ====================================================================
 * Copyright (c) 2015 - 2018 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <stdio.h>
#include <openssl/smx.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include "internal/cryptlib.h"
#include "internal/asn1_int.h"
#include "internal/evp_int.h"
#include "smx_lcl.h"

typedef struct {
	int pairing; /* NID_sm9bn256v1 */
	int scheme; /* NID_smx[sign|encrypt|keyagreement] */
	int hash1; /* NID_smxhash1_with_[sm3|sha256] */
	int sign_scheme; /* NID_smxsign_with_[sm3|sha256] */
	int encrypt_scheme; /*NID_sm9encrypt */
	char *id;
} SMX_MASTER_PKEY_CTX;

static int pkey_smx_master_init(EVP_PKEY_CTX *ctx)
{
	SMX_MASTER_PKEY_CTX *dctx;
	if (!(dctx = OPENSSL_zalloc(sizeof(*dctx)))) {
		SM9err(SMX_F_PKEY_SMX_MASTER_INIT, ERR_R_MALLOC_FAILURE);
		return 0;
	}

	dctx->pairing = NID_sm9bn256v1;
	dctx->scheme = NID_sm9encrypt;
	dctx->hash1 = NID_sm9hash1_with_sm3;
	dctx->sign_scheme = NID_sm3;
	dctx->encrypt_scheme = NID_sm9encrypt_with_sm3_xor;
	dctx->id = NULL;

	ctx->data = dctx;
	return 1;
}

static int pkey_smx_master_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
	SMX_MASTER_PKEY_CTX *dctx, *sctx;
	if (!pkey_smx_master_init(dst))
		return 0;
	sctx = src->data;
	dctx = dst->data;
	*dctx = *sctx;
	if (!(dctx->id = OPENSSL_strdup(sctx->id))) {
		SM9err(SMX_F_PKEY_SMX_MASTER_COPY, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	return 1;
}

static void pkey_smx_master_cleanup(EVP_PKEY_CTX *ctx)
{
	SMX_MASTER_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
	if (dctx) {
		OPENSSL_free(dctx->id);
		OPENSSL_free(dctx);
	}
}

static int pkey_smx_master_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
	SMX_MASTER_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
	SMX_MASTER_KEY *smx_master;

	if (!(smx_master = SMX_generate_master_secret(dctx->pairing,
		dctx->scheme, dctx->hash1))) {
		SM9err(SMX_F_PKEY_SMX_MASTER_KEYGEN, ERR_R_SM9_LIB);
		return 0;
	}
	if (!EVP_PKEY_assign_SM9_MASTER(pkey, smx_master)) {
		SM9err(SMX_F_PKEY_SMX_MASTER_KEYGEN, ERR_R_EVP_LIB);
		SMX_MASTER_KEY_free(smx_master);
		return 0;
	}
	return 1;
}

static int pkey_smx_master_verify(EVP_PKEY_CTX *ctx,
	const unsigned char *sig, size_t siglen,
	const unsigned char *tbs, size_t tbslen)
{
	int ret;
	SMX_MASTER_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
	SMX_MASTER_KEY *smx_master = EVP_PKEY_get0_SM9_MASTER(
		EVP_PKEY_CTX_get0_pkey(ctx));

	if (OBJ_obj2nid(smx_master->scheme) != NID_sm9sign) {
		SM9err(SMX_F_PKEY_SMX_MASTER_VERIFY, SMX_R_INVALID_KEY_USAGE);
		return 0;
	}
	if (!dctx->id) {
		SM9err(SMX_F_PKEY_SMX_MASTER_VERIFY, SMX_R_SIGNER_ID_REQUIRED);
		return 0;
	}

	if ((ret = SMX_verify(dctx->sign_scheme, tbs, tbslen, sig, siglen,
		smx_master, dctx->id, strlen(dctx->id))) < 0) {
		SM9err(SMX_F_PKEY_SMX_MASTER_VERIFY, ERR_R_SM9_LIB);
	}
	return ret;
}

static int pkey_smx_master_encrypt(EVP_PKEY_CTX *ctx,
	unsigned char *out, size_t *outlen,
	const unsigned char *in, size_t inlen)
{
	SMX_MASTER_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
	SMX_MASTER_KEY *smx_master = EVP_PKEY_get0_SM9_MASTER(
		EVP_PKEY_CTX_get0_pkey(ctx));

	if (OBJ_obj2nid(smx_master->scheme) != NID_sm9encrypt) {
		SM9err(SMX_F_PKEY_SMX_MASTER_ENCRYPT, SMX_R_INVALID_KEY_USAGE);
		return 0;
	}

	if (!dctx->id) {
		SM9err(SMX_F_PKEY_SMX_MASTER_ENCRYPT, SMX_R_IDENTITY_REQUIRED);
		return 0;
	}

	if (!SMX_encrypt(dctx->encrypt_scheme, in, inlen, out, outlen,
		smx_master, dctx->id, strlen(dctx->id))) {
		SM9err(SMX_F_PKEY_SMX_MASTER_ENCRYPT, ERR_R_SM9_LIB);
		return 0;
	}

	return 1;
}

static int pkey_smx_master_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)
{
	/*
	SMX_MASTER_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
	SMX_MASTER_KEY *smx_master = EVP_PKEY_get0_SM9_MASTER(
		EVP_PKEY_CTX_get0_pkey(ctx));
	*/

	return -2;
}

static int pkey_smx_master_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
	SMX_MASTER_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);

	switch (type) {
	case EVP_PKEY_CTRL_SMX_PAIRING:
		if (p1 == -2)
			return dctx->pairing;
		if (!smx_check_pairing(p1)) {
		}
		dctx->pairing = p1;
		return 1;

	case EVP_PKEY_CTRL_SMX_SCHEME:
		if (p1 == -2)
			return dctx->scheme;
		if (!smx_check_scheme(p1)) {
			SM9err(SMX_F_PKEY_SMX_MASTER_CTRL, SMX_R_INVALID_SCHEME);
			return 0;
		}
		dctx->scheme = p1;
		return 1;

	case EVP_PKEY_CTRL_SMX_HASH1:
		if (p1 == -2)
			return dctx->hash1;
		if (!smx_check_hash1(p1)) {
			SM9err(SMX_F_PKEY_SMX_MASTER_CTRL, SMX_R_INVALID_HASH1);
			return 0;
		}
		dctx->hash1 = p1;
		return 1;

	case EVP_PKEY_CTRL_SMX_ID:
		if (!p2 || !strlen((char *)p2) || strlen((char *)p2) > SMX_MAX_ID_LENGTH) {
			SM9err(SMX_F_PKEY_SMX_MASTER_CTRL, SMX_R_INVALID_ID);
			return 0;
		} else {
			char *id = NULL;
			if (!(id = OPENSSL_strdup((char *)p2))) {
				SM9err(SMX_F_PKEY_SMX_MASTER_CTRL, ERR_R_MALLOC_FAILURE);
			}
			if (dctx->id) {
				OPENSSL_free(dctx->id);
			}
			dctx->id = id;
		}
		return 1;

	case EVP_PKEY_CTRL_GET_SMX_ID:
		*(const char **)p2 = dctx->id;
		return 1;
	}

	return -2;
}

static int pkey_smx_master_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value)
{
	if (!strcmp(type, "pairing")) {
		int nid = OBJ_txt2nid(value);
		if (!smx_check_pairing(nid)) {
			SM9err(SMX_F_PKEY_SMX_MASTER_CTRL_STR, SMX_R_INVALID_PAIRING);
			return 0;
		}
		return EVP_PKEY_CTX_set_sm9_pairing(ctx, nid);

	} else if (!strcmp(type, "scheme")) {
		int nid = OBJ_txt2nid(value);
		if (!smx_check_scheme(nid)) {
			SM9err(SMX_F_PKEY_SMX_MASTER_CTRL_STR, SMX_R_INVALID_SMX_SCHEME);
			return 0;
		}
		return EVP_PKEY_CTX_set_sm9_scheme(ctx, nid);

	} else if (!strcmp(type, "hash1")) {
		int nid = OBJ_txt2nid(value);
		if (!smx_check_hash1(nid)) {
			SM9err(SMX_F_PKEY_SMX_MASTER_CTRL_STR, SMX_R_INVALID_SMX_SCHEME);
			return 0;
		}
		return EVP_PKEY_CTX_set_sm9_hash1(ctx, nid);

	} else if (!strcmp(type, "id")) {
		return EVP_PKEY_CTX_set_sm9_id(ctx, value);
	}

	return -2;
}

const EVP_PKEY_METHOD smx_master_pkey_meth = {
	EVP_PKEY_SM9_MASTER,		/* pkey_id */
	0,				/* flags */
	pkey_smx_master_init,		/* init */
	pkey_smx_master_copy,		/* copy */
	pkey_smx_master_cleanup,	/* cleanup */
	NULL,				/* paramgen_init */
	NULL,				/* paramgen */
	NULL,				/* keygen_init */
	pkey_smx_master_keygen,		/* keygen */
	NULL,				/* sign_init */
	NULL,				/* sign */
	NULL,				/* verify_init */
	pkey_smx_master_verify,		/* verify */
	NULL,				/* verify_recover_init */
	NULL,				/* verify_recover */
	NULL,				/* signctx_init */
	NULL,				/* signctx */
	NULL,				/* verifyctx_init */
	NULL,				/* verifyctx */
	NULL,				/* encrypt_init */
	pkey_smx_master_encrypt,	/* encrypt */
	NULL,				/* decrypt_init */
	NULL,				/* decrypt */
	NULL,				/* derive_init */
	pkey_smx_master_derive,		/* derive */
	pkey_smx_master_ctrl,		/* ctrl */
	pkey_smx_master_ctrl_str,	/* ctrl_str */
};

typedef struct {
	int sign_scheme;
	int encrypt_scheme;
	char *id;
} SMX_PKEY_CTX;

static int pkey_smx_init(EVP_PKEY_CTX *ctx)
{
	SMX_PKEY_CTX *dctx;
	if (!(dctx = OPENSSL_zalloc(sizeof(*dctx)))) {
		SM9err(SMX_F_PKEY_SMX_INIT, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	dctx->sign_scheme = NID_sm3; // FIXME: some like NID_smxsign_sm3 			
	dctx->encrypt_scheme = NID_sm9encrypt_with_sm3_xor;
	dctx->id = NULL;
	OPENSSL_assert(EVP_PKEY_CTX_get_data(ctx) == NULL);
	(void)EVP_PKEY_CTX_set_data(ctx, dctx);
	return 1;
}

static int pkey_smx_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
	SMX_PKEY_CTX *dctx, *sctx;
	if (!pkey_smx_init(dst)) {
		SM9err(SMX_F_PKEY_SMX_COPY, ERR_R_SM9_LIB);
		return 0;
	}
	sctx = EVP_PKEY_CTX_get_data(src);
	dctx = EVP_PKEY_CTX_get_data(dst);
	*dctx = *sctx;
	if (!(dctx->id = OPENSSL_strdup(sctx->id))) {
		return 0;
	}
	return 1;
}

static void pkey_smx_cleanup(EVP_PKEY_CTX *ctx)
{
	SMX_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
	if (dctx) {
		OPENSSL_free(dctx->id);
		OPENSSL_free(dctx);
	}
}

static int pkey_smx_sign(EVP_PKEY_CTX *ctx,
	unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen)
{
	SMX_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
	SMX_KEY *smx = EVP_PKEY_get0_SM9(EVP_PKEY_CTX_get0_pkey(ctx));
	if (!SMX_sign(dctx->sign_scheme, tbs, tbslen, sig, siglen, smx)) {
		SM9err(SMX_F_PKEY_SMX_SIGN, ERR_R_SM9_LIB);
		return 0;
	}
	return 1;
}

static int pkey_smx_decrypt(EVP_PKEY_CTX *ctx,
	unsigned char *out, size_t *outlen,
	const unsigned char *in, size_t inlen)
{
	SMX_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
	SMX_KEY *smx = EVP_PKEY_get0_SM9(EVP_PKEY_CTX_get0_pkey(ctx));
	if (!SMX_decrypt(dctx->encrypt_scheme, in, inlen,
		out, outlen, smx)) {
		SM9err(SMX_F_PKEY_SMX_DECRYPT, ERR_R_SM9_LIB);
		return 0;
	}
	return 1;
}

static int pkey_smx_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)
{
	return -2;
}

static int pkey_smx_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
	SMX_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);

	switch (type) {
	case EVP_PKEY_CTRL_SMX_SIGN_SCHEME:
		if (p1 == -2)
			return dctx->sign_scheme;
		if (!smx_check_sign_scheme(p1)) {
			SM9err(SMX_F_PKEY_SMX_CTRL, SMX_R_INVALID_SIGN_SCHEME);
			return 0;
		}
		dctx->sign_scheme = p1;
		return 1;

	case EVP_PKEY_CTRL_SMX_ENCRYPT_SCHEME:
		if (p1 == -2)
			return dctx->encrypt_scheme;
		if (!smx_check_encrypt_scheme(p1)) {
			SM9err(SMX_F_PKEY_SMX_CTRL, SMX_R_INVALID_ENCRYPT_SCHEME);
			return 0;
		}
		dctx->encrypt_scheme = p1;
		return 1;

	case EVP_PKEY_CTRL_SMX_ID:
		if (!p2 || !strlen((char *)p2) || strlen((char *)p2) > SMX_MAX_ID_LENGTH) {
			return 0;
		} else {
		}
		return 1;

	case EVP_PKEY_CTRL_GET_SMX_ID:
		*(const char **)p2 = dctx->id;
		return 1;

	default:
		return -2;
	}

	return -2;
}

static int pkey_smx_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value)
{
	if (!strcmp(type, "sign_scheme")) {
		int nid = OBJ_txt2nid(value);
		if (!smx_check_sign_scheme(nid)) {
			SM9err(SMX_F_PKEY_SMX_CTRL_STR, SMX_R_INVALID_SIGN_MD);
			return 0;
		}
		return EVP_PKEY_CTX_set_sm9_sign_scheme(ctx, nid);

	} else if (!strcmp(type, "encrypt_scheme")) {
		int nid = OBJ_txt2nid(value);
		if (!smx_check_encrypt_scheme(nid)) {
			SM9err(SMX_F_PKEY_SMX_CTRL_STR, SMX_R_INVALID_ENCRYPT_SCHEME);
			return 0;
		}
		return EVP_PKEY_CTX_set_smx_encrypt_scheme(ctx, nid);

	} else if (!strcmp(type, "id")) {
		return EVP_PKEY_CTX_set_sm9_id(ctx, value);
	}

	return -2;
}

/* TODO: currently data instead of dgst is signed.
 * we need to support to ctrl which to sign.
 */
const EVP_PKEY_METHOD smx_pkey_meth = {
	EVP_PKEY_SM9,		/* pkey_id */
	0,			/* flags */
	pkey_smx_init,		/* init */
	pkey_smx_copy,		/* copy */
	pkey_smx_cleanup,	/* cleanup */
	NULL,			/* paramgen_init */
	NULL,			/* paramgen */
	NULL,			/* keygen_init */
	NULL,			/* keygen */
	NULL,			/* sign_init */
	pkey_smx_sign,		/* sign */
	NULL, 			/* verify_init */
	NULL,			/* verify */
	NULL,			/* verify_recover_init */
	NULL,			/* verify_recover */
	NULL,			/* signctx_init */
	NULL,			/* signctx */
	NULL,			/* verifyctx_init */
	NULL,			/* verifyctx */
	NULL,			/* encrypt_init */
	NULL,			/* encrypt */
	NULL,			/* decrypt_init */
	pkey_smx_decrypt,	/* decrypt */
	NULL,			/* derive_init */
	pkey_smx_derive,	/* derive */
	pkey_smx_ctrl,		/* ctrl */
	pkey_smx_ctrl_str,	/* ctrl_str */
};
