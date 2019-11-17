/* ====================================================================
 * Copyright (c) 2016 The GmSSL Project.  All rights reserved.
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

#include <string.h>
#include <openssl/err.h>
#include <openssl/smx.h>
#include <openssl/crypto.h>
#include "../bn/bn_lcl.h"
#include "smx_lcl.h"

#if 0
typedef struct {
	int nid;
	int nid;
} smx_algor_table;


static const smx_algor_table smxencrypt_scheme_table[] = {
	{NID_smxencrypt_with_sm3, NID_sm3},
	{NID_smxencrypt_with_sha256, NID_sha256},
};

static const smx_algoro_table smxsign_scheme_table[] = {
	{NID_smxsign_with_sm3, NID_sm3},
	{NID_smxsign_with_sha256, NID_sha256},
};

static const smx_algor_table smx_encrypt_table[] = {
	{smxencrypt-with-sm3-xor, NID_sm3, NID_undef},
	{smxencrypt-with-sm3-sms4-cbc, NID_sm3, NID_sms4_cbc},
	{smxencrypt-with-sm3-sms4-ctr, NID_sm3, NID_sms4_ctr},
};

static const smx_algor smx_hash1[] = {
	{NID_sm9hash1_with_sm3, NID_sm3},
	{NID_sm9hash1_with_sha256, NID_sha256},
	{NID_sm9kdf_with_sm3, NID_sm3},
	{NID_sm9kdf_with_sha256, NID_sha256},
};
#endif


SMX_MASTER_KEY *SMX_MASTER_KEY_new(void)
{
	SMX_MASTER_KEY *ret = NULL;

	if (!(ret = OPENSSL_zalloc(sizeof(*ret)))) {
		SM9err(SMX_F_SMX_MASTER_KEY_NEW, ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	return ret;
}

void SMX_MASTER_KEY_free(SMX_MASTER_KEY *key)
{
	if (key) {
		ASN1_OBJECT_free(key->pairing);
		ASN1_OBJECT_free(key->scheme);
		ASN1_OBJECT_free(key->hash1);
		ASN1_OCTET_STRING_free(key->pointPpub1);
		ASN1_OCTET_STRING_free(key->pointPpub2);
		BN_clear_free(key->masterSecret);
	}
	OPENSSL_clear_free(key, sizeof(*key));
}

SMX_KEY *SMX_KEY_new(void)
{
	SMX_KEY *ret = NULL;

	if (!(ret = OPENSSL_zalloc(sizeof(*ret)))) {
		SM9err(SMX_F_SMX_KEY_NEW, ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	return ret;
}

void SMX_KEY_free(SMX_KEY *key)
{
	if (key) {
		ASN1_OBJECT_free(key->pairing);
		ASN1_OBJECT_free(key->scheme);
		ASN1_OBJECT_free(key->hash1);
		ASN1_OCTET_STRING_free(key->pointPpub1);
		ASN1_OCTET_STRING_free(key->pointPpub2);
		ASN1_OCTET_STRING_free(key->identity);
		ASN1_OCTET_STRING_free(key->publicPoint);
	}
	OPENSSL_clear_free(key, sizeof(*key));
}


int SMXPrivateKey_get_gmtls_public_key(SMXPublicParameters *mpk,
	SMXPrivateKey *sk, unsigned char pub_key[1024])
{
	return 0;
}

int SMXPublicKey_get_gmtls_encoded(SMXPublicParameters *mpk,
	SMXPublicKey *pk, unsigned char encoded[1024])
{
	return 0;
}


int SMX_DigestInit(EVP_MD_CTX *ctx, unsigned char prefix,
	const EVP_MD *md, ENGINE *impl)
{
	if (!EVP_DigestInit_ex(ctx, md, impl)
		|| !EVP_DigestUpdate(ctx, &prefix, 1)) {
		ERR_print_errors_fp(stderr);
		return 0;
	}
	return 1;
}

int SMX_MASTER_KEY_up_ref(SMX_MASTER_KEY *msk)
{
	int i;

	if (CRYPTO_atomic_add(&msk->references, 1,  &i, msk->lock) <= 0)
		return 0;

	REF_PRINT_COUNT("SMX_MASTER_KEY", msk);
	REF_ASSERT_ISNT(i < 2);
	return ((i > 1) ? 1 : 0);
}

int SMX_KEY_up_ref(SMX_KEY *sk)
{
	int i;

	if (CRYPTO_atomic_add(&sk->references, 1,  &i, sk->lock) <= 0)
		return 0;

	REF_PRINT_COUNT("SMX_KEY", sk);
	REF_ASSERT_ISNT(i < 2);
	return ((i > 1) ? 1 : 0);
}

int smx_check_pairing(int nid)
{
	return 1;
}

int smx_check_scheme(int nid)
{
	return 1;
}

int smx_check_hash1(int nid)
{
	return 1;
}

int smx_check_encrypt_scheme(int nid)
{
	return 1;
}

int smx_check_sign_scheme(int nid)
{
	return 1;
}

/* SMX_hash2() should be implemented as an EVP_MD module
 * and refactor the SMX_SignInit/Update/Final API
 */
#if 0
int BN_hash_to_range(const EVP_MD *md, BIGNUM **bn,
	const void *s, size_t slen, const BIGNUM *range, BN_CTX *bn_ctx)
{
	int ret = 0;
	BIGNUM *r = NULL;
	BIGNUM *a = NULL;
	unsigned char *buf = NULL;
	size_t buflen, mdlen;
	int nbytes, rounds, i;

	if (!s || slen <= 0 || !md || !range) {
		//BNerr(BN_F_BN_HASH_TO_RANGE, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!(*bn)) {
		if (!(r = BN_new())) {
			//BNerr(BN_F_BN_HASH_TO_RANGE, ERR_R_MALLOC_FAILURE);
			return 0;
		}
	} else {
		r = *bn;
		BN_zero(r);
	}

	mdlen = EVP_MD_size(md);
	buflen = mdlen + slen;
	if (!(buf = OPENSSL_malloc(buflen))) {
		//BNerr(BN_F_BN_HASH_TO_RANGE, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	memset(buf, 0, mdlen);
	memcpy(buf + mdlen, s, slen);

	a = BN_new();
	if (!a) {
		//BNerr(BN_F_BN_HASH_TO_RANGE, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	nbytes = BN_num_bytes(range);
	rounds = (nbytes + mdlen - 1)/mdlen;

	if (!bn_expand(r, rounds * mdlen * 8)) {
		//BNerr(BN_F_BN_HASH_TO_RANGE, ERR_R_BN_LIB);
		goto end;
	}

	for (i = 0; i < rounds; i++) {
		if (!EVP_Digest(buf, buflen, buf, (unsigned int *)&mdlen, md, NULL)) {
			//BNerr(BN_F_BN_HASH_TO_RANGE, ERR_R_EVP_LIB);
			goto end;
		}
		if (!BN_bin2bn(buf, mdlen, a)) {
			//BNerr(BN_F_BN_HASH_TO_RANGE, ERR_R_BN_LIB);
			goto end;
		}
		if (!BN_lshift(r, r, mdlen * 8)) {
			//BNerr(BN_F_BN_HASH_TO_RANGE, ERR_R_BN_LIB);
			goto end;
		}
		if (!BN_uadd(r, r, a)) {
			goto end;
		}
	}

	if (!BN_mod(r, r, range, bn_ctx)) {
		//BNerr(BN_F_BN_HASH_TO_RANGE, ERR_R_BN_LIB);
		goto end;
	}

	*bn = r;
	ret = 1;
end:
	if (!ret && !(*bn)) {
		BN_free(r);
	}
	BN_free(a);
	OPENSSL_free(buf);
	return ret;
}

int SMX_hash2(const EVP_MD *md, BIGNUM **r,
	const unsigned char *data, size_t datalen,
	const unsigned char *elem, size_t elemlen,
	const BIGNUM *range, BN_CTX *ctx)
{
	EVP_MD_CTX *mctx = NULL;

	if (!(mctx = EVP_MD_CTX_new())) {
	}

	if (!EVP_DigestInit_ex(mctx, md, NULL)
		|| !EVP_DigestUpdate(mctx, data, datalen)
		|| !EVP_DigestUpdate(mctx, elem, elemlen)
		|| !EVP_DigestFinal_ex(mctx, buf, &buflen)) {
	}

	

}

#endif
