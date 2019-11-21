/* ====================================================================
 * Copyright (c) 2016 - 2018 The GmSSL Project.  All rights reserved.
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
#include <openssl/ec.h>
#include "smx_lcl.h"


SMXSignature *SMX_do_sign(const unsigned char *dgst, int dgstlen, SMX_KEY *smx)
{
	return NULL;
}

int SMX_do_verify(const unsigned char *dgst, int dgstlen,
	const SMXSignature *sig, SMX_KEY *smx)
{
	return -1;
}

int SMX_SignInit(EVP_MD_CTX *ctx, const EVP_MD *md, ENGINE *eng)
{
	unsigned char prefix[1] = {0x02};

	if (!EVP_DigestInit_ex(ctx, md, eng)) {
		SM9err(SMX_F_SMX_SIGNINIT, ERR_R_EVP_LIB);
		return 0;
	}
	if (!EVP_DigestUpdate(ctx, prefix, sizeof(prefix))) {
		SM9err(SMX_F_SMX_SIGNINIT, ERR_R_EVP_LIB);
		return 0;
	}

	return 1;
}

SMXSignature *SMX_SignFinal(EVP_MD_CTX *ctx1, SMXPrivateKey *sk)
{
	SMXSignature *ret = NULL;
	SMXSignature *sig = NULL;
	const BIGNUM *p = SMX_get0_prime();
	const BIGNUM *n = SMX_get0_order();
	int point_form = POINT_CONVERSION_COMPRESSED;
	/* buf for w and prefix zeros of ct1/2 */
	unsigned char buf[384] = {0};
	unsigned int len;
	const unsigned char ct1[4] = {0x00, 0x00, 0x00, 0x01};
	const unsigned char ct2[4] = {0x00, 0x00, 0x00, 0x02};
	EVP_MD_CTX *ctx2 = NULL;
	EC_GROUP *group = NULL;
	EC_POINT *S = NULL;
	EC_POINT *Q = NULL;
	EC_POINT *Ppub1 = NULL;
	BN_CTX *bn_ctx = NULL;
	BIGNUM *r = NULL;
	point_t Ppub2;
	fp12_t w;

	if (!(sig = SMXSignature_new())
		|| !(ctx2 = EVP_MD_CTX_new())
		|| !(group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1))
		|| !(S = EC_POINT_new(group))
		|| !(Q = EC_POINT_new(group))
		|| !(Ppub1 = EC_POINT_new(group))
		|| !(bn_ctx = BN_CTX_new())) {
		SM9err(SMX_F_SMX_SIGNFINAL, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	BN_CTX_start(bn_ctx);
	if (!(r = BN_CTX_get(bn_ctx))
		|| !fp12_init_smx(w, bn_ctx)
		|| !point_init_smx(&Ppub2, bn_ctx)) {
		SM9err(SMX_F_SMX_SIGNFINAL, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* get Ppub1 */
	if (ASN1_STRING_length(sk->pointPpub1) != 65
		|| !EC_POINT_oct2point(group, Ppub1, 
			ASN1_STRING_get0_data(sk->pointPpub1),
			ASN1_STRING_length(sk->pointPpub1), bn_ctx)) {
		SM9err(SMX_F_SMX_SIGNFINAL, SMX_R_INVALID_POINTPPUB);
		goto end;
	}

	/* get Q */
	if (ASN1_STRING_length(sk->publicPoint) != 65
		|| !EC_POINT_oct2point(group, Q, 
			ASN1_STRING_get0_data(sk->publicPoint),
			ASN1_STRING_length(sk->publicPoint), bn_ctx)) {
		SM9err(SMX_F_SMX_SIGNFINAL, SMX_R_INVALID_POINTPPUB);
		goto end;
	}


	/* get Ppub2 */
	if (ASN1_STRING_length(sk->pointPpub2) != 129
		|| !point_from_octets_smx(&Ppub2, ASN1_STRING_get0_data(sk->pointPpub2), p, bn_ctx)) {
		SM9err(SMX_F_SMX_SIGNFINAL, SMX_R_INVALID_POINTPPUB);
		goto end;
	}


	/* g = e(Q, Ppub2) */
	if (!rate_pairing_smx(w, &Ppub2, Q, bn_ctx)) {
		SM9err(SMX_F_SMX_SIGNFINAL, SMX_R_PAIRING_ERROR);
		goto end;
	}

	do {
		/* r = rand(1, n - 1) */
		do {
			if (!BN_rand_range(r, n)) {
				SM9err(SMX_F_SMX_SIGNFINAL, ERR_R_BN_LIB);
				goto end;
			}
		} while (BN_is_zero(r));

		/* w = g^r */
		if (!fp12_pow_smx(w, w, r, p, bn_ctx)
			|| !fp12_to_bin_smx(w, buf)) {
			SM9err(SMX_F_SMX_SIGNFINAL, SMX_R_EXTENSION_FIELD_ERROR);
			goto end;
		}

		if (!EVP_DigestUpdate(ctx1, buf, sizeof(buf))
			|| !EVP_MD_CTX_copy(ctx2, ctx1)
			/* Ha1 = Hv(0x02||M||w||0x00000001) */
			|| !EVP_DigestUpdate(ctx1, ct1, sizeof(ct1))
		 	/* Ha2 = Hv(0x02||M||w||0x00000002) */
			|| !EVP_DigestUpdate(ctx2, ct2, sizeof(ct2))
			|| !EVP_DigestFinal_ex(ctx1, buf, &len)
			|| !EVP_DigestFinal_ex(ctx2, buf + len, &len)) {
			SM9err(SMX_F_SMX_SIGNFINAL, SMX_R_DIGEST_FAILURE);
			goto end;
		}

		/* Ha = Ha1||Ha2[0..7] */
		if (!BN_bin2bn(buf, 40, sig->h)
			/* h = (Ha mod (n - 1)) + 1 */
			|| !BN_mod(sig->h, sig->h, SMX_get0_order_minus_one(), bn_ctx)
			|| !BN_add_word(sig->h, 1)
			/* l = r - h (mod n) */
			|| !BN_mod_sub(r, r, sig->h, n, bn_ctx)) {
			SM9err(SMX_F_SMX_SIGNFINAL, ERR_R_BN_LIB);
			goto end;
		}
	} while (BN_is_zero(r));

	/* get sk */
	if (!EC_POINT_oct2point(group, S, ASN1_STRING_get0_data(sk->privatePoint),
		ASN1_STRING_length(sk->privatePoint), bn_ctx)) {
		SM9err(SMX_F_SMX_SIGNFINAL, SMX_R_INVALID_PRIVATE_POINT);
		goto end;
	}

	/* S = l * sk */
	len = sizeof(buf);
	if (!EC_POINT_mul(group, S, NULL, S, r, bn_ctx)
		|| !(len = EC_POINT_point2oct(group, S, point_form, buf, len, bn_ctx))
		|| !ASN1_OCTET_STRING_set(sig->pointS, buf, len)) {
		SM9err(SMX_F_SMX_SIGNFINAL, ERR_R_EC_LIB);
		goto end;
	}

	ret = sig;
	sig = NULL;

end:
	SMXSignature_free(sig);
	EVP_MD_CTX_free(ctx2);
	EC_GROUP_free(group);
	EC_POINT_free(S);
	EC_POINT_free(Ppub1);
	EC_POINT_free(Q);
	BN_free(r);
	point_cleanup_smx(&Ppub2);
	fp12_cleanup_smx(w);
	BN_CTX_end(bn_ctx);
	BN_CTX_free(bn_ctx);
	return ret;
}

int SMX_VerifyInit(EVP_MD_CTX *ctx, const EVP_MD *md, ENGINE *eng)
{
	unsigned char prefix[1] = {0x02};

	if (!EVP_DigestInit_ex(ctx, md, eng)) {
		SM9err(SMX_F_SMX_VERIFYINIT, ERR_R_EVP_LIB);
		return 0;
	}
	if (!EVP_DigestUpdate(ctx, prefix, sizeof(prefix))) {
		SM9err(SMX_F_SMX_VERIFYINIT, ERR_R_EVP_LIB);
		return 0;
	}

	return 1;
}

static const EVP_MD *smxhash1_to_md(const ASN1_OBJECT *hash1obj)
{
	switch (OBJ_obj2nid(hash1obj)) {
	case NID_sm9hash1_with_sm3:
		return EVP_sm3();
	case NID_sm9hash1_with_sha256:
		return EVP_sha256();
	}
	return NULL;
}

int SMX_VerifyFinal(EVP_MD_CTX *ctx1, const SMXSignature *sig, SMXPublicKey *pk)
{
	int ret = -1;
	const BIGNUM *p = SMX_get0_prime();
	const BIGNUM *n = SMX_get0_order();
	const EVP_MD *md;
	unsigned char buf[384] = {0};
	unsigned int len;
	const unsigned char ct1[4] = {0x00, 0x00, 0x00, 0x01};
	const unsigned char ct2[4] = {0x00, 0x00, 0x00, 0x02};
	EVP_MD_CTX *ctx2 = NULL;
	EC_GROUP *group = NULL;
	EC_POINT *S = NULL;
	EC_POINT *Q = NULL;
	EC_POINT *Ppub1 = NULL;
	BN_CTX *bn_ctx = NULL;
	BIGNUM *h = NULL;
	point_t Ppub2;
	fp12_t w;
	fp12_t u;

	if (!(ctx2 = EVP_MD_CTX_new())
		|| !(group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1))
		|| !(S = EC_POINT_new(group))
		|| !(Q = EC_POINT_new(group))
		|| !(Ppub1 = EC_POINT_new(group))
		|| !(bn_ctx = BN_CTX_new())) {
		SM9err(SMX_F_SMX_VERIFYFINAL, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	BN_CTX_start(bn_ctx);
	if (!(h = BN_CTX_get(bn_ctx))
		|| !point_init_smx(&Ppub2, bn_ctx)
		|| !fp12_init_smx(w, bn_ctx)
		|| !fp12_init_smx(u, bn_ctx)) {
		SM9err(SMX_F_SMX_VERIFYFINAL, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* check signature (h, S) */
	if (BN_is_zero(sig->h) || BN_cmp(sig->h, SMX_get0_order()) >= 0) {
		SM9err(SMX_F_SMX_VERIFYFINAL, SMX_R_INVALID_SIGNATURE);
		goto end;
	}
	if (!EC_POINT_oct2point(group, S, ASN1_STRING_get0_data(sig->pointS),
		ASN1_STRING_length(sig->pointS), bn_ctx)) {
		SM9err(SMX_F_SMX_VERIFYFINAL, SMX_R_INVALID_SIGNATURE);
		goto end;
	}


	/* h1 = H1(ID||hid, N) */
	// if (!(md = smxhash1_to_md(pk->hash1))) {
	// 	SM9err(SMX_F_SMX_VERIFYFINAL, SMX_R_INVALID_HASH1);
	// 	goto end;
	// }
	// if (!SMX_hash1(md, &h, (const char *)ASN1_STRING_get0_data(pk->identity),
	// 	ASN1_STRING_length(pk->identity), SMX_HID_SIGN, n, bn_ctx)) {
	// 	SM9err(SMX_F_SMX_VERIFYFINAL, ERR_R_SM9_LIB);
	// 	goto end;
	// }


	/* get Ppub1 */
	if (ASN1_STRING_length(pk->pointPpub1) != 65
		|| !EC_POINT_oct2point(group, Ppub1, 
			ASN1_STRING_get0_data(pk->pointPpub1),
			ASN1_STRING_length(pk->pointPpub1), bn_ctx)) {
		SM9err(SMX_F_SMX_SIGNFINAL, SMX_R_INVALID_POINTPPUB);
		goto end;
	}

	/* get Q */
	if (ASN1_STRING_length(pk->publicPoint) != 65
		|| !EC_POINT_oct2point(group, Q, 
			ASN1_STRING_get0_data(pk->publicPoint),
			ASN1_STRING_length(pk->publicPoint), bn_ctx)) {
		SM9err(SMX_F_SMX_SIGNFINAL, SMX_R_INVALID_POINTPPUB);
		goto end;
	}


	/* get Ppub2 */
	if (ASN1_STRING_length(pk->pointPpub2) != 129
		|| !point_from_octets_smx(&Ppub2, ASN1_STRING_get0_data(pk->pointPpub2), p, bn_ctx)) {
		SM9err(SMX_F_SMX_VERIFYFINAL, SMX_R_INVALID_POINTPPUB);
		goto end;
	}

	/* g = e(Q, Ppub2) */
	if (!rate_pairing_smx(w, &Ppub2, Q, bn_ctx)) {
		SM9err(SMX_F_SMX_VERIFYFINAL, SMX_R_PAIRING_ERROR);
		goto end;
	}

	/* t = g^(sig->h) */
	if (!fp12_pow_smx(w, w, sig->h, p, bn_ctx)) {
		SM9err(SMX_F_SMX_VERIFYFINAL, SMX_R_EXTENSION_FIELD_ERROR);
		goto end;
	}


	/* w = u * t */
	if (!rate_pairing_smx(u, NULL, S, bn_ctx)
		|| !fp12_mul_smx(w, u, w, p, bn_ctx)
		|| !fp12_to_bin_smx(w, buf)) {
		SM9err(SMX_F_SMX_VERIFYFINAL, SMX_R_EXTENSION_FIELD_ERROR);
		goto end;
	}



	/* h2 = H2(M||w) mod n */
	if (!EVP_DigestUpdate(ctx1, buf, sizeof(buf))
		|| !EVP_MD_CTX_copy(ctx2, ctx1)
		/* Ha1 = Hv(0x02||M||w||0x00000001) */
		|| !EVP_DigestUpdate(ctx1, ct1, sizeof(ct1))
	 	/* Ha2 = Hv(0x02||M||w||0x00000002) */
		|| !EVP_DigestUpdate(ctx2, ct2, sizeof(ct2))
		|| !EVP_DigestFinal_ex(ctx1, buf, &len)
		|| !EVP_DigestFinal_ex(ctx2, buf + len, &len)) {
		SM9err(SMX_F_SMX_VERIFYFINAL, SMX_R_DIGEST_FAILURE);
		goto end;
	}
	/* Ha = Ha1||Ha2[0..7] */
	if (!BN_bin2bn(buf, 40, h)
		/* h2 = (Ha mod (n - 1)) + 1 */
		|| !BN_mod(h, h, SMX_get0_order_minus_one(), bn_ctx)
		|| !BN_add_word(h, 1)) {
		SM9err(SMX_F_SMX_VERIFYFINAL, ERR_R_BN_LIB);
		goto end;
	}

	/* check if h2 == sig->h */
	if (BN_cmp(h, sig->h) != 0) {
		SM9err(SMX_F_SMX_VERIFYFINAL, SMX_R_VERIFY_FAILURE);
		ret = 0;
		goto end;
	}

	ret = 1;

end:
	EVP_MD_CTX_free(ctx2);
	EC_GROUP_free(group);
	EC_POINT_free(S);
	EC_POINT_free(Q);
	EC_POINT_free(Ppub1);
	BN_free(h);
	point_cleanup_smx(&Ppub2);
	fp12_cleanup_smx(w);
	fp12_cleanup_smx(u);
	BN_CTX_end(bn_ctx);
	BN_CTX_free(bn_ctx);
	return ret;
}

int SMX_sign(int type, /* NID_[sm3 | sha256] */
	const unsigned char *data, size_t datalen,
	unsigned char *sig, size_t *siglen,
	SMXPrivateKey *sk)
{
	int ret = 0;
	EVP_MD_CTX *ctx = NULL;
	SMXSignature *smxsig = NULL;
	const EVP_MD *md;
	int len;

	if (!(md = EVP_get_digestbynid(type))
		|| EVP_MD_size(md) != EVP_MD_size(EVP_sm3())) {
		SM9err(SMX_F_SMX_SIGN, SMX_R_INVALID_HASH2_DIGEST);
		return 0;
	}

	if (!(ctx = EVP_MD_CTX_new())) {
		SM9err(SMX_F_SMX_SIGN, ERR_R_MALLOC_FAILURE);
		return 0;
	}

	if (!SMX_SignInit(ctx, md, NULL)
		|| !SMX_SignUpdate(ctx, data, datalen)
		|| !(smxsig = SMX_SignFinal(ctx, sk))) {
		SM9err(SMX_F_SMX_SIGN, ERR_R_SM9_LIB);
		goto end;
	}

	if ((len = i2d_SMXSignature(smxsig, &sig)) <= 0) {
		SM9err(SMX_F_SMX_SIGN, ERR_R_SM9_LIB);
		goto end;
	}

	*siglen = len;
	ret = 1;

end:
	EVP_MD_CTX_free(ctx);
	SMXSignature_free(smxsig);
	return ret;
}

int SMX_verify(int type, /* NID_[sm3 | sha256] */
	const unsigned char *data, size_t datalen,
	const unsigned char *sig, size_t siglen,
	SMXPublicParameters *mpk, const char *id, size_t idlen)
{
	int ret = -1;
	EVP_MD_CTX *ctx = NULL;
	SMXSignature *smxsig = NULL;
	SMXPublicKey *pk = NULL;
	const EVP_MD *md;

	if (!(md = EVP_get_digestbynid(type))
		|| EVP_MD_size(md) != EVP_MD_size(EVP_sm3())) {
		SM9err(SMX_F_SMX_VERIFY, SMX_R_INVALID_HASH2_DIGEST);
		return -1;
	}

	if (!(smxsig = d2i_SMXSignature(NULL, &sig, siglen))
		|| i2d_SMXSignature(smxsig, NULL) != siglen) {
		SM9err(SMX_F_SMX_VERIFY, SMX_R_INVALID_SIGNATURE_FORMAT);
		goto end;
	}

	if (!(pk = SMX_extract_public_key(mpk, id, idlen))) {
		SM9err(SMX_F_SMX_VERIFY, ERR_R_SM9_LIB);
		goto end;
	}

	if (!(ctx = EVP_MD_CTX_new())) {
		SM9err(SMX_F_SMX_VERIFY, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!SMX_VerifyInit(ctx, md, NULL)
		|| !SMX_VerifyUpdate(ctx, data, datalen)
		|| (ret = SMX_VerifyFinal(ctx, smxsig, pk)) < 0) {
		SM9err(SMX_F_SMX_VERIFY, ERR_R_SM9_LIB);
		goto end;
	}

end:
	EVP_MD_CTX_free(ctx);
	SMXSignature_free(smxsig);
	SMXPublicKey_free(pk);
	return ret;
}
