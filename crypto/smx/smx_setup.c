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

#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/smx.h>
#include "smx_lcl.h"

SMXMasterSecret *SMX_generate_master_secret(int pairing, int scheme, int hash1)
{
	SMXMasterSecret *ret = NULL;
	SMXMasterSecret *msk = NULL;
	BN_CTX *ctx = NULL;
	const BIGNUM *n = SMX_get0_order();
	const BIGNUM *p = SMX_get0_prime();
	int point_form = POINT_CONVERSION_UNCOMPRESSED;
	unsigned char buf[129];
	size_t len = sizeof(buf);

	if (!(msk = SMXMasterSecret_new())
		|| !(ctx = BN_CTX_new())) {
		SM9err(SMX_F_SMX_GENERATE_MASTER_SECRET, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	BN_CTX_start(ctx);

	/* set pairing type */
	switch (pairing) {
	case NID_sm9bn256v1:
		if (!(msk->pairing = OBJ_nid2obj(pairing))) {
			SM9err(SMX_F_SMX_GENERATE_MASTER_SECRET, ERR_R_OBJ_LIB);
			goto end;
		}
		break;
	default:
		SM9err(SMX_F_SMX_GENERATE_MASTER_SECRET, SMX_R_INVALID_PAIRING_TYPE);
		goto end;
	}

	/* set helper functions */
	switch (scheme) {
	case NID_sm9sign:
	case NID_sm9encrypt:
	case NID_sm9keyagreement:
		if (!(msk->scheme = OBJ_nid2obj(scheme))) {
			SM9err(SMX_F_SMX_GENERATE_MASTER_SECRET, ERR_R_OBJ_LIB);
			goto end;
		}
		break;
	default:
		SM9err(SMX_F_SMX_GENERATE_MASTER_SECRET, SMX_R_INVALID_SCHEME);
		goto end;
	}

	/* set hash1 */
	switch (hash1) {
	case NID_sm9hash1_with_sm3:
	case NID_sm9hash1_with_sha256:
		if (!(msk->hash1 = OBJ_nid2obj(hash1))) {
			SM9err(SMX_F_SMX_GENERATE_MASTER_SECRET, ERR_R_OBJ_LIB);
			goto end;
		}
		break;
	default:
		SM9err(SMX_F_SMX_GENERATE_MASTER_SECRET, SMX_R_INVALID_HASH1);
		goto end;
	}

	/* generate master secret k = rand(1, n - 1) */
	do {

		if (!(msk->masterSecret = BN_new())) {
			SM9err(SMX_F_SMX_GENERATE_MASTER_SECRET, ERR_R_MALLOC_FAILURE);
			goto end;
		}
		if (!BN_rand_range(msk->masterSecret, n)) {
			SM9err(SMX_F_SMX_GENERATE_MASTER_SECRET, ERR_R_BN_LIB);
			goto end;
		}
	} while (BN_is_zero(msk->masterSecret));

	/* generate master public point */
	{

		/* Ppubs = k * P2 in E'(F_p^2) */
		point_t Ppubs;

		if (!point_init_smx(&Ppubs, ctx)
			|| !point_mul_smx_generator(&Ppubs, msk->masterSecret, p, ctx)
			|| !point_to_octets_smx(&Ppubs, buf, ctx)) {
			SM9err(SMX_F_SMX_GENERATE_MASTER_SECRET, SMX_R_TWIST_CURVE_ERROR);
			point_cleanup_smx(&Ppubs);
			goto end;
		}

		len = 129;
		point_cleanup_smx(&Ppubs);

	}

	if (!(msk->pointPpub2 = ASN1_OCTET_STRING_new())) {
		SM9err(SMX_F_SMX_GENERATE_MASTER_SECRET, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!ASN1_OCTET_STRING_set(msk->pointPpub2, buf, (int)len)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	{

		/* Ppube = k * P1 in E(F_p) */
		EC_GROUP *group = NULL;
		EC_POINT *Ppube = NULL;

		if (!(group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1))
			|| !(Ppube = EC_POINT_new(group))
			|| !EC_POINT_mul(group, Ppube, msk->masterSecret, NULL, NULL, ctx)
			|| !(len = EC_POINT_point2oct(group, Ppube, point_form, buf, len, ctx))) {
			SM9err(SMX_F_SMX_GENERATE_MASTER_SECRET, SMX_R_EC_LIB);
			EC_GROUP_free(group);
			EC_POINT_free(Ppube);
			goto end;
		}

		EC_GROUP_free(group);
		EC_POINT_free(Ppube);

	} 

	if (!(msk->pointPpub1 = ASN1_OCTET_STRING_new())) {
		SM9err(SMX_F_SMX_GENERATE_MASTER_SECRET, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!ASN1_OCTET_STRING_set(msk->pointPpub1, buf, (int)len)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	ret = msk;
	msk = NULL;

end:
	SMXMasterSecret_free(msk);
	if (ctx) {
		BN_CTX_end(ctx);
	}
	BN_CTX_free(ctx);
	OPENSSL_cleanse(buf, sizeof(buf));
	return ret;
}

SMXPublicParameters *SMX_extract_public_parameters(SMXMasterSecret *msk)
{
	SMXPublicParameters *ret = NULL;
	SMXPublicParameters *mpk = NULL;

	if (!(mpk = SMXPublicParameters_new())) {
		SM9err(SMX_F_SMX_EXTRACT_PUBLIC_PARAMETERS, ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	if (!(mpk->pairing = OBJ_dup(msk->pairing))
		|| !(mpk->scheme = OBJ_dup(msk->scheme))
		|| !(mpk->hash1 = OBJ_dup(msk->hash1))
		|| !(mpk->pointPpub1 = ASN1_OCTET_STRING_dup(msk->pointPpub1))
		|| !(mpk->pointPpub2 = ASN1_OCTET_STRING_dup(msk->pointPpub2))) {
		SM9err(SMX_F_SMX_EXTRACT_PUBLIC_PARAMETERS, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	ret = mpk;
	mpk = NULL;

end:
	SMXPublicParameters_free(mpk);
	return ret;
}

int SMX_setup(int pairing, int scheme, int hash1,
	SMXPublicParameters **pmpk, SMXMasterSecret **pmsk)
{
	int ret = 0;
	SMXMasterSecret *msk = NULL;
	SMXPublicParameters *mpk = NULL;

	if (!(msk = SMX_generate_master_secret(pairing, scheme, hash1))
		|| !(mpk = SMX_extract_public_parameters(msk))) {
		goto end;
	}

	*pmsk = msk;
	*pmpk = mpk;
	msk = NULL;
	mpk = NULL;
	ret = 1;

end:
	SMXMasterSecret_free(msk);
	SMXPublicParameters_free(mpk);
	return ret;
}
