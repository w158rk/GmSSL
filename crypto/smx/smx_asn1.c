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

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/sm3.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include <openssl/smx.h>
#include "smx_lcl.h"

static int smx_master_key_cb(int operation, ASN1_VALUE **pval,
	const ASN1_ITEM *it, void *exarg)
{
	if (operation == ASN1_OP_NEW_PRE) {
		*pval = (ASN1_VALUE *)SMX_MASTER_KEY_new();
		if (*pval)
			return 2;
		return 0;
	} else if (operation == ASN1_OP_FREE_PRE) {
		SMX_MASTER_KEY_free((SMX_MASTER_KEY *)*pval);
		*pval = NULL;
		return 2;
	}
	return 1;
}

/* NOTE : the pointPpub2 is not printed */
/* not sure if it has some effects on the rightness */

ASN1_SEQUENCE_cb(SMXMasterSecret, smx_master_key_cb) = {
	ASN1_SIMPLE(SMX_MASTER_KEY, pairing, ASN1_OBJECT),
	ASN1_SIMPLE(SMX_MASTER_KEY, scheme, ASN1_OBJECT),
	ASN1_SIMPLE(SMX_MASTER_KEY, hash1, ASN1_OBJECT),
	ASN1_SIMPLE(SMX_MASTER_KEY, pointPpub1, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SMX_MASTER_KEY, pointPpub2, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SMX_MASTER_KEY, masterSecret, BIGNUM)
} ASN1_SEQUENCE_END_cb(SMX_MASTER_KEY, SMXMasterSecret)
IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(SMX_MASTER_KEY,SMXMasterSecret,SMXMasterSecret)

ASN1_SEQUENCE_cb(SMXPublicParameters, smx_master_key_cb) = {
	ASN1_SIMPLE(SMX_MASTER_KEY, pairing, ASN1_OBJECT),
	ASN1_SIMPLE(SMX_MASTER_KEY, scheme, ASN1_OBJECT),
	ASN1_SIMPLE(SMX_MASTER_KEY, hash1, ASN1_OBJECT),
	ASN1_SIMPLE(SMX_MASTER_KEY, pointPpub1, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SMX_MASTER_KEY, pointPpub2, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END_cb(SMX_MASTER_KEY, SMXPublicParameters)
IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(SMX_MASTER_KEY,SMXPublicParameters,SMXPublicParameters)


static int smx_key_cb(int operation, ASN1_VALUE **pval,
	const ASN1_ITEM *it, void *exarg)
{
	if (operation == ASN1_OP_NEW_PRE) {
		*pval = (ASN1_VALUE *)SMX_KEY_new();
		if (*pval)
			return 2;
		return 0;
	} else if (operation == ASN1_OP_FREE_PRE) {
		SMX_KEY_free((SMX_KEY *)*pval);
		*pval = NULL;
		return 2;
	}
	return 1;
}

ASN1_SEQUENCE_cb(SMXPrivateKey, smx_key_cb) = {
	ASN1_SIMPLE(SMX_KEY, pairing, ASN1_OBJECT),
	ASN1_SIMPLE(SMX_KEY, scheme, ASN1_OBJECT),
	ASN1_SIMPLE(SMX_KEY, hash1, ASN1_OBJECT),
	ASN1_SIMPLE(SMX_KEY, pointPpub1, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SMX_KEY, pointPpub2, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SMX_KEY, identity, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SMX_KEY, publicPoint, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SMX_KEY, privatePoint, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END_cb(SMX_KEY, SMXPrivateKey)
IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(SMX_KEY,SMXPrivateKey,SMXPrivateKey)

ASN1_SEQUENCE_cb(SMXPublicKey, smx_key_cb) = {
	ASN1_SIMPLE(SMX_KEY, pairing, ASN1_OBJECT),
	ASN1_SIMPLE(SMX_KEY, scheme, ASN1_OBJECT),
	ASN1_SIMPLE(SMX_KEY, hash1, ASN1_OBJECT),
	ASN1_SIMPLE(SMX_KEY, pointPpub1, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SMX_KEY, pointPpub2, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SMX_KEY, identity, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SMX_KEY, publicPoint, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END_cb(SMX_KEY, SMXPublicKey)
IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(SMX_KEY,SMXPublicKey,SMXPublicKey)

ASN1_SEQUENCE(SMXCiphertext) = {
	ASN1_SIMPLE(SMXCiphertext, pointC1, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SMXCiphertext, c2, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SMXCiphertext, c3, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(SMXCiphertext)
IMPLEMENT_ASN1_FUNCTIONS(SMXCiphertext)
IMPLEMENT_ASN1_DUP_FUNCTION(SMXCiphertext)

ASN1_SEQUENCE(SMXSignature) = {
	ASN1_SIMPLE(SMXSignature, h, BIGNUM),
	ASN1_SIMPLE(SMXSignature, pointS, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(SMXSignature)
IMPLEMENT_ASN1_FUNCTIONS(SMXSignature)
IMPLEMENT_ASN1_DUP_FUNCTION(SMXSignature)

int SMXPublicKey_gmtls_encode(SMXPublicKey *pk, unsigned char key[1024])
{
	return 0;
}

int i2d_SMXMasterSecret_bio(BIO *bp, SMXMasterSecret *a)
{
	return ASN1_item_i2d_bio(ASN1_ITEM_rptr(SMXMasterSecret), bp, a);
}

SMXMasterSecret *d2i_SMXMasterSecret_bio(BIO *bp, SMXMasterSecret **a)
{
	return ASN1_item_d2i_bio(ASN1_ITEM_rptr(SMXMasterSecret), bp, a);
}

int i2d_SMXPublicParameters_bio(BIO *bp, SMXPublicParameters *a)
{
	return ASN1_item_i2d_bio(ASN1_ITEM_rptr(SMXPublicParameters), bp, a);
}

SMXPublicParameters *d2i_SMXPublicParameters_bio(BIO *bp, SMXPublicParameters **a)
{
	return ASN1_item_d2i_bio(ASN1_ITEM_rptr(SMXPublicParameters), bp, a);
}

int i2d_SMXPrivateKey_bio(BIO *bp, SMXPrivateKey *a)
{
	return ASN1_item_i2d_bio(ASN1_ITEM_rptr(SMXPrivateKey), bp, a);
}

SMXPrivateKey *d2i_SMXPrivateKey_bio(BIO *bp, SMXPrivateKey **a)
{
	return ASN1_item_d2i_bio(ASN1_ITEM_rptr(SMXPrivateKey), bp, a);
}

			


int i2d_SMXSignature_bio(BIO *bp, SMXSignature *a)
{
	return ASN1_item_i2d_bio(ASN1_ITEM_rptr(SMXSignature), bp, a);
}

SMXSignature *d2i_SMXSignature_bio(BIO *bp, SMXSignature **a)
{
	return ASN1_item_d2i_bio(ASN1_ITEM_rptr(SMXSignature), bp, a);
}

int i2d_SMXCiphertext_bio(BIO *bp, SMXCiphertext *a)
{
	return ASN1_item_i2d_bio(ASN1_ITEM_rptr(SMXCiphertext), bp, a);
}

SMXCiphertext *d2i_SMXCiphertext_bio(BIO *bp, SMXCiphertext **a)
{
	return ASN1_item_d2i_bio(ASN1_ITEM_rptr(SMXCiphertext), bp, a);
}


#ifndef OPENSSL_NO_STDIO
SMXMasterSecret *d2i_SMXMasterSecret_fp(FILE *fp, SMXMasterSecret **msk)
{
	return ASN1_item_d2i_fp(ASN1_ITEM_rptr(SMXMasterSecret), fp, msk);
}

int i2d_SMXMasterSecret_fp(FILE *fp, SMXMasterSecret *msk)
{
	return ASN1_item_i2d_fp(ASN1_ITEM_rptr(SMXMasterSecret), fp, msk);
}

SMXPublicParameters *d2i_SMXPublicParameters_fp(FILE *fp, SMXPublicParameters **mpk)
{
	return ASN1_item_d2i_fp(ASN1_ITEM_rptr(SMXPublicParameters), fp, mpk);
}

int i2d_SMXPublicParameters_fp(FILE *fp, SMXPublicParameters *mpk)
{
	return ASN1_item_i2d_fp(ASN1_ITEM_rptr(SMXPublicParameters), fp, mpk);
}

SMXPrivateKey *d2i_SMXPrivateKey_fp(FILE *fp, SMXPrivateKey **sk)
{
	return ASN1_item_d2i_fp(ASN1_ITEM_rptr(SMXPrivateKey), fp, sk);
}

int i2d_SMXPrivateKey_fp(FILE *fp, SMXPrivateKey *sk)
{
	return ASN1_item_i2d_fp(ASN1_ITEM_rptr(SMXPrivateKey), fp, sk);
}

SMXSignature *d2i_SMXSignature_fp(FILE *fp, SMXSignature **sig)
{
	return ASN1_item_d2i_fp(ASN1_ITEM_rptr(SMXSignature), fp, sig);
}

int i2d_SMXSignature_fp(FILE *fp, SMXSignature *sig)
{
	return ASN1_item_i2d_fp(ASN1_ITEM_rptr(SMXSignature), fp, sig);
}

SMXCiphertext *d2i_SMXCiphertext_fp(FILE *fp, SMXCiphertext **c)
{
	return ASN1_item_d2i_fp(ASN1_ITEM_rptr(SMXCiphertext), fp, c);
}

int i2d_SMXCiphertext_fp(FILE *fp, SMXCiphertext *c)
{
	return ASN1_item_i2d_fp(ASN1_ITEM_rptr(SMXCiphertext), fp, c);
}
#endif

int SMX_signature_size(const SMX_MASTER_KEY *params)
{
	if (params) {
		int ret;
		ASN1_INTEGER h;
		ASN1_OCTET_STRING s;
		unsigned char buf[4] = {0xff};
		int len = 0;

		/* ASN1_INTEGER h convert from hash */
		h.length = SM3_DIGEST_LENGTH;
		h.data = buf;
		h.type = V_ASN1_INTEGER;
		len += i2d_ASN1_INTEGER(&h, NULL);

		/* ASN1_OCTET_STRING pointS over E'(F_p^2) */
		s.length = 129;
		s.data = buf;
		s.type = V_ASN1_OCTET_STRING;
		len += i2d_ASN1_OCTET_STRING(&s, NULL);

		ret = ASN1_object_size(1, len, V_ASN1_SEQUENCE);
		return ret;
	} else {
		return 170;
	}
}

int SMX_ciphertext_size(const SMX_MASTER_KEY *params, size_t inlen)
{
	int ret;
	ASN1_OCTET_STRING s;
	s.type = V_ASN1_OCTET_STRING;
	s.data = NULL;
	int len = 0;

	if (inlen > SMX_MAX_PLAINTEXT_LENGTH) {
		SM9err(SMX_F_SMX_CIPHERTEXT_SIZE, SMX_R_PLAINTEXT_TOO_LONG);
		return 0;
	}

	if (params) {
		/* ASN1_OCTET_STRING pointC1 over E(F_p) */
		s.length = 129;
		len += i2d_ASN1_OCTET_STRING(&s, NULL);

		/* ASN1_OCTET_STRING c3 SM3-MAC */
		s.length = SM3_DIGEST_LENGTH;
		len += i2d_ASN1_OCTET_STRING(&s, NULL);
	} else {
		/* when no params given, if use point compression is unknown,
		 * so the maximum uncompressed point length is used */
		len += 101;
	}

	/* ASN1_OCTET_STRING c2 ciphertext */
	s.length = inlen;
	len += i2d_ASN1_OCTET_STRING(&s, NULL);

	ret = ASN1_object_size(1, len, V_ASN1_SEQUENCE);
	return ret;
}
