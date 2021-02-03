/* ====================================================================
 * Copyright (c) 2018 The GmSSL Project.  All rights reserved.
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
#include <string.h>
#include <stdint.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include "sm9_lcl.h"



static char exp_montgomery[][65] = {
	"",
	"9EF74015D5A16393F51F5EAC13DF846C9EC8547B245C54FD1A98DFBD4575299F",
	"1C753E748601C9929C705DB2FD91512A08296B3557ED0186B626197DCE4736CA",
	"9848EEC25498CAB5B8554AB054AC91E3DB043BF50858278239B4EF0F3EE72529",
	"88F53E748B4917764877B452E8AEDFB44C0E91CB8CE2DF3E81054FCD94E9C1C4",
	"AF91AEAC819B0E1399399754365BD4BC5E2E7AC4FE76C161048BAA79DCC34107",
	"6C80000005474DE3AC07569FEB1D8E8A43E5269634F5DDB7CADF364FC6A28AFA",
	"1748BFEA2D02435DE0E44CA3E1AF42D8832A3ECFF61E99DECAD6BB6A9DDC1BDE",
	"99CAC18B7CA1DD5F39934D9CF7FD761B19C92815C28DED552F4981AA150A0EB3",
	"1DF7113DAE0ADC3C1DAE609FA0E2356146EE57561222C759ABBAAC18A46A2054",
	"2D4AC18B775A8F7B8D8BF6FD0CDFE790D5E4017F8D980F9D646A4B5A4E6783B9",
	"6AE5153810898DE3CCA13FBBF32F288C3C418861C042D7AE0E3F0AE068E0476"
};


static BN_MONT_CTX *mont;

static int fp2_init(fp2_t a, BN_CTX *ctx)
{
	a[0] = NULL;
	a[1] = NULL;
	a[0] = BN_new();
	a[1] = BN_new();
	/*
	if (!a[1]) {
		BN_free(a[0]);
		a[0] = NULL;
		return 0;
	}
	*/
	return 1;
}

static void fp2_cleanup(fp2_t a)
{
	BN_free(a[0]);
	BN_free(a[1]);
	a[0] = NULL;
	a[1] = NULL;
}

static void fp2_clear_cleanup(fp2_t a)
{
	BN_clear_free(a[0]);
	BN_clear_free(a[1]);
	a[0] = NULL;
	a[1] = NULL;
}

static int fp2_is_zero(const fp2_t a)
{
	return BN_is_zero(a[0])
		&& BN_is_zero(a[1]);
}

static int fp2_print(const fp2_t a)
{
	// printf("%s\n", BN_bn2hex(a[0]));
	// printf("%s\n", BN_bn2hex(a[1]));
	return 1;
}

static int fp2_is_one(const fp2_t a)
{
	return BN_is_one(a[0])
		&& BN_is_zero(a[1]);
}

static void fp2_set_zero(fp2_t r)
{
	BN_zero(r[0]);
	BN_zero(r[1]);
}

static int fp2_set_one_montgomery(fp2_t r)
{
	BN_zero(r[1]);
	BN_copy(r[0], SM9_get0_one_montgomery());
	return 1;
}

static int fp2_set_inv_unit(fp2_t r)
{
	BN_zero(r[0]);
	BN_copy(r[1], SM9_get0_inv_unit());
	return 1;
}

static int fp2_set_inv_unit_montgomery(fp2_t r)
{
	BN_zero(r[0]);
	BN_copy(r[1], SM9_get0_inv_unit_montgomery());
	return 1;
}


static int fp2_set_one(fp2_t r)
{
	BN_zero(r[1]);
	return BN_one(r[0]);
}

static int fp2_copy(fp2_t r, const fp2_t a)
{
	return BN_copy(r[0], a[0])
		&& BN_copy(r[1], a[1]);
}

static int fp2_set(fp2_t r, const BIGNUM *a0, const BIGNUM *a1)
{
	return BN_copy(r[0], a0)
		&& BN_copy(r[1], a1);
}

static int fp2_set_hex(fp2_t r, const char *str[2])
{
	return BN_hex2bn(&r[0], str[0])
		&& BN_hex2bn(&r[1], str[1]);
}

static int fp2_set_u(fp2_t r)
{
	BN_zero(r[0]);
	return BN_one(r[1]);
}

static int fp2_set_5u(fp2_t r)
{
	BN_zero(r[0]);
	return BN_set_word(r[1], 5);
}

static int fp2_set_bn(fp2_t r, const BIGNUM *a)
{
	BN_zero(r[1]);
	return BN_copy(r[0], a) != NULL;
}

static int fp2_set_word(fp2_t r, unsigned long a)
{
	BN_zero(r[1]);
	return BN_set_word(r[0], a);
}

static int fp2_equ(const fp2_t a, const fp2_t b)
{
	return !BN_cmp(a[0], b[0]) && !BN_cmp(a[1], b[1]);
}

#if SM9_TEST
static int fp2_equ_hex(const fp2_t a, const char *str[2], BN_CTX *ctx)
{
	fp2_t t;
	fp2_init(t, ctx);
	fp2_set_hex(t, str);
	return fp2_equ(a, t);
}
#endif

#if SM9_TEST
static int fp2_add_word(fp2_t r, const fp2_t a, unsigned long b, const BIGNUM *p, BN_CTX *ctx)
{
	BIGNUM *w = NULL;
	if (!(w = BN_new())
		|| !BN_set_word(w, b)
		|| !BN_mod_add_quick(r[0], a[0], w, p)
		|| !BN_copy(r[1], a[1])) {
		BN_free(w);
		return 0;
	}
	BN_free(w);
	return 1;
}
#endif

static int fp2_add(fp2_t r, const fp2_t a, const fp2_t b, const BIGNUM *p, BN_CTX *ctx)
{
	return BN_mod_add_quick(r[0], a[0], b[0], p)
		&& BN_mod_add_quick(r[1], a[1], b[1], p);
}

static int fp2_dbl(fp2_t r, const fp2_t a, const BIGNUM *p, BN_CTX *ctx)
{
	return BN_mod_add_quick(r[0], a[0], a[0], p)
		&& BN_mod_add_quick(r[1], a[1], a[1], p);
}

static int fp2_tri(fp2_t r, const fp2_t a, const BIGNUM *p, BN_CTX *ctx)
{
	fp2_t t;
	if (!fp2_init(t, ctx)
		|| !fp2_dbl(t, a, p, ctx)
		|| !fp2_add(r, t, a, p, ctx)) {
		fp2_cleanup(t);
		return 0;
	}
	fp2_cleanup(t);
	return 1;
}

static int fp2_sub(fp2_t r, const fp2_t a, const fp2_t b, const BIGNUM *p, BN_CTX *ctx)
{
	return BN_mod_sub_quick(r[0], a[0], b[0], p)
		&& BN_mod_sub_quick(r[1], a[1], b[1], p);
}

static int fp2_neg(fp2_t r, const fp2_t a, const BIGNUM *p, BN_CTX *ctx)
{
	return BN_mod_sub_quick(r[0], p, a[0], p)
		&& BN_mod_sub_quick(r[1], p, a[1], p);
}

static int fp2_from_montgomery(fp2_t ret, fp2_t in, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	return BN_from_montgomery(ret[0], in[0], mont, ctx)
			&& BN_from_montgomery(ret[1], in[1], mont, ctx);
}

static int fp2_to_montgomery(fp2_t ret, fp2_t in, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	/* temp, remove me later */
	return BN_to_montgomery(ret[0], in[0], mont, ctx)
			&& BN_to_montgomery(ret[1], in[1], mont, ctx);
}

static int fp2_mul_montgomery(fp2_t r, const fp2_t a, const fp2_t b, const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	BIGNUM *t = NULL;
	BIGNUM *t1 = NULL;
	BIGNUM *r0 = NULL;
	BIGNUM *r1 = NULL;
	if (!(t = BN_new())
		// || !(t1 = BN_new())
		|| !(r0 = BN_new())
		|| !(r1 = BN_new())

		/* r0 = a0 * b0 - 2 * a1 * b1 */
		|| !BN_mod_mul_montgomery(r0, a[0], b[0], mont, ctx)
		|| !BN_mod_mul_montgomery(t, a[1], b[1], mont, ctx)
		|| !BN_mod_add_quick(t, t, t, p)
		|| !BN_mod_sub_quick(r0, r0, t, p)

		/* r1 = a0*b1 + a1*b0 */
		|| !BN_mod_mul_montgomery(r1, a[0], b[1], mont, ctx)
		|| !BN_mod_mul_montgomery(t, a[1], b[0], mont, ctx)
		|| !BN_mod_add_quick(r1, r1, t, p)

	

		|| !BN_copy(r[0], r0)
		|| !BN_copy(r[1], r1)) {
		BN_free(t);
		BN_free(r0);
		BN_free(r1);
		return 0;
	}

	BN_free(t);
	BN_free(r0);
	BN_free(r1);
	return 1;
}

static int fp2_mul_u_montgomery_123(fp2_t r, const fp2_t a, const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	/* return a*u */
	BIGNUM *r0 = NULL;
	if (!(r0 = BN_new())

		/* r0 = -2 * a1 */
		|| !BN_mod_add_quick(r0, a[1], a[1], p)
		|| !BN_mod_sub_quick(r0, p, r0, p)

		/* r1 = a0 */
		|| !BN_copy(r[1], a[0])
		|| !BN_copy(r[0], r0)) {
		BN_free(r0);
		return 0;
	}
	BN_free(r0);
	return 1;
}

static int fp2_mul_u_montgomery(fp2_t r, const fp2_t a, const fp2_t b, const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	BIGNUM *r0 = NULL;
	BIGNUM *r1 = NULL;
	BIGNUM *t = NULL;
	if (!(r0 = BN_new())
		|| !(r1 = BN_new())
		|| !(t = BN_new())

		/* r0 = -2 * (a0 * b1 + a1 * b0) */
		|| !BN_mod_mul_montgomery(r0, a[0], b[1], mont, ctx)
		|| !BN_mod_mul_montgomery(t, a[1], b[0], mont, ctx)
		|| !BN_mod_add_quick(r0, r0, t, p)
		|| !BN_mod_add_quick(r0, r0, r0, p)
		|| !BN_mod_sub_quick(r0, p, r0, p)

		/* r1 = a0 * b0 - 2 * a1 * b1 */
		|| !BN_mod_mul_montgomery(r1, a[0], b[0], mont, ctx)
		|| !BN_mod_mul_montgomery(t, a[1], b[1], mont, ctx)
		|| !BN_mod_add_quick(t, t, t, p)
		|| !BN_mod_sub_quick(r1, r1, t, p)

		|| !BN_copy(r[0], r0)
		|| !BN_copy(r[1], r1)) {
		BN_free(r0);
		BN_free(r1);
		BN_free(t);
		return 0;
	}
	BN_free(r0);
	BN_free(r1);
	BN_free(t);
	return 1;
}

static int fp2_sqr_montgomery(fp2_t r, const fp2_t a, const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	BIGNUM *r0 = NULL;
	BIGNUM *r1 = NULL;
	BIGNUM *t = NULL;
	if (!(r0 = BN_new())
		|| !(r1 = BN_new())
		||!(t = BN_new())
		/* r0 = a0^2 - 2 * a1^2 */
		|| !BN_mod_mul_montgomery(r0, a[0], a[0], mont, ctx)
		|| !BN_mod_mul_montgomery(t, a[1], a[1], mont, ctx)
		|| !BN_mod_add_quick(t, t, t, p)
		|| !BN_mod_sub_quick(r0, r0, t, p)

		/* r1 = 2 * a0 * a1 */
		|| !BN_mod_mul_montgomery(r1, a[0], a[1], mont, ctx)
		|| !BN_mod_add_quick(r1, r1, r1, p)
		|| !BN_copy(r[0], r0)
		|| !BN_copy(r[1], r1)) {
		BN_free(r0);
		BN_free(r1);
		BN_free(t);
		return 0;
	}
	BN_free(r0);
	BN_free(r1);
	BN_free(t);
	return 1;
}

static int fp2_sqr_u_montgomery(fp2_t r, const fp2_t a, const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	BIGNUM *r0 = NULL;
	BIGNUM *r1 = NULL;
	BIGNUM *t = NULL;
	if (!(r0 = BN_new())
		|| !(r1 = BN_new())
		|| !(t = BN_new())
		/* r0 = -4 * a0 * a1 */
		|| !BN_mod_mul_montgomery(r0, a[0], a[1], mont, ctx)
		|| !BN_mod_add_quick(r0, r0, r0, p)
		|| !BN_mod_add_quick(r0, r0, r0, p)
		|| !BN_mod_sub_quick(r0, p, r0, p)

		/* r1 = a0^2 - 2 * a1^2 */
		|| !BN_mod_mul_montgomery(r1, a[0], a[0], mont, ctx)
		|| !BN_mod_mul_montgomery(t, a[1], a[1], mont, ctx)
		|| !BN_mod_add_quick(t, t, t, p)
		|| !BN_mod_sub_quick(r1, r1, t, p)

		|| !BN_copy(r[0], r0)
		|| !BN_copy(r[1], r1)) {
		BN_free(r0);
		BN_free(r1);
		BN_free(t);
		return 0;
	}
	BN_free(r0);
	BN_free(r1);
	BN_free(t);
	return 1;
}
static int fp2_mul(fp2_t r, const fp2_t a, const fp2_t b, const BIGNUM *p, BN_CTX *ctx)
{
	BIGNUM *t = NULL;
	BIGNUM *r0 = NULL;
	BIGNUM *r1 = NULL;
	if (!(t = BN_new())
		|| !(r0 = BN_new())
		|| !(r1 = BN_new())

		/* r0 = a0 * b0 - 2 * a1 * b1 */
		|| !BN_mod_mul(r0, a[0], b[0], p, ctx)
		|| !BN_mod_mul(t, a[1], b[1], p, ctx)
		|| !BN_mod_add_quick(t, t, t, p)
		|| !BN_mod_sub_quick(r0, r0, t, p)

		/* r1 = a0 * b1 + a1 * b0 */
		|| !BN_mod_mul(r1, a[0], b[1], p, ctx)
		|| !BN_mod_mul(t, a[1], b[0], p, ctx)
		|| !BN_mod_add_quick(r1, r1, t, p)

		|| !BN_copy(r[0], r0)
		|| !BN_copy(r[1], r1)) {
		BN_free(t);
		BN_free(r0);
		BN_free(r1);
		return 0;
	}

// #define TESTFP2
#ifdef TESTFP2

	fp2_t ta, tb, tr;
	fp2_init(ta, ctx);
	fp2_init(tb, ctx);
	fp2_init(tr, ctx);

	/* temp, remove me later */
	
	if(!mont){
		mont = BN_MONT_CTX_new();
		BN_MONT_CTX_set(mont, p, ctx);
	}

	fp2_to_montgomery(ta, a, mont, ctx);
	fp2_to_montgomery(tb, b, mont, ctx);
	fp2_mul_montgomery(tr, ta, tb, p, mont, ctx);
	fp2_from_montgomery(tr, tr, mont, ctx);

	if(!fp2_equ(r, tr) && !fp2_equ(r, a) && !fp2_equ(r, b))
	{
		// printf("mul\n\n");
		fp2_print(a);
		// printf("\n\n");
		fp2_print(r);
		// printf("\n\n");
		fp2_print(tr);
		// printf("\n\n");
	}

#endif

	BN_free(t);
	BN_free(r0);
	BN_free(r1);
	return 1;
}

static int fp2_mul_u(fp2_t r, const fp2_t a, const fp2_t b, const BIGNUM *p, BN_CTX *ctx)
{
	BIGNUM *r0 = NULL;
	BIGNUM *r1 = NULL;
	BIGNUM *t = NULL;
	if (!(r0 = BN_new())
		|| !(r1 = BN_new())
		|| !(t = BN_new())

		/* r0 = -2 * (a0 * b1 + a1 * b0) */
		|| !BN_mod_mul(r0, a[0], b[1], p, ctx)
		|| !BN_mod_mul(t, a[1], b[0], p, ctx)
		|| !BN_mod_add_quick(r0, r0, t, p)
		|| !BN_mod_add_quick(r0, r0, r0, p)
		|| !BN_mod_sub_quick(r0, p, r0, p)

		/* r1 = a0 * b0 - 2 * a1 * b1 */
		|| !BN_mod_mul(r1, a[0], b[0], p, ctx)
		|| !BN_mod_mul(t, a[1], b[1], p, ctx)
		|| !BN_mod_add_quick(t, t, t, p)
		|| !BN_mod_sub_quick(r1, r1, t, p)

		|| !BN_copy(r[0], r0)
		|| !BN_copy(r[1], r1)) {
		BN_free(r0);
		BN_free(r1);
		BN_free(t);
		return 0;
	}

#ifdef TESTFP2

	fp2_t ta, tb, tr;
	fp2_init(ta, ctx);
	fp2_init(tb, ctx);
	fp2_init(tr, ctx);

	/* temp, remove me later */
	
	if(!mont){
		mont = BN_MONT_CTX_new();
		BN_MONT_CTX_set(mont, p, ctx);
	}

	fp2_to_montgomery(ta, a, mont, ctx);
	fp2_to_montgomery(tb, b, mont, ctx);
	fp2_mul_u_montgomery(tr, ta, tb, p, mont, ctx);
	fp2_from_montgomery(tr, tr, mont, ctx);

	if(!fp2_equ(r, tr) && !fp2_equ(r, a) && !fp2_equ(r, b))
	{
		// printf("mul_u\n\n");
		fp2_print(a);
		// printf("\n\n");
		fp2_print(r);
		// printf("\n\n");
		fp2_print(tr);
		// printf("\n\n");
	}

#endif

	BN_free(r0);
	BN_free(r1);
	BN_free(t);
	return 1;
}

static int fp2_mul_num_montgomery(fp2_t r, const fp2_t a, const BIGNUM *n, const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	BIGNUM *r0 = NULL;
	BIGNUM *r1 = NULL;
	if (!(r0 = BN_new())
		|| !(r1 = BN_new())

		|| !BN_mod_mul_montgomery(r0, a[0], n, mont, ctx)
		|| !BN_mod_mul_montgomery(r1, a[1], n, mont, ctx)

		|| !BN_copy(r[0], r0)
		|| !BN_copy(r[1], r1)) {
		BN_free(r0);
		BN_free(r1);
		return 0;
	}
	BN_free(r0);
	BN_free(r1);
	return 1;
}


static int fp2_mul_num(fp2_t r, const fp2_t a, const BIGNUM *n, const BIGNUM *p, BN_CTX *ctx)
{
	BIGNUM *r0 = NULL;
	BIGNUM *r1 = NULL;
	if (!(r0 = BN_new())
		|| !(r1 = BN_new())

		|| !BN_mod_mul(r0, a[0], n, p, ctx)
		|| !BN_mod_mul(r1, a[1], n, p, ctx)

		|| !BN_copy(r[0], r0)
		|| !BN_copy(r[1], r1)) {
		BN_free(r0);
		BN_free(r1);
		return 0;
	}
	BN_free(r0);
	BN_free(r1);
	return 1;
}

static int fp2_sqr(fp2_t r, const fp2_t a, const BIGNUM *p, BN_CTX *ctx)
{
	BIGNUM *r0 = NULL;
	BIGNUM *r1 = NULL;
	BIGNUM *t = NULL;
	if (!(r0 = BN_new())
		|| !(r1 = BN_new())
		||!(t = BN_new())
		/* r0 = a0^2 - 2 * a1^2 */
		|| !BN_mod_sqr(r0, a[0], p, ctx)
		|| !BN_mod_sqr(t, a[1], p, ctx)
		|| !BN_mod_add_quick(t, t, t, p)
		|| !BN_mod_sub_quick(r0, r0, t, p)

		/* r1 = 2 * a0 * a1 */
		|| !BN_mod_mul(r1, a[0], a[1], p, ctx)
		|| !BN_mod_add_quick(r1, r1, r1, p)
		|| !BN_copy(r[0], r0)
		|| !BN_copy(r[1], r1)) {
		BN_free(r0);
		BN_free(r1);
		BN_free(t);
		return 0;
	}

#ifdef TESTFP2

	fp2_t ta, tb, tr;
	fp2_init(ta, ctx);
	fp2_init(tb, ctx);
	fp2_init(tr, ctx);

	/* temp, remove me later */
	
	if(!mont){
		mont = BN_MONT_CTX_new();
		BN_MONT_CTX_set(mont, p, ctx);
	}

	fp2_to_montgomery(ta, a, mont, ctx);
	// fp2_to_montgomery(tb, b, mont, ctx);
	fp2_sqr_montgomery(tr, ta, p, mont, ctx);
	fp2_from_montgomery(tr, tr, mont, ctx);

	if(!fp2_equ(r, tr) && !fp2_equ(r, a))
	{
		// printf("sqr\n\n");
		fp2_print(a);
		// printf("\n\n");
		fp2_print(r);
		// printf("\n\n");
		fp2_print(tr);
		// printf("\n\n");
	}

#endif

	BN_free(r0);
	BN_free(r1);
	BN_free(t);
	return 1;
}

static int fp2_sqr_u(fp2_t r, const fp2_t a, const BIGNUM *p, BN_CTX *ctx)
{
	BIGNUM *r0 = NULL;
	BIGNUM *r1 = NULL;
	BIGNUM *t = NULL;
	if (!(r0 = BN_new())
		|| !(r1 = BN_new())
		|| !(t = BN_new())
		/* r0 = -4 * a0 * a1 */
		|| !BN_mod_mul(r0, a[0], a[1], p, ctx)
		|| !BN_mod_add_quick(r0, r0, r0, p)
		|| !BN_mod_add_quick(r0, r0, r0, p)
		|| !BN_mod_sub_quick(r0, p, r0, p)

		/* r1 = a0^2 - 2 * a1^2 */
		|| !BN_mod_sqr(r1, a[0], p, ctx)
		|| !BN_mod_sqr(t, a[1], p, ctx)
		|| !BN_mod_add_quick(t, t, t, p)
		|| !BN_mod_sub_quick(r1, r1, t, p)

		|| !BN_copy(r[0], r0)
		|| !BN_copy(r[1], r1)) {
		BN_free(r0);
		BN_free(r1);
		BN_free(t);
		return 0;
	}

#ifdef TESTFP2

	fp2_t ta, tb, tr;
	fp2_init(ta, ctx);
	fp2_init(tb, ctx);
	fp2_init(tr, ctx);

	/* temp, remove me later */
	
	if(!mont){
		mont = BN_MONT_CTX_new();
		BN_MONT_CTX_set(mont, p, ctx);
	}

	fp2_to_montgomery(ta, a, mont, ctx);
	// fp2_to_montgomery(tb, b, mont, ctx);
	fp2_sqr_u_montgomery(tr, ta, p, mont, ctx);
	fp2_from_montgomery(tr, tr, mont, ctx);

	if(!fp2_equ(r, tr) && !fp2_equ(r, a))
	{
		// printf("sqr_u\n\n");
		fp2_print(a);
		// printf("\n\n");
		fp2_print(r);
		// printf("\n\n");
		fp2_print(tr);
		// printf("\n\n");
	}

#endif

	BN_free(r0);
	BN_free(r1);
	BN_free(t);
	return 1;
}

static int fp2_inv(fp2_t r, const fp2_t a, const BIGNUM *p, BN_CTX *ctx)
{
	if (BN_is_zero(a[0])) {
		/* r0 = 0 */
		BN_zero(r[0]);
		/* r1 = -(2 * a1)^-1 */
		if (!BN_mod_add_quick(r[1], a[1], a[1], p)
			|| !BN_mod_inverse(r[1], r[1], p, ctx)
			|| !BN_mod_sub_quick(r[1], p, r[1], p)) {
			return 0;
		}

	} else if (BN_is_zero(a[1])) {
		/* r1 = 0 */
		BN_zero(r[1]);
		/* r0 = a0^-1 */
		if (!BN_mod_inverse(r[0], a[0], p, ctx)) {
			return 0;
		}

	} else {
		BIGNUM *k = NULL;
		BIGNUM *t = NULL;
		if (!(k = BN_new())
			|| !(t = BN_new())

			/* k = (a[0]^2 + 2 * a[1]^2)^-1 */
			|| !BN_mod_sqr(k, a[0], p, ctx)
			|| !BN_mod_sqr(t, a[1], p, ctx)
			|| !BN_mod_add_quick(t, t, t, p)
			|| !BN_mod_add_quick(k, k, t, p)
			|| !BN_mod_inverse(k, k, p, ctx)

			/* r[0] = a[0] * k, r[1] = -a[1] * k */
			|| !BN_mod_mul(r[0], a[0], k, p, ctx)
			|| !BN_mod_mul(r[1], a[1], k, p, ctx)
			|| !BN_mod_sub_quick(r[1], p, r[1], p)) {

			BN_free(k);
			BN_free(t);
			return 0;
		}
		BN_free(k);
		BN_free(t);
	}

	return 1;
}


static int fp2_to_bin(const fp2_t a, unsigned char to[64])
{
	memset(to, 0, 64);
	BN_bn2bin(a[1], to + 32 - BN_num_bytes(a[1]));
	BN_bn2bin(a[0], to + 64 - BN_num_bytes(a[0]));
	return 1;
}

static int fp2_from_bin(fp2_t a, const unsigned char from[64])
{
	return BN_bin2bn(from, 32, a[1])
		&& BN_bin2bn(from + 32, 32, a[0]);
}

static int fp4_init(fp4_t a, BN_CTX *ctx)
{
	int r;
	r = fp2_init(a[0], ctx);
	r &= fp2_init(a[1], ctx);
	if (!r) {
		fp2_cleanup(a[0]);
		fp2_cleanup(a[1]);
	}
	return r;
}

static void fp4_cleanup(fp4_t a)
{
	fp2_cleanup(a[0]);
	fp2_cleanup(a[1]);
}

#if SM9_TEST
static void fp4_clear_cleanup(fp4_t a)
{
	fp2_clear_cleanup(a[0]);
	fp2_clear_cleanup(a[1]);
}
#endif

static int fp4_print(const fp4_t a)
{
	fp2_print(a[0]);
	fp2_print(a[1]);
	// printf("\n");
	return 1;
}

static int fp4_is_zero(const fp4_t a)
{
	return fp2_is_zero(a[0])
		&& fp2_is_zero(a[1]);
}

static int fp4_is_one(const fp4_t a)
{
	return fp2_is_one(a[0])
		&& fp2_is_zero(a[1]);
}

static void fp4_set_zero(fp4_t r)
{
	fp2_set_zero(r[0]);
	fp2_set_zero(r[1]);
}

static int fp4_set_one_montgomery(fp4_t r)
{
	fp2_set_zero(r[1]);
	return fp2_set_one_montgomery(r[0]);
}

static int fp4_set_one(fp4_t r)
{
	fp2_set_zero(r[1]);
	return fp2_set_one(r[0]);
}

static int fp4_set_inv_unit(fp4_t r)
{
	fp2_set_zero(r[0]);
	return fp2_set_inv_unit(r[1]);
}

static int fp4_set_inv_unit_montgomery(fp4_t r)
{
	fp2_set_zero(r[0]);
	return fp2_set_inv_unit_montgomery(r[1]);
}

static int fp4_set_bn(fp4_t r, const BIGNUM *a)
{
	fp2_set_zero(r[1]);
	return fp2_set_bn(r[0], a);
}

static int fp4_set_word(fp4_t r, unsigned long a)
{
	fp2_set_zero(r[1]);
	return fp2_set_word(r[0], a);
}

static int fp4_set_fp2(fp4_t r, const fp2_t a)
{
	fp2_set_zero(r[1]);
	return fp2_copy(r[0], a);
}

static int fp4_set(fp4_t r, const fp2_t a0, const fp2_t a1)
{
	return fp2_copy(r[0], a0)
		&& fp2_copy(r[1], a1);
}

static int fp4_set_hex(fp4_t r, const char *str[4])
{
	return fp2_set_hex(r[0], str)
		&& fp2_set_hex(r[1], str+2);
}

static int fp4_copy(fp4_t r, const fp4_t a)
{
	return fp2_copy(r[0], a[0])
		&& fp2_copy(r[1], a[1]);
}

static int fp4_set_u(fp4_t r)
{
	fp2_set_zero(r[1]);
	return fp2_set_u(r[0]);
}

static int fp4_set_v_montgomery(fp4_t r)
{
	fp2_set_zero(r[0]);
	return fp2_set_one_montgomery(r[1]);
}

static int fp4_set_v(fp4_t r)
{
	fp2_set_zero(r[0]);
	return fp2_set_one(r[1]);
}

static int fp4_equ(const fp4_t a, const fp4_t b)
{
	return fp2_equ(a[0], b[0])
		&& fp2_equ(a[1], b[1]);
}

#if SM9_TEST
static int fp4_equ_hex(const fp4_t a, const char *str[4], BN_CTX *ctx)
{
	fp4_t t;
	fp4_init(t, ctx);
	fp4_set_hex(t, str);
	return fp4_equ(a, t);
}
#endif

static int fp4_to_bin(const fp4_t a, unsigned char to[128])
{
	return fp2_to_bin(a[1], to)
		&& fp2_to_bin(a[0], to + 64);
}

static int fp4_from_bin(fp4_t a, const unsigned char from[128])
{
	return fp2_from_bin(a[1], from)
		&& fp2_from_bin(a[0], from + 64);
}

static int fp4_add(fp4_t r, const fp4_t a, const fp4_t b, const BIGNUM *p, BN_CTX *ctx)
{
	return fp2_add(r[0], a[0], b[0], p, ctx)
		&& fp2_add(r[1], a[1], b[1], p, ctx);
}

static int fp4_dbl(fp4_t r, const fp4_t a, const BIGNUM *p, BN_CTX *ctx)
{
	return fp2_dbl(r[0], a[0], p, ctx)
		&& fp2_dbl(r[1], a[1], p, ctx);
}

static int fp4_sub(fp4_t r, const fp4_t a, const fp4_t b, const BIGNUM *p, BN_CTX *ctx)
{
	return fp2_sub(r[0], a[0], b[0], p, ctx)
		&& fp2_sub(r[1], a[1], b[1], p, ctx);
}

static int fp4_neg(fp4_t r, const fp4_t a, const BIGNUM *p, BN_CTX *ctx)
{
	return fp2_neg(r[0], a[0], p, ctx)
		&&fp2_neg(r[1], a[1], p, ctx);
}

static int fp4_from_montgomery(fp4_t r, fp4_t a, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	return fp2_from_montgomery(r[0], a[0], mont, ctx)
			&& fp2_from_montgomery(r[1], a[1], mont, ctx);
}

static int fp4_to_montgomery(fp4_t r, fp4_t a, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	return fp2_to_montgomery(r[0], a[0], mont, ctx)
			&& fp2_to_montgomery(r[1], a[1], mont, ctx);
}

static int fp4_mul_v_montgomery_123(fp4_t r, const fp4_t a, const BIGNUM *p, BN_CTX *ctx)
{
	fp2_t r0;

	fp2_init(r0, ctx);
	if (/* r0 = r1 * u */
		! fp2_mul_u_montgomery_123(r0, a[1], p, mont, ctx)
		/* r1 = a0 */
		|| !fp2_copy(r[1], a[0])
		|| !fp2_copy(r[0], r0)) {
		fp2_cleanup(r0);
		return 0;
	}

	fp2_cleanup(r0);
	return 1;
}

static int fp4_mul_montgomery(fp4_t r, const fp4_t a, const fp4_t b, const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	fp2_t r0, r1, t, t1;

	fp2_init(r0, ctx);
	fp2_init(r1, ctx);
	fp2_init(t1, ctx);

	if (!fp2_init(t, ctx)
		/* r0 = a0 * b0 + a1 * b1 * u */
		// || !fp2_mul_montgomery(r0, a[0], b[0], p, mont, ctx)
		// || !fp2_mul_montgomery(t, a[1], b[1], p, mont, ctx)
		// || !fp2_mul_u_montgomery_123(t, t, p, mont, ctx)
		// || !fp2_add(r0, r0, t, p, ctx)

		// /* r[1] = a[0] * b[1] + a[1] * b[0] */
		// || !fp2_mul_montgomery(r1, a[0], b[1], p, mont, ctx)
		// || !fp2_mul_montgomery(t, a[1], b[0], p, mont, ctx)
		// || !fp2_add(r1, r1, t, p, ctx)

		|| !fp2_mul_montgomery(r0, a[0], b[0], p, mont, ctx)
		|| !fp2_mul_montgomery(t, a[1], b[1], p, mont, ctx)

		/* r[1] = (a0+a1)(b0+b1) - a0b1 - a1b0 */
		|| !fp2_add(t1, a[0], a[1], p, ctx)
		|| !fp2_add(r1, b[0], b[1], p, ctx)
		|| !fp2_mul_montgomery(r1, r1, t1, p, mont, ctx)
		|| !fp2_sub(r1, r1, t, p, ctx)
		|| !fp2_sub(r1, r1, r0, p, ctx)

		/* r0 = a0 * b0 + a1 * b1 * u */
		|| !fp2_mul_u_montgomery_123(t, t, p, mont, ctx)
		|| !fp2_add(r0, r0, t, p, ctx)

		|| !fp2_copy(r[0], r0)
		|| !fp2_copy(r[1], r1)) {
		fp2_cleanup(r0);
		fp2_cleanup(r1);
		fp2_cleanup(t);
		return 0;
	}
	fp2_cleanup(r0);
	fp2_cleanup(r1);
	fp2_cleanup(t);
	return 1;
}

static int fp4_mul_v_montgomery(fp4_t r, const fp4_t a, const fp4_t b, const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	fp2_t r0, r1, t;
	fp2_init(r0, ctx);
	fp2_init(r1, ctx);
	if (!fp2_init(t, ctx)
		/* r0 = a0 * b1 * u + a1 * b0 * u */
		|| !fp2_mul_u_montgomery(r0, a[0], b[1], p, mont, ctx)
		|| !fp2_mul_u_montgomery(t, a[1], b[0], p, mont, ctx)
		|| !fp2_add(r0, r0, t, p, ctx)

		/* r1 = a0 * b0 + a1 * b1 * u */
		|| !fp2_mul_montgomery(r1, a[0], b[0], p, mont, ctx)
		|| !fp2_mul_u_montgomery(t, a[1], b[1], p, mont, ctx)
		|| !fp2_add(r1, r1, t, p, ctx)

		|| !fp2_copy(r[0], r0)
		|| !fp2_copy(r[1], r1)) {
		fp2_cleanup(r0);
		fp2_cleanup(r1);
		fp2_cleanup(t);
		return 0;
	}
	fp2_cleanup(r0);
	fp2_cleanup(r1);
	fp2_cleanup(t);
	return 1;
}

static int fp4_sqr_montgomery(fp4_t r, const fp4_t a, const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	fp2_t r0, r1, t;
	fp2_init(r0, ctx);
	fp2_init(r1, ctx);
	if (!fp2_init(t, ctx)
		/* r0 = a0^2 + a1^2 * u */
		|| !fp2_sqr_montgomery(r0, a[0], p, mont, ctx)
		|| !fp2_sqr_u_montgomery(t, a[1], p, mont, ctx)
		|| !fp2_add(r0, r0, t, p, ctx)
		/* r1 = 2 * (a0 * a1) */
		|| !fp2_mul_montgomery(r1, a[0], a[1], p, mont, ctx)
		|| !fp2_dbl(r1, r1, p, ctx)
		|| !fp2_copy(r[0], r0)
		|| !fp2_copy(r[1], r1)) {
		fp2_cleanup(r0);
		fp2_cleanup(r1);
		fp2_cleanup(t);
		return 0;
	}
	fp2_cleanup(r0);
	fp2_cleanup(r1);
	fp2_cleanup(t);
	return 1;
}

static int fp4_sqr_v_montgomery(fp4_t r, const fp4_t a, const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	fp2_t r0, r1, t;
	fp2_init(r0, ctx);
	fp2_init(r1, ctx);
	if (!fp2_init(t, ctx)
		/* r0 = 2 * (a0 * a1) */
		|| !fp2_mul_u_montgomery(t, a[0], a[1], p, mont, ctx)
		|| !fp2_dbl(r0, t, p, ctx)

		/* r1 = a0^2 + a1^2 * u */
		|| !fp2_sqr_montgomery(r1, a[0], p, mont, ctx)
		|| !fp2_sqr_u_montgomery(t, a[1], p, mont, ctx)
		|| !fp2_add(r1, r1, t, p, ctx)
		|| !fp2_copy(r[0], r0)
		|| !fp2_copy(r[1], r1)) {
		fp2_cleanup(r0);
		fp2_cleanup(r1);
		fp2_cleanup(t);
		return 0;
	}
	fp2_cleanup(r0);
	fp2_cleanup(r1);
	fp2_cleanup(t);
	return 1;
}
static int fp4_mul(fp4_t r, const fp4_t a, const fp4_t b, const BIGNUM *p, BN_CTX *ctx)
{
	fp2_t r0, r1, t;

	fp2_init(r0, ctx);
	fp2_init(r1, ctx);

	if (!fp2_init(t, ctx)
		/* r0 = a0 * b0 + a1 * b1 * u */
		|| !fp2_mul(r0, a[0], b[0], p, ctx)
		|| !fp2_mul_u(t, a[1], b[1], p, ctx)
		|| !fp2_add(r0, r0, t, p, ctx)

		/* r[1] = a[0] * b[1] + a[1] * b[0] */
		|| !fp2_mul(r1, a[0], b[1], p, ctx)
		|| !fp2_mul(t, a[1], b[0], p, ctx)
		|| !fp2_add(r1, r1, t, p, ctx)

		|| !fp2_copy(r[0], r0)
		|| !fp2_copy(r[1], r1)) {
		fp2_cleanup(r0);
		fp2_cleanup(r1);
		fp2_cleanup(t);
		return 0;
	}

#ifdef TESTFP4

	fp4_t ta, tb, tr;
	fp4_init(ta, ctx);
	fp4_init(tb, ctx);
	fp4_init(tr, ctx);

	/* temp, remove me later */
	
	if(!mont){
		mont = BN_MONT_CTX_new();
		BN_MONT_CTX_set(mont, p, ctx);
	}

	fp4_to_montgomery(ta, a, mont, ctx);
	fp4_to_montgomery(tb, b, mont, ctx);
	fp4_mul_montgomery(tr, ta, tb, p, mont, ctx);
	fp4_from_montgomery(tr, tr, mont, ctx);

	if(!fp4_equ(r, tr) && !fp4_equ(r, a) && !fp4_equ(r, b))
	{
		// printf("mul\n\n");
		fp4_print(a);
		// printf("\n\n");
		fp4_print(r);
		// printf("\n\n");
		fp4_print(tr);
		// printf("\n\n");
	}

#endif

	fp2_cleanup(r0);
	fp2_cleanup(r1);
	fp2_cleanup(t);
	return 1;
}



static int fp4_mul_v(fp4_t r, const fp4_t a, const fp4_t b, const BIGNUM *p, BN_CTX *ctx)
{
	fp2_t r0, r1, t;
	fp2_init(r0, ctx);
	fp2_init(r1, ctx);
	if (!fp2_init(t, ctx)
		/* r0 = a0 * b1 * u + a1 * b0 * u */
		|| !fp2_mul_u(r0, a[0], b[1], p, ctx)
		|| !fp2_mul_u(t, a[1], b[0], p, ctx)
		|| !fp2_add(r0, r0, t, p, ctx)

		/* r1 = a0 * b0 + a1 * b1 * u */
		|| !fp2_mul(r1, a[0], b[0], p, ctx)
		|| !fp2_mul_u(t, a[1], b[1], p, ctx)
		|| !fp2_add(r1, r1, t, p, ctx)

		|| !fp2_copy(r[0], r0)
		|| !fp2_copy(r[1], r1)) {
		fp2_cleanup(r0);
		fp2_cleanup(r1);
		fp2_cleanup(t);
		return 0;
	}

#ifdef TESTFP4

	fp4_t ta, tb, tr;
	fp4_init(ta, ctx);
	fp4_init(tb, ctx);
	fp4_init(tr, ctx);

	/* temp, remove me later */
	
	if(!mont){
		mont = BN_MONT_CTX_new();
		BN_MONT_CTX_set(mont, p, ctx);
	}

	fp4_to_montgomery(ta, a, mont, ctx);
	fp4_to_montgomery(tb, b, mont, ctx);
	fp4_mul_v_montgomery(tr, ta, tb, p, mont, ctx);
	fp4_from_montgomery(tr, tr, mont, ctx);

	if(!fp4_equ(r, tr) && !fp4_equ(r, a) && !fp4_equ(r, b))
	{
		// printf("mul\n\n");
		fp4_print(a);
		// printf("\n\n");
		fp4_print(r);
		// printf("\n\n");
		fp4_print(tr);
		// printf("\n\n");
	}

#endif

	fp2_cleanup(r0);
	fp2_cleanup(r1);
	fp2_cleanup(t);
	return 1;
}

static int fp4_sqr(fp4_t r, const fp4_t a, const BIGNUM *p, BN_CTX *ctx)
{
	fp2_t r0, r1, t;
	fp2_init(r0, ctx);
	fp2_init(r1, ctx);
	if (!fp2_init(t, ctx)
		/* r0 = a0^2 + a1^2 * u */
		|| !fp2_sqr(r0, a[0], p, ctx)
		|| !fp2_sqr_u(t, a[1], p, ctx)
		|| !fp2_add(r0, r0, t, p, ctx)
		/* r1 = 2 * (a0 * a1) */
		|| !fp2_mul(r1, a[0], a[1], p, ctx)
		|| !fp2_dbl(r1, r1, p, ctx)
		|| !fp2_copy(r[0], r0)
		|| !fp2_copy(r[1], r1)) {
		fp2_cleanup(r0);
		fp2_cleanup(r1);
		fp2_cleanup(t);
		return 0;
	}

#ifdef TESTFP4

	fp4_t ta, tb, tr;
	fp4_init(ta, ctx);
	fp4_init(tb, ctx);
	fp4_init(tr, ctx);

	/* temp, remove me later */
	
	if(!mont){
		mont = BN_MONT_CTX_new();
		BN_MONT_CTX_set(mont, p, ctx);
	}

	fp4_to_montgomery(ta, a, mont, ctx);
	// fp4_to_montgomery(tb, b, mont, ctx);
	fp4_sqr_montgomery(tr, ta, p, mont, ctx);
	fp4_from_montgomery(tr, tr, mont, ctx);

	if(!fp4_equ(r, tr) && !fp4_equ(r, a))
	{
		// printf("mul\n\n");
		fp4_print(a);
		// printf("\n\n");
		fp4_print(r);
		// printf("\n\n");
		fp4_print(tr);
		// printf("\n\n");
	}

#endif

	fp2_cleanup(r0);
	fp2_cleanup(r1);
	fp2_cleanup(t);
	return 1;
}

static int fp4_sqr_v(fp4_t r, const fp4_t a, const BIGNUM *p, BN_CTX *ctx)
{
	fp2_t r0, r1, t;
	fp2_init(r0, ctx);
	fp2_init(r1, ctx);
	if (!fp2_init(t, ctx)
		/* r0 = 2 * (a0 * a1) */
		|| !fp2_mul_u(t, a[0], a[1], p, ctx)
		|| !fp2_dbl(r0, t, p, ctx)

		/* r1 = a0^2 + a1^2 * u */
		|| !fp2_sqr(r1, a[0], p, ctx)
		|| !fp2_sqr_u(t, a[1], p, ctx)
		|| !fp2_add(r1, r1, t, p, ctx)
		|| !fp2_copy(r[0], r0)
		|| !fp2_copy(r[1], r1)) {
		fp2_cleanup(r0);
		fp2_cleanup(r1);
		fp2_cleanup(t);
		return 0;
	}

#ifdef TESTFP4

	fp4_t ta, tb, tr;
	fp4_init(ta, ctx);
	fp4_init(tb, ctx);
	fp4_init(tr, ctx);

	/* temp, remove me later */
	
	if(!mont){
		mont = BN_MONT_CTX_new();
		BN_MONT_CTX_set(mont, p, ctx);
	}

	fp4_to_montgomery(ta, a, mont, ctx);
	// fp4_to_montgomery(tb, b, mont, ctx);
	fp4_sqr_v_montgomery(tr, ta, p, mont, ctx);
	fp4_from_montgomery(tr, tr, mont, ctx);

	if(!fp4_equ(r, tr) && !fp4_equ(r, a))
	{
		// printf("mul\n\n");
		fp4_print(a);
		// printf("\n\n");
		fp4_print(r);
		// printf("\n\n");
		fp4_print(tr);
		// printf("\n\n");
	}

#endif

	fp2_cleanup(r0);
	fp2_cleanup(r1);
	fp2_cleanup(t);
	return 1;
}
static int fp4_mul_num_montgomery(fp4_t r, const fp4_t a, const BIGNUM *n, const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	fp4_t tr;
	int ret = 0;

	if(!fp4_init(tr, ctx))
	{
		return 0;
	}


	if(!fp2_mul_num_montgomery(tr[0], a[0], n, p, mont, ctx)
		|| !fp2_mul_num_montgomery(tr[1], a[1], n, p, mont, ctx)
		|| !fp4_copy(r, tr))
	{
		goto end;
	}

	ret = 1;

end:
	fp4_cleanup(tr);
	return ret;
}





static int fp4_inv(fp4_t r, const fp4_t a, const BIGNUM *p, BN_CTX *ctx)
{
	fp2_t r0, r1, k;
	fp2_init(r0, ctx);
	fp2_init(r1, ctx);


	if (!fp2_init(k, ctx)
		/* k = (a1^2 * u - a0^2)^-1 */
		|| !fp2_sqr_u(k, a[1], p, ctx)
		|| !fp2_sqr(r0, a[0], p, ctx)
		|| !fp2_sub(k, k, r0, p, ctx)
		|| !fp2_inv(k, k, p, ctx)

		/* r0 = -(a0 * k) */
		|| !fp2_mul(r0, a[0], k, p, ctx)
		|| !fp2_neg(r0, r0, p, ctx)

		/* r1 = a1 * k */
		|| !fp2_mul(r1, a[1], k, p, ctx)

		|| !fp2_copy(r[0], r0)
		|| !fp2_copy(r[1], r1)) {
		fp2_cleanup(r0);
		fp2_cleanup(r1);
		fp2_cleanup(k);
		return 0;
	}
	fp2_cleanup(r0);
	fp2_cleanup(r1);
	fp2_cleanup(k);
	return 1;
}

#if SM9_TEST
static int fp4_test(const BIGNUM *p, BN_CTX *ctx)
{
	const char *_a[] = {
		"bec057c34cec656c05f236d9399cd00c64319632885d200f964e4591dd7ca77",
		"55a10432b9095a12c106019c97fa1ed2a484d84bbb750bcf6a378c3f85ba9d09",
		"9eb75c7b34e0259a59385602bd2210b844e6b9f6396443eed06dbd701b48a26c",
		"76f63f8fb8272b173eaf93cb79e57444c816ef099b3fb11057977d1f3f50eb8"};
	const char *_b[] = {
		"1dd8569e8b7d7a53a362334330ff5b4e3beeb180466cf7d268c157ff724c2de7",
		"48619106bcf6f34107318044223fa5ae3ec74573829f9873e4f06b41d0210762",
		"79fdcb2d33f115ef5405c62b509be15adc14cc82abbe6f89978ed0de987377c6",
		"71a8d1fd3d68cd689b9ed04872690c41858d98065b2535e70d1a6a8f2547f07e"};
	const char *add_a_b[] = {
		"29c45c1ac04c40aa63c156b0c499284f0231cae36ef2c9d362263c589023f85e",
		"9e02953976004d53c83781e0ba39c480e34c1dbf3e14a4434f27f78155dba46b",
		"627527a8662d9497d73a70de182f2acdff08f32dcaa7c49c828cf326d06ad4b5",
		"791835f638eb401a0f89c9852a076385d20f06f6f4d930f81293e261193cff36"};
	const char *dbl_a[] = {
		"17d80af8699d8cad80be46db27339a018c8632c6510ba401f2c9c8b23baf94ee",
		"ab4208657212b425820c03392ff43da54909b09776ea179ed46f187f0b753a12",
		"872eb8f6671ca442dc6d00b584b55a2b67dae0a1584d9901bb6bdfb8533fff5b",
		"edec7f1f704e562e7d5f2796f3cae889902dde13367f6220af2efa3e7ea1d70"};
	const char *sub_a_b[] = {
		"a453aeddabf4f2f4f3009b7a582938f7ac46fb2dfc93c90a761327818edce20d",
		"d3f732bfc1266d1b9d4815875ba792465bd92d838d5735b854720fdb59995a7",
		"24b9914e00ef0fab05328fd76c862f5d68d1ed738da5d46538deec9182d52aa6",
		"4c0691fbc0bd4c3aae4fd4443ac41247e8e66a355909b405ddcea86ab1fe63b7"};
	const char *neg_a[] = {
		"aa53fa83cdd4e09b15a487e261f4fa445baf79e7f1f51cdaec0ab6cec5797b06",
		"609efbcd499a4cdf14fda9b35d94a8727d6dbaff5f05e30c7b380ee85d96a874",
		"1788a384cdc381577ccb554d386cb68cdd0bd954e116aaed1501ddb7c808a311",
		"aed09c07072134406218b2133df07000d571245a80c6f3cadff62355ef5c36c5"};
	const char *mul_a_b[] = {
		"8e897a274c44e47c7db00d58bf08c020472e75f1e008a8a34975a6c947587f80",
		"e8b79955f768f30ab48aa1b12b305a71fd12e252f34345d7692d58adf908739",
		"a647307d347637d0525d62f9148d9bd7aabfb9c93ec03a7575404e5d4fa64310",
		"65cbf741cdf37a3459727a9fcd84b10cc8b1d4c1a3641556de11434b330daf04"};
	const char *mulv_a_b[] = {
		"a0e8117c6960597af922616050142c70b2817d12ee2db30a0ebcafb960872cf2",
		"a647307d347637d0525d62f9148d9bd7aabfb9c93ec03a7575404e5d4fa64310",
		"8e897a274c44e47c7db00d58bf08c020472e75f1e008a8a34975a6c947587f80",
		"e8b79955f768f30ab48aa1b12b305a71fd12e252f34345d7692d58adf908739"};
	const char *sqr_a[] = {
		"fb487bb1bee1c8d21956f8b5b7b1d93c5e7087b02666fc475f63b65cf5a2198",
		"3a4deaf2a26a4f42fdb3bd34ae1c866a2d1ae5f5d9739d66ec758a38661d7639",
		"a089b0d9a76cc56a2db2b56ab0df6e15f7a76ba8ad15e1f3b20accb2245bd827",
		"8ad9618cfbada9f4cb296b5f219267785bc4d9b4d3070048e5301972005bb37f"};
	const char *sqrv_a[] = {
		"56cd3ce60debf9fa15b47fe1a7f8bf998c5b732c8ee7dd26007f036bc5eb23fc",
		"a089b0d9a76cc56a2db2b56ab0df6e15f7a76ba8ad15e1f3b20accb2245bd827",
		"fb487bb1bee1c8d21956f8b5b7b1d93c5e7087b02666fc475f63b65cf5a2198",
		"3a4deaf2a26a4f42fdb3bd34ae1c866a2d1ae5f5d9739d66ec758a38661d7639"};
	const char *inv_a[] = {
		"7aa3d284401216d78e171627742b5a5dc3af41c15e112ceba1eb9e12ea3780cf",
		"99711ed85be3e353d43f87600a9f416b64e1778d92e6b3fc374bc94f59772f70",
		"8be97927776cbf6b7a162a5268df1d6a184ecd4ee56cc36273a7127ceabbebd4",
		"7b4b924e6c5e548d2c5467e6db40bf35858f690d312d35066821af199a81ff67"};
	const char *inv_1[] = {
		"1",
		"0",
		"0",
		"0"};
	const char *inv_u[] = {
		"0",
		"5b2000000151d378eb01d5a7fac763a290f949a58d3d776df2b7cd93f1a8a2be",
		"0",
		"0"};
	const char *inv_v[] = {
		"0",
		"0",
		"0",
		"5b2000000151d378eb01d5a7fac763a290f949a58d3d776df2b7cd93f1a8a2be"};

	fp4_t r, a, b;
	int ok;

	fp4_init(r, ctx);
	fp4_init(a, ctx);
	fp4_init(b, ctx);

	fp4_set_hex(a, _a);
	fp4_set_hex(b, _b);

	fp4_add(r, a, b, p, ctx);
	ok = fp4_equ_hex(r, add_a_b, ctx);
	// printf("fp4 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp4_dbl(r, a, p, ctx);
	ok = fp4_equ_hex(r, dbl_a, ctx);
	// printf("fp4 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp4_sub(r, a, b, p, ctx);
	ok = fp4_equ_hex(r, sub_a_b, ctx);
	// printf("fp4 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp4_neg(r, a, p, ctx);
	ok = fp4_equ_hex(r, neg_a, ctx);
	// printf("fp4 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp4_mul(r, a, b, p, ctx);
	ok = fp4_equ_hex(r, mul_a_b, ctx);
	// printf("fp4 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp4_mul_v(r, a, b, p, ctx);
	ok = fp4_equ_hex(r, mulv_a_b, ctx);
	// printf("fp4 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp4_sqr(r, a, p, ctx);
	ok = fp4_equ_hex(r, sqr_a, ctx);
	// printf("fp4 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp4_sqr_v(r, a, p, ctx);
	ok = fp4_equ_hex(r, sqrv_a, ctx);
	// printf("fp4 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp4_inv(r, a, p, ctx);
	ok = fp4_equ_hex(r, inv_a, ctx);
	// printf("fp4 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp4_set_one(r);
	fp4_inv(r, r, p, ctx);
	ok = fp4_equ_hex(r, inv_1, ctx);
	// printf("fp4 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp4_set_u(r);
	fp4_inv(r, r, p, ctx);
	ok = fp4_equ_hex(r, inv_u, ctx);
	// printf("fp4 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp4_set_v(r);
	fp4_inv(r, r, p, ctx);
	ok = fp4_equ_hex(r, inv_v, ctx);
	// printf("fp4 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	return 0;
}
#endif

int fp12_init(fp12_t a, BN_CTX *ctx)
{
	int r;
	r = fp4_init(a[0], ctx);
	r &= fp4_init(a[1], ctx);
	r &= fp4_init(a[2], ctx);
	if (!r) {
		fp4_cleanup(a[0]);
		fp4_cleanup(a[1]);
		fp4_cleanup(a[2]);
	}
	return r;
}

void fp12_cleanup(fp12_t a)
{
	fp4_cleanup(a[0]);
	fp4_cleanup(a[1]);
	fp4_cleanup(a[2]);
}

#if SM9_TEST
static void fp12_clear_cleanup(fp12_t a)
{
	fp4_clear_cleanup(a[0]);
	fp4_clear_cleanup(a[1]);
	fp4_clear_cleanup(a[2]);
}
#endif

int fp12_print_sm9(const fp12_t a)
{
	fp4_print(a[0]);
	fp4_print(a[1]);
	fp4_print(a[2]);
	return 1;
}

static int fp12_is_zero(const fp12_t a)
{
	return fp4_is_zero(a[0])
		&& fp4_is_zero(a[1])
		&& fp4_is_zero(a[2]);
}

static int fp12_is_one(const fp12_t a)
{
	return fp4_is_one(a[0])
		&& fp4_is_zero(a[1])
		&& fp4_is_zero(a[2]);
}

static int fp12_set_zero(fp12_t r)
{
	fp4_set_zero(r[0]);
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
	return 1;
}

static int fp12_set_one(fp12_t r)
{
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
	return fp4_set_one(r[0]);
}

static int fp12_copy(fp12_t r, const fp12_t a)
{
	return fp4_copy(r[0], a[0])
		&& fp4_copy(r[1], a[1])
		&& fp4_copy(r[2], a[2]);
}

#if SM9_TEST
static int fp12_set(fp12_t r, const fp4_t a0, const fp4_t a1, const fp4_t a2)
{
	return fp4_copy(r[0], a0)
		&& fp4_copy(r[1], a1)
		&& fp4_copy(r[2], a2);
}
#endif

static int fp12_set_hex(fp12_t r, const char *str[12])
{
	return fp4_set_hex(r[0], str)
		&& fp4_set_hex(r[1], str + 4)
		&& fp4_set_hex(r[2], str + 8);
}

#if SM9_TEST
static int fp12_set_fp4(fp12_t r, const fp4_t a)
{
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
	return fp4_copy(r[0], a);
}
#endif

static int fp12_set_fp2(fp12_t r, const fp2_t a)
{
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
	return fp4_set_fp2(r[0], a);
}

static int fp12_set_bn(fp12_t r, const BIGNUM *a)
{
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
	return fp4_set_bn(r[0], a);
}

#if SM9_TEST
static int fp12_set_word(fp12_t r, unsigned long a)
{
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
	return fp4_set_word(r[0], a);
}

static int fp12_set_u(fp12_t r)
{
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
	return fp4_set_u(r[0]);
}
#endif

static int fp12_set_v_montgomery(fp12_t r)
{
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
	return fp4_set_v_montgomery(r[0]);
}


static int fp12_set_v(fp12_t r)
{
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
	return fp4_set_v(r[0]);
}



#if SM9_TEST
static int fp12_set_w(fp12_t r)
{
	fp4_set_zero(r[0]);
	fp4_set_zero(r[2]);
	return fp4_set_one(r[1]);
}
#endif

static int fp12_set_w_sqr_montgomery(fp12_t r)
{
	fp4_set_zero(r[0]);
	fp4_set_zero(r[1]);
	return fp4_set_one_montgomery(r[2]);
}

static int fp12_set_w_sqr(fp12_t r)
{
	fp4_set_zero(r[0]);
	fp4_set_zero(r[1]);
	return fp4_set_one(r[2]);
}


static int fp12_set_w_inv(fp12_t r)
{
	fp4_set_zero(r[0]);
	fp4_set_zero(r[1]);
	return fp4_set_inv_unit(r[2]);
}

static int fp12_set_w_sqr_inv(fp12_t r)
{
	fp4_set_zero(r[0]);
	fp4_set_zero(r[2]);
	return fp4_set_inv_unit(r[1]);
}

static int fp12_set_v_inv(fp12_t r)
{
	fp4_set_zero(r[2]);
	fp4_set_zero(r[1]);
	return fp4_set_inv_unit(r[0]);
}

static int fp12_equ(const fp12_t a, const fp12_t b)
{
	return fp4_equ(a[0], b[0])
		&& fp4_equ(a[1], b[1])
		&& fp4_equ(a[2], b[2]);
}

#if SM9_TEST
static int fp12_equ_hex(const fp12_t a, const char *str[12], BN_CTX *ctx)
{
	fp12_t t;
	fp12_init(t, ctx);
	fp12_set_hex(t, str);
	return fp12_equ(a, t);
}
#endif

int fp12_to_bin(const fp12_t a, unsigned char to[384])
{
	return fp4_to_bin(a[2], to)
		&& fp4_to_bin(a[1], to + 128)
		&& fp4_to_bin(a[0], to + 256);
}

static int fp12_from_bin(fp4_t a, const unsigned char from[384])
{
	return fp4_from_bin(&a[2], from)
		&& fp4_from_bin(&a[1], from + 128)
		&& fp4_from_bin(&a[0], from + 256);
}

static int fp12_add(fp12_t r, const fp12_t a, const fp12_t b, const BIGNUM *p, BN_CTX *ctx)
{
	return fp4_add(r[0], a[0], b[0], p, ctx)
		&& fp4_add(r[1], a[1], b[1], p, ctx)
		&& fp4_add(r[2], a[2], b[2], p, ctx);
}

static int fp12_dbl(fp12_t r, const fp12_t a, const BIGNUM *p, BN_CTX *ctx)
{
	return fp4_dbl(r[0], a[0], p, ctx)
		&& fp4_dbl(r[1], a[1], p, ctx)
		&& fp4_dbl(r[2], a[2], p, ctx);
}

static int fp12_tri(fp12_t r, const fp12_t a, const BIGNUM *p, BN_CTX *ctx)
{
	fp12_t t;
	fp12_init(t, ctx);

	if (!fp12_dbl(t, a, p, ctx)
		|| !fp12_add(r, t, a, p, ctx)) {
		fp12_cleanup(t);
		return 0;
	}
	fp12_cleanup(t);
	return 1;
}

static int fp12_sub(fp12_t r, const fp12_t a, const fp12_t b, const BIGNUM *p, BN_CTX *ctx)
{
	return fp4_sub(r[0], a[0], b[0], p, ctx)
		&& fp4_sub(r[1], a[1], b[1], p, ctx)
		&& fp4_sub(r[2], a[2], b[2], p, ctx);
}

static int fp12_neg(fp12_t r, const fp12_t a, const BIGNUM *p, BN_CTX *ctx)
{
	return fp4_neg(r[0], a[0], p, ctx)
		&& fp4_neg(r[1], a[1], p, ctx)
		&& fp4_neg(r[2], a[2], p, ctx);
}

static int fp12_from_montgomery(fp12_t r, fp12_t a, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	return fp4_from_montgomery(r[0], a[0], mont, ctx)
			&& fp4_from_montgomery(r[1], a[1], mont, ctx)
			&& fp4_from_montgomery(r[2], a[2], mont, ctx);
}

static int fp12_to_montgomery(fp12_t r, fp12_t a, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	return fp4_to_montgomery(r[0], a[0], mont, ctx)
			&& fp4_to_montgomery(r[1], a[1], mont, ctx)
			&& fp4_to_montgomery(r[2], a[2], mont, ctx);
}


static int fp12_set_w_sqr_inv_montgomery(fp12_t r)
{
	fp4_set_zero(r[0]);
	fp4_set_zero(r[2]);
	fp4_set_inv_unit_montgomery(r[1]);
	return fp4_set_inv_unit_montgomery(r[1]);
}

static int fp12_set_v_inv_montgomery(fp12_t r)
{
	fp4_set_zero(r[2]);
	fp4_set_zero(r[1]);
	return fp4_set_inv_unit_montgomery(r[0]);
}


int fp12_mul_montgomery(fp12_t r, const fp12_t a, const fp12_t b, const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	fp4_t r0, r1, r2, t, t0, t1, t2;
	fp4_init(r0, ctx);
	fp4_init(r1, ctx);
	fp4_init(r2, ctx);

	if (!fp4_init(t, ctx)
		|| !fp4_init(t0, ctx)
		|| !fp4_init(t1, ctx)
		|| !fp4_init(t2, ctx)
		|| !fp4_mul_montgomery(t0, a[0], b[0], p, mont, ctx)
		|| !fp4_mul_montgomery(t1, a[1], b[1], p, mont, ctx)
		|| !fp4_mul_montgomery(t2, a[2], b[2], p, mont, ctx)

		/* r0 = a0 * b0 + a1 * b2 * v + a2 * b1 * v */
		|| !fp4_add(t, a[1], a[2], p, ctx)
		|| !fp4_add(r0, b[1], b[2], p, ctx)
		|| !fp4_mul_montgomery(r0, r0, t, p, mont, ctx)
		|| !fp4_sub(r0, r0, t1, p, ctx)
		|| !fp4_sub(r0, r0, t2, p, ctx)
		|| !fp4_mul_v_montgomery_123(r0, r0, p, ctx)
		|| !fp4_add(r0, r0, t0, p, ctx)


		/* r1 = a0*b1 + a1*b0 + a2*b2*v */
		|| !fp4_add(t, a[1], a[0], p, ctx)
		|| !fp4_add(r1, b[1], b[0], p, ctx)
		|| !fp4_mul_montgomery(r1, r1, t, p, mont, ctx)
		|| !fp4_sub(r1, r1, t1, p, ctx)
		|| !fp4_sub(r1, r1, t0, p, ctx)
		|| !fp4_mul_v_montgomery_123(t, t2, p, ctx)
		|| !fp4_add(r1, r1, t, p, ctx)

		/* r2 = a0*b2 + a1*b1 + a2*b0 */
		|| !fp4_add(t, a[2], a[0], p, ctx)
		|| !fp4_add(r2, b[2], b[0], p, ctx)
		|| !fp4_mul_montgomery(r2, r2, t, p, mont, ctx)
		|| !fp4_sub(r2, r2, t2, p, ctx)
		|| !fp4_sub(r2, r2, t0, p, ctx)
		|| !fp4_add(r2, r2, t1, p, ctx)

		|| !fp4_copy(r[0], r0)
		|| !fp4_copy(r[1], r1)
		|| !fp4_copy(r[2], r2)) {

		fp4_cleanup(r0);
		fp4_cleanup(r1);
		fp4_cleanup(r2);
		fp4_cleanup(t);
		fp4_cleanup(t1);
		fp4_cleanup(t2);
		fp4_cleanup(t0);
		return 0;
	}
	fp4_cleanup(r0);
	fp4_cleanup(r1);
	fp4_cleanup(r2);
	fp4_cleanup(t);
	return 1;
}

int fp12_mul_num_montgomery(fp12_t r, const fp12_t a, const BIGNUM *n, const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	fp12_t tr;
	int ret = 0;
	if (!fp12_init(tr, ctx))
	{
		return 0;
	}

	if(!fp4_mul_num_montgomery(tr[0], a[0], n, p, mont, ctx)
	 	|| !fp4_mul_num_montgomery(tr[1], a[1], n, p, mont, ctx)
		|| !fp4_mul_num_montgomery(tr[2], a[2], n, p, mont, ctx)
		|| !fp12_copy(r, tr))
	{
		goto end;
	}

	ret = 1;
end:
	fp12_cleanup(tr);
	return ret;

}

int fp12_mul_fp2_montgomery(fp12_t r, const fp12_t a, const fp2_t n, const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	fp12_t tr;
	int ret = 0;
	if (!fp12_init(tr, ctx))
	{
		return 0;
	}

	if(!fp2_mul_montgomery(tr[0][0], a[0][0], n, p, mont, ctx)
		|| !fp2_mul_montgomery(tr[0][1], a[0][1], n, p, mont, ctx)
		|| !fp2_mul_montgomery(tr[1][0], a[1][0], n, p, mont, ctx)
		|| !fp2_mul_montgomery(tr[1][1], a[1][1], n, p, mont, ctx)
		|| !fp2_mul_montgomery(tr[2][0], a[2][0], n, p, mont, ctx)
		|| !fp2_mul_montgomery(tr[2][1], a[2][1], n, p, mont, ctx)
		|| !fp12_copy(r, tr))
	{
		goto end;
	}

	ret = 1;
end:
	fp12_cleanup(tr);
	return ret;

}

/**
 * r = a * w ^ 3 
 */
int fp12_mul_w_pow_3(fp12_t r, const fp12_t a, const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	fp12_t tr;
	BIGNUM *t = BN_new();
	int ret = 0;
	int i;

	if (!fp12_init(tr, ctx))
	{
		return 0;
	}

	for (i=0; i<3; i++)
	{
		if(!BN_copy(tr[i][1][1], a[i][0][1])
			|| !BN_copy(tr[i][1][0], a[i][0][0])
			|| !BN_copy(tr[i][0][1], a[i][1][0])
			|| !BN_mod_add_quick(t, a[i][1][1], a[i][1][1], p)
			|| !BN_mod_sub_quick(tr[i][0][0], tr[i][0][0], t, p))
		{
			goto end;
		}
	}

	if(!fp12_copy(r, tr))
	{
		goto end;
	}


	ret = 1;
end:
	fp12_cleanup(tr);
	BN_free(t);
	t = NULL;
	return ret;
}

int fp12_mul_w_pow_neg_2(fp12_t r, const fp12_t a, const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	// char hex[] = "3640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D";
	fp12_t tr;
	BIGNUM *t = BN_new();
	const BIGNUM *scalar = SM9_get0_inv_neg_2_montgomery();
	int ret = 0;
	int i;

	if (!fp12_init(tr, ctx))
	{
		return 0;
	}

	if(!fp4_copy(tr[0], a[2])
		|| !fp2_copy(tr[1][0], a[0][1])
		|| !fp2_copy(tr[2][0], a[1][1])
		|| !BN_copy(tr[1][1][0], a[0][0][1])
		|| !BN_copy(tr[2][1][0], a[1][0][1])
		|| !BN_mod_mul_montgomery(tr[1][1][1], a[0][0][0], scalar, mont, ctx)
		|| !BN_mod_mul_montgomery(tr[2][1][1], a[1][0][0], scalar, mont, ctx))
	{
		goto end;
	}

	if(!fp12_copy(r, tr))
	{
		goto end;
	}


	ret = 1;
end:
	fp12_cleanup(tr);
	BN_free(t);
	t = NULL;
	return ret;
}
/**
 * r = a * w ^ -3 
 */
int fp12_mul_w_pow_neg_3(fp12_t r, const fp12_t a, const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	// char hex[] = "3640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D";
	fp12_t tr;
	BIGNUM *t = BN_new();
	BIGNUM *scalar = SM9_get0_inv_neg_2_montgomery();
	int ret = 0;
	int i;

	if (!fp12_init(tr, ctx))
	{
		return 0;
	}

	for (i=0; i<3; i++)
	{
		if(!BN_copy(tr[i][0][0], a[i][1][0])
			|| !BN_copy(tr[i][0][1], a[i][1][1])
			|| !BN_copy(tr[i][1][0], a[i][0][1])
			|| !BN_mod_mul_montgomery(tr[i][1][1], a[i][0][0], scalar, mont, ctx))
		{
			goto end;
		}
	}

	if(!fp12_copy(r, tr))
	{
		goto end;
	}


	ret = 1;
end:
	fp12_cleanup(tr);
	BN_free(t);
	t = NULL;
	return ret;
}

int fp12_mul(fp12_t r, const fp12_t a, const fp12_t b, const BIGNUM *p, BN_CTX *ctx)
{
	fp4_t r0, r1, r2, t;
	fp4_init(r0, ctx);
	fp4_init(r1, ctx);
	fp4_init(r2, ctx);

	if (!fp4_init(t, ctx)
		/* r0 = a0 * b0 + a1 * b2 * v + a2 * b1 * v */
		|| !fp4_mul(r0, a[0], b[0], p, ctx)
		|| !fp4_mul_v(t, a[1], b[2], p, ctx)
		|| !fp4_add(r0, r0, t, p, ctx)
		|| !fp4_mul_v(t, a[2], b[1], p, ctx)
		|| !fp4_add(r0, r0, t, p, ctx)

		/* r1 = a0*b1 + a1*b0 + a2*b2*v */
		|| !fp4_mul(r1, a[0], b[1], p, ctx)
		|| !fp4_mul(t, a[1], b[0], p, ctx)
		|| !fp4_add(r1, r1, t, p, ctx)
		|| !fp4_mul_v(t, a[2], b[2], p, ctx)
		|| !fp4_add(r1, r1, t, p, ctx)

		/* r2 = a0*b2 + a1*b1 + a2*b0 */
		|| !fp4_mul(r2, a[0], b[2], p, ctx)
		|| !fp4_mul(t, a[1], b[1], p, ctx)
		|| !fp4_add(r2, r2, t, p, ctx)
		|| !fp4_mul(t, a[2], b[0], p, ctx)
		|| !fp4_add(r2, r2, t, p, ctx)

		|| !fp4_copy(r[0], r0)
		|| !fp4_copy(r[1], r1)
		|| !fp4_copy(r[2], r2)) {

		fp4_cleanup(r0);
		fp4_cleanup(r1);
		fp4_cleanup(r2);
		fp4_cleanup(t);
		return 0;
	}
	fp4_cleanup(r0);
	fp4_cleanup(r1);
	fp4_cleanup(r2);
	fp4_cleanup(t);
	return 1;
}

static int fp12_sqr_montgomery(fp12_t r, const fp12_t a, const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	fp4_t r0, r1, r2, t;
	fp4_init(r0, ctx);
	fp4_init(r1, ctx);
	fp4_init(r2, ctx);
	if (!(fp4_init(t, ctx))
		/* r0 = a0^2 + 2*a1*a2*v */
		|| !fp4_sqr_montgomery(r0, a[0], p, mont, ctx)
		|| !fp4_mul_v_montgomery(t, a[1], a[2], p, mont, ctx)
		|| !fp4_dbl(t, t, p, ctx)
		|| !fp4_add(r0, r0, t, p, ctx)

		/* r1 = 2*a0*a1 + a^2 * v */
		|| !fp4_mul_montgomery(r1, a[0], a[1], p, mont, ctx)
		|| !fp4_dbl(r1, r1, p, ctx)
		|| !fp4_sqr_v_montgomery(t, a[2], p, mont, ctx)
		|| !fp4_add(r1, r1, t, p, ctx)

		/* r2 = 2*a0*a2 + a1^2*/
		|| !fp4_mul_montgomery(r2, a[0], a[2], p, mont, ctx)
		|| !fp4_dbl(r2, r2, p, ctx)
		|| !fp4_sqr_montgomery(t, a[1], p, mont, ctx)
		|| !fp4_add(r2, r2, t, p, ctx)

		|| !fp4_copy(r[0], r0)
		|| !fp4_copy(r[1], r1)
		|| !fp4_copy(r[2], r2)) {

		fp4_cleanup(r0);
		fp4_cleanup(r1);
		fp4_cleanup(r2);
		fp4_cleanup(t);
		return 0;
	}
	fp4_cleanup(r0);
	fp4_cleanup(r1);
	fp4_cleanup(r2);
	fp4_cleanup(t);
	return 1;
}
static int fp12_sqr(fp12_t r, const fp12_t a, const BIGNUM *p, BN_CTX *ctx)
{
	fp4_t r0, r1, r2, t;
	fp4_init(r0, ctx);
	fp4_init(r1, ctx);
	fp4_init(r2, ctx);
	if (!(fp4_init(t, ctx))
		/* r0 = a0^2 + 2*a1*a2*v */
		|| !fp4_sqr(r0, a[0], p, ctx)
		|| !fp4_mul_v(t, a[1], a[2], p, ctx)
		|| !fp4_dbl(t, t, p, ctx)
		|| !fp4_add(r0, r0, t, p, ctx)

		/* r1 = 2*a0*a1 + a^2 * v */
		|| !fp4_mul(r1, a[0], a[1], p, ctx)
		|| !fp4_dbl(r1, r1, p, ctx)
		|| !fp4_sqr_v(t, a[2], p, ctx)
		|| !fp4_add(r1, r1, t, p, ctx)

		/* r2 = 2*a0*a2 + a1^2*/
		|| !fp4_mul(r2, a[0], a[2], p, ctx)
		|| !fp4_dbl(r2, r2, p, ctx)
		|| !fp4_sqr(t, a[1], p, ctx)
		|| !fp4_add(r2, r2, t, p, ctx)

		|| !fp4_copy(r[0], r0)
		|| !fp4_copy(r[1], r1)
		|| !fp4_copy(r[2], r2)) {

		fp4_cleanup(r0);
		fp4_cleanup(r1);
		fp4_cleanup(r2);
		fp4_cleanup(t);
		return 0;
	}
	fp4_cleanup(r0);
	fp4_cleanup(r1);
	fp4_cleanup(r2);
	fp4_cleanup(t);
	return 1;
}

static int fp12_sqr_montgomery_2(fp12_t r, const fp12_t a, int ind/*0 except for a[ind] and a[ind+6]*/, 
									const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	int ret = 0;
	int srci = ind%3, srcj = ind/3;
	int dest = ind*2;
	int desti = (dest)%3, destj = (dest%6)/3;
	int is_exchange = dest >= 6;

	fp2_t tr;
	BIGNUM *t = BN_new();
	
	if(is_exchange)
	{
		if (!(fp2_init(tr, ctx))
			|| !fp2_sqr_montgomery(tr, a[srci][srcj], p, mont, ctx)
			|| !fp12_set_zero(r)
			|| !BN_copy(r[desti][destj][1], tr[0])
			|| !BN_mod_sub_quick(tr[0], p, tr[1], p)
			|| !BN_mod_add_quick(tr[1], tr[0], tr[0], p)
			|| !BN_copy(r[desti][destj][0], tr[1])) {

				goto end;
		}
	}
	else 
	{
		if (!(fp2_init(tr, ctx))
			|| !fp12_set_zero(r)
			|| !fp2_sqr_montgomery(tr, a[srci][srcj], p, mont, ctx)
			|| !fp2_copy(r[desti][destj], tr)) {

				goto end;
		}
	}

	ret = 1;

end:

	fp2_cleanup(tr);
	BN_free(t);
	t = NULL;
	return ret;
}

static int fp12_inv(fp12_t r, const fp12_t a, const BIGNUM *p, BN_CTX *ctx)
{
	if (fp4_is_zero(a[2])) {
		fp4_t k;
		fp4_t t;
		if (!fp4_init(t, ctx)) {
			return 0;
		}

		fp4_t r0, r1, r2;
		fp4_init(r0, ctx);
		fp4_init(r1, ctx);
		fp4_init(r2, ctx);

		if (!(fp4_init(k, ctx))
			/* k = (a0^3 + a1^3 * v)^-1 */
			|| !fp4_sqr(k, a[0], p, ctx)
			|| !fp4_mul(k, k, a[0], p, ctx)
			|| !fp4_sqr_v(t, a[1], p, ctx)
			|| !fp4_mul(t, t, a[1], p, ctx)
			|| !fp4_add(k, k, t, p, ctx)
			|| !fp4_inv(k, k, p, ctx)

			/* r2 = a1^2 * k */
			|| !fp4_sqr(r[2], a[1], p, ctx)
			|| !fp4_mul(r[2], r[2], k, p, ctx)

			/* r1 = -(a0 * a1 * k) */
			|| !fp4_mul(r[1], a[0], a[1], p, ctx)
			|| !fp4_mul(r[1], r[1], k, p, ctx)
			|| !fp4_neg(r[1], r[1], p, ctx)

			/* r0 = a0^2 * k */
			|| !fp4_sqr(r[0], a[0], p, ctx)
			|| !fp4_mul(r[0], r[0], k, p, ctx)

			) {

			fp4_cleanup(k);
			fp4_cleanup(t);
			return 0;
		}
		fp4_cleanup(k);
		fp4_cleanup(t);

	} else {

		fp4_t t0, t1, t2, t3;

		if (!(fp4_init(t0, ctx))
			|| !(fp4_init(t1, ctx)) //FIXME
			|| !(fp4_init(t2, ctx))
			|| !(fp4_init(t3, ctx))

			/* t0 = a1^2 - a0 * a2 */
			|| !fp4_sqr(t0, a[1], p, ctx)
			|| !fp4_mul(t1, a[0], a[2], p, ctx)
			|| !fp4_sub(t0, t0, t1, p, ctx)

			/* t1 = a0 * a1 - a2^2 * v */
			|| !fp4_mul(t1, a[0], a[1], p, ctx)
			|| !fp4_sqr_v(t2, a[2], p, ctx)
			|| !fp4_sub(t1, t1, t2, p, ctx)

			/* t2 = a0^2 - a1 * a2 * v */
			|| !fp4_sqr(t2, a[0], p, ctx)
			|| !fp4_mul_v(t3, a[1], a[2], p, ctx)
			|| !fp4_sub(t2, t2, t3, p, ctx)

			/* t3 = a2 * (t1^2 - t0 * t2)^-1 */
			|| !fp4_sqr(t3, t1, p, ctx)
			|| !fp4_mul(r[0], t0, t2, p, ctx)
			|| !fp4_sub(t3, t3, r[0], p, ctx)
			|| !fp4_inv(t3, t3, p, ctx)
			|| !fp4_mul(t3, a[2], t3, p, ctx)

			/* r0 = t2 * t3 */
			|| !fp4_mul(r[0], t2, t3, p, ctx)

			/* r1 = -(t1 * t3) */
			|| !fp4_mul(r[1], t1, t3, p, ctx)
			|| !fp4_neg(r[1], r[1], p, ctx)

			/* r2 = t0 * t3 */
			|| !fp4_mul(r[2], t0, t3, p, ctx)
			) {
			fp4_cleanup(t0);
			fp4_cleanup(t1);
			fp4_cleanup(t2);
			fp4_cleanup(t3);
			return 0;
		}

		fp4_cleanup(t0);
		fp4_cleanup(t1);
		fp4_cleanup(t2);
		fp4_cleanup(t3);
	}

	return 1;
}


int fp12_pow_montgomery(fp12_t r, const fp12_t a, const BIGNUM *k, const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	int n, i;
	fp12_t t;

	fp12_init(t, ctx);

	if (BN_is_zero(k)) {
		return fp12_set_one(r);
	}

	n = BN_num_bits(k);
	if (n < 1 || n > 256 * 12) {
		return 0;
	}

	if (!fp12_copy(t, a)) {
		return 0;
	}
	for (i = n - 2; i >= 0; i--) {
		if (!fp12_sqr_montgomery(t, t, p, mont, ctx)) {
			return 0;
		}
		if (BN_is_bit_set(k, i)) {
			if (!fp12_mul_montgomery(t, t, a, p, mont, ctx)) {
				return 0;
			}
		}
	}

	fp12_copy(r, t);

	fp12_cleanup(t);
	return 1;
}

int fp12_fast_expo_p_montgomery(fp12_t r, const fp12_t a, const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{

	int n, i;
	fp12_t t;

	fp12_init(t, ctx);
	BIGNUM *tmp = NULL;

	BN_copy(t[0][0][0], a[0][0][0]);
	BN_sub(t[0][0][1], p, a[0][0][1]);

	BN_hex2bn(&tmp, exp_montgomery[3]);
	BN_mod_mul_montgomery(t[0][1][0], a[0][1][0], tmp, mont, ctx);
	BN_clear_free(tmp);
	tmp = NULL;
	BN_hex2bn(&tmp, exp_montgomery[9]);
	BN_mod_mul_montgomery(t[0][1][1], a[0][1][1], tmp, mont, ctx);
	BN_clear_free(tmp);
	tmp = NULL;

	BN_hex2bn(&tmp, exp_montgomery[1]);
	BN_mod_mul_montgomery(t[1][0][0], a[1][0][0], tmp, mont, ctx);
	BN_clear_free(tmp);
	tmp = NULL;
	BN_hex2bn(&tmp, exp_montgomery[7]);
	BN_mod_mul_montgomery(t[1][0][1], a[1][0][1], tmp, mont, ctx);
	BN_clear_free(tmp);
	tmp = NULL;

	BN_hex2bn(&tmp, exp_montgomery[4]);
	BN_mod_mul_montgomery(t[1][1][0], a[1][1][0], tmp, mont, ctx);
	BN_clear_free(tmp);
	tmp = NULL;
	BN_hex2bn(&tmp, exp_montgomery[10]);
	BN_mod_mul_montgomery(t[1][1][1], a[1][1][1], tmp, mont, ctx);
	BN_clear_free(tmp);
	tmp = NULL;

	BN_hex2bn(&tmp, exp_montgomery[2]);
	BN_mod_mul_montgomery(t[2][0][0], a[2][0][0], tmp, mont, ctx);
	BN_clear_free(tmp);
	tmp = NULL;
	BN_hex2bn(&tmp, exp_montgomery[8]);
	BN_mod_mul_montgomery(t[2][0][1], a[2][0][1], tmp, mont, ctx);
	BN_clear_free(tmp);
	tmp = NULL;

	BN_hex2bn(&tmp, exp_montgomery[5]);
	BN_mod_mul_montgomery(t[2][1][0], a[2][1][0], tmp, mont, ctx);
	BN_clear_free(tmp);
	tmp = NULL;
	BN_hex2bn(&tmp, exp_montgomery[11]);
	BN_mod_mul_montgomery(t[2][1][1], a[2][1][1], tmp, mont, ctx);
	BN_clear_free(tmp);
	tmp = NULL;

	fp12_copy(r, t);

	fp12_cleanup(t);
	return 1;
}

int fp12_fast_expo_p(fp12_t r, const fp12_t a, const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	int n, i;
	fp12_t t;

	fp12_init(t, ctx);

	BN_from_montgomery(t[0][0][0], a[0][0][0], mont, ctx);
	
	BN_sub(t[0][0][1], p, a[0][0][1]);
	BN_from_montgomery(t[0][0][1], t[0][0][1], mont, ctx);

	BN_mod_mul_montgomery(t[0][1][0], a[0][1][0], SM9_get0_fast_final_expo_pto3(), mont, ctx);
	BN_mod_mul_montgomery(t[0][1][1], a[0][1][1], SM9_get0_fast_final_expo_pto9(), mont, ctx);

	BN_mod_mul_montgomery(t[1][0][0], a[1][0][0], SM9_get0_fast_final_expo_pto1(), mont, ctx);
	BN_mod_mul_montgomery(t[1][0][1], a[1][0][1], SM9_get0_fast_final_expo_pto7(), mont, ctx);

	BN_mod_mul_montgomery(t[1][1][0], a[1][1][0], SM9_get0_fast_final_expo_pto4(), mont, ctx);
	BN_mod_mul_montgomery(t[1][1][1], a[1][1][1], SM9_get0_fast_final_expo_pto10(), mont, ctx);

	BN_mod_mul_montgomery(t[2][0][0], a[2][0][0], SM9_get0_fast_final_expo_pto2(), mont, ctx);
	BN_mod_mul_montgomery(t[2][0][1], a[2][0][1], SM9_get0_fast_final_expo_pto8(), mont, ctx);

	BN_mod_mul_montgomery(t[2][1][0], a[2][1][0], SM9_get0_fast_final_expo_pto5(), mont, ctx);
	BN_mod_mul_montgomery(t[2][1][1], a[2][1][1], SM9_get0_fast_final_expo_pto11(), mont, ctx);

	fp12_copy(r, t);

	fp12_cleanup(t);
	return 1;
}



int fp12_pow(fp12_t r, const fp12_t a, const BIGNUM *k, const BIGNUM *p, BN_CTX *ctx)
{
	int n, i;
	fp12_t t;
	fp12_t ta;

	fp12_init(t, ctx);
	fp12_init(ta, ctx);

	if(!mont)
	{
		mont = BN_MONT_CTX_new();
		BN_MONT_CTX_set(mont, p, ctx);
	}

	fp12_to_montgomery(ta, a, mont, ctx);
	fp12_pow_montgomery(t, ta, k, p, mont, ctx);
	fp12_from_montgomery(r, t, mont, ctx);

	fp12_cleanup(ta);
	fp12_cleanup(t);
	return 1;
}

static int fp12_fast_expo_p6(fp12_t r, const fp12_t a, const BIGNUM *p, BN_CTX *ctx)
{
	return fp2_copy(r[0][0], a[0][0])
		&& fp2_neg (r[0][1], a[0][1], p, ctx)
		&& fp2_neg (r[1][0], a[1][0], p, ctx)
		&& fp2_copy(r[1][1], a[1][1])
		&& fp2_copy(r[2][0], a[2][0])
		&& fp2_neg (r[2][1], a[2][1], p, ctx);
}

static int fp12_fast_expo_p2(fp12_t r, const fp12_t a, const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	const BIGNUM *pw20;
	const BIGNUM *pw21;
	const BIGNUM *pw22;
	const BIGNUM *pw23;
	pw20 = SM9_get0_fast_final_exponent_p20();
	pw21 = SM9_get0_fast_final_exponent_p21();
	pw22 = SM9_get0_fast_final_exponent_p22();
	pw23 = SM9_get0_fast_final_exponent_p23();

	if(!fp2_copy(r[0][0], a[0][0])
		|| !fp2_from_montgomery(r[0][0], r[0][0], mont, ctx)
		|| !fp2_neg (r[0][1], a[0][1], p, ctx)
		|| !fp2_from_montgomery(r[0][1], r[0][1], mont, ctx)
		|| !fp2_mul_num_montgomery(r[1][0], a[1][0], pw20, p, mont, ctx)
		|| !fp2_mul_num_montgomery(r[1][1], a[1][1], pw21, p, mont, ctx)
		|| !fp2_mul_num_montgomery(r[2][0], a[2][0], pw22, p, mont, ctx)
		|| !fp2_mul_num_montgomery(r[2][1], a[2][1], pw23, p, mont, ctx)) {

		return 0;
	}
	return 1;
}

static int fp12_fast_expo_p3(fp12_t r, const fp12_t a, const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	const BIGNUM *pw33;
	const BIGNUM *pw39;
	pw33 = SM9_get0_fast_final_expo_pto3();
	pw39 = SM9_get0_fast_final_expo_pto9();

	if(!BN_from_montgomery(r[0][0][0], a[0][0][0], mont, ctx)
		|| !BN_sub(r[0][0][1], p, a[0][0][1]) || !BN_from_montgomery(r[0][0][1], r[0][0][1], mont, ctx)	
		|| !BN_mod_mul_montgomery(r[0][1][0], pw39, a[0][1][0], mont, ctx)
		|| !BN_mod_mul_montgomery(r[0][1][1], pw33, a[0][1][1], mont, ctx)
		|| !BN_mod_mul_montgomery(r[1][0][0], pw33, a[1][0][0], mont, ctx)
		|| !BN_mod_mul_montgomery(r[1][0][1], pw39, a[1][0][1], mont, ctx)
		|| !BN_from_montgomery(r[1][1][0], a[1][1][0], mont, ctx)
		|| !BN_sub(r[1][1][1], p, a[1][1][1]) || !BN_from_montgomery(r[1][1][1], r[1][1][1], mont, ctx)	
		|| !BN_sub(r[2][0][0], p, a[2][0][0]) || !BN_from_montgomery(r[2][0][0], r[2][0][0], mont, ctx)	
		|| !BN_from_montgomery(r[2][0][1], a[2][0][1], mont, ctx)
		|| !BN_mod_mul_montgomery(r[2][1][0], pw33, a[2][1][0], mont, ctx)
		|| !BN_mod_mul_montgomery(r[2][1][1], pw39, a[2][1][1], mont, ctx)
		) {

		return 0;
	}
	return 1;
}


int point_init(point_t *P, BN_CTX *ctx)
{
	int r;
	r = fp2_init(P->X, ctx);
	r &= fp2_init(P->Y, ctx);
	r &= fp2_init(P->Z, ctx);
	r &= fp2_set_one(P->Y);
	if (!r) {
		fp2_cleanup(P->X);
		fp2_cleanup(P->Y);
		fp2_cleanup(P->Z);
		return 0;
	}
	fp2_set_zero(P->X);
	fp2_set_zero(P->Z);
	return 1;
}

void point_cleanup(point_t *P)
{
	fp2_cleanup(P->X);
	fp2_cleanup(P->Y);
	fp2_cleanup(P->Z);
}

void point_print_sm9(const point_t *P)
{
	// printf(" X1: %s\n", BN_bn2hex((P->X)[1]));
	// printf(" X0: %s\n", BN_bn2hex((P->X)[0]));
	// printf(" Y1: %s\n", BN_bn2hex((P->Y)[1]));
	// printf(" Y0: %s\n", BN_bn2hex((P->Y)[0]));
	// printf(" Z1: %s\n", BN_bn2hex((P->Z)[1]));
	// printf(" Z0: %s\n", BN_bn2hex((P->Z)[0]));
	// printf("\n");
}

int point_copy_sm9(point_t *R, const point_t *P)
{
	return fp2_copy(R->X, P->X)
		&& fp2_copy(R->Y, P->Y)
		&& fp2_copy(R->Z, P->Z);
}

static int point_set_to_infinity(point_t *P)
{
	fp2_set_zero(P->X);
	fp2_set_zero(P->Z);
	return fp2_set_one(P->Y);
}

static int point_is_at_infinity(const point_t *P)
{
	return fp2_is_zero(P->X)
		&& fp2_is_one(P->Y)
		&& fp2_is_zero(P->Z);
}

int point_equ_sm9(const point_t *P, const point_t *Q)
{
	return fp2_equ(P->X, Q->X)
		&& fp2_equ(P->Y, Q->Y)
		&& fp2_equ(P->Z, Q->Z);
}

static int point_from_montgomery(point_t *R, const point_t *P, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	if(point_is_at_infinity(P))
	{
		return point_copy_sm9(R, P);
	}

	return fp2_from_montgomery(R->X, P->X, mont, ctx)
			&& fp2_from_montgomery(R->Y, P->Y, mont, ctx)
			&& fp2_from_montgomery(R->Z, P->Z, mont, ctx);
}

static int point_to_montgomery(point_t *R, const point_t *P, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	if(point_is_at_infinity(P))
	{
		return point_copy_sm9(R, P);
	}

	return fp2_to_montgomery(R->X, P->X, mont, ctx)
			&& fp2_to_montgomery(R->Y, P->Y, mont, ctx)
			&& fp2_to_montgomery(R->Z, P->Z, mont, ctx);
}


int point_set_affine_coordinates_montgomery(point_t *P, const fp2_t x, const fp2_t y)
{
	return fp2_copy(P->X, x)
		&& fp2_copy(P->Y, y)
		&& fp2_set_one_montgomery(P->Z);
}


int point_set_affine_coordinates(point_t *P, const fp2_t x, const fp2_t y)
{
	return fp2_copy(P->X, x)
		&& fp2_copy(P->Y, y)
		&& fp2_set_one(P->Z);
}

int point_set_affine_coordinates_hex(point_t *P, const char *str[4])
{
	fp2_set_hex(P->X, str);
	fp2_set_hex(P->Y, str + 2);
	fp2_set_one(P->Z);
	return 1;
}

static int point_equ_hex(const point_t *P, const char *str[4], BN_CTX *ctx)
{
	point_t T;
	point_init(&T, ctx);
	point_set_affine_coordinates_hex(&T, str);
	return point_equ_sm9(P, &T);
}

int point_set_affine_coordinates_bignums(point_t *P,
	const BIGNUM *x0, const BIGNUM *x1, const BIGNUM *y0, const BIGNUM *y1)
{
	return fp2_set(P->X, x0, x1)
		&& fp2_set(P->Y, y0, y1)
		&& fp2_set_one(P->Z);
}

static int point_get_affine_coordinates_affine(const point_t *P, fp2_t x, fp2_t y, const BIGNUM* p, BN_CTX *ctx)
{
	/**
	 * x = X/Z^2 
	 * y = Y/Z^3
	*/
	int r;
	fp2_t w, w2, w3, tx, ty;

	r = 1;
	r &= fp2_init(tx, ctx);
	r &= fp2_init(ty, ctx);
	r &= fp2_init(w, ctx);
	r &= fp2_init(w2, ctx);
	r &= fp2_init(w3, ctx);

	if(!r)
	{
		goto end;
	}

	r = 0;

	if(!fp2_inv(w, P->Z, p, ctx)
		|| !fp2_sqr(w2, w, p, ctx)
		|| !fp2_mul(tx, P->X, w2, p, ctx)
		|| !fp2_mul(w3, w, w2, p, ctx)
		|| !fp2_mul(ty, P->Y, w3, p, ctx))
	{
		goto end;
	}

	r = fp2_copy(x, tx) && fp2_copy(y, ty);

end:
	return r;
}

int point_get_affine_coordinates_montgomery(const point_t *P, fp2_t x, fp2_t y)
{

	return fp2_copy(x, P->X)
		&& fp2_copy(y, P->Y);
}

int point_get_affine_coordinates(const point_t *P, fp2_t x, fp2_t y)
{
	return fp2_copy(x, P->X)
		&& fp2_copy(y, P->Y)
		&& fp2_is_one(P->Z);
}

static int point_get_ext_affine_coordinates_affine_montgomery(const point_t *P, fp12_t x, fp12_t y, fp12_t z, const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	int r;
	fp2_t xP;
	fp2_t yP;
	fp2_t zP;

	r = 1;
	r &= fp2_init(xP, ctx);
	r &= fp2_init(yP, ctx);
	r &= fp2_init(zP, ctx);
	if (!r) {
		goto end;
	}

	r = 0;
	if (!fp2_copy(xP, P->X)
		|| !fp2_copy(yP, P->Y)
		|| !fp2_copy(zP, P->Z)	/* if necessary */
		|| !fp12_set_fp2(x, xP)
		|| !fp12_set_fp2(y, yP)
		|| !fp12_set_fp2(z, zP)

		/* x = x * w^-2 */
		|| !fp12_mul_w_pow_neg_2(x, x, p, mont, ctx)

		/* y = y * w^-3 */
		|| !fp12_mul_w_pow_neg_3(y, y, p, mont, ctx)
		
		/* z is unchanged */) {
		goto end;
	}

	r = 1;

end:
	fp2_cleanup(xP);
	fp2_cleanup(yP);
	fp2_cleanup(zP);
	return r;
}



int point_get_ext_affine_coordinates_montgomery(const point_t *P, fp12_t x, fp12_t y, const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	int r;
	fp2_t xP;
	fp2_t yP;

	r = 1;
	r &= fp2_init(xP, ctx);
	r &= fp2_init(yP, ctx);
	if (!r) {
		goto end;
	}

	r = 0;
	if (!point_get_affine_coordinates_montgomery(P, xP, yP)
		|| !fp12_set_fp2(x, xP)
		|| !fp12_set_fp2(y, yP)

		/* x = x * w^-2 */
		|| !fp12_mul_w_pow_neg_2(x, x, p, mont, ctx)

		/* y = y * w^-3 */
		|| !fp12_mul_w_pow_neg_3(y, y, p, mont, ctx)) {
		//goto end;
	}
	r = 1;

end:
	fp2_cleanup(xP);
	fp2_cleanup(yP);
	return r;
}



int point_set_ext_affine_coordinates_montgomery(point_t *P, const fp12_t x, const fp12_t y, const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	fp12_t tx;
	fp12_t ty;

	fp12_init(tx, ctx);
	fp12_init(ty, ctx);

	fp12_set_w_sqr_montgomery(tx);
	fp12_set_v_montgomery(ty);
	fp12_mul_montgomery(tx, x, tx, p, mont, ctx);
	fp12_mul_montgomery(ty, y, ty, p, mont, ctx);

	point_set_affine_coordinates_montgomery(P, tx[0][0], ty[0][0]);

	fp12_cleanup(tx);
	fp12_cleanup(ty);
	return 1;
}




int point_is_on_curve_sm9(point_t *P, const BIGNUM *p, BN_CTX *ctx)
{
	int r;
	fp2_t x, y, b, t;

	r = fp2_init(x, ctx);
	r &= fp2_init(y, ctx);
	r &= fp2_init(b, ctx);
	r &= fp2_init(t, ctx);
	if (!r) {
		goto end;
	}

	fp2_set_5u(b);

	if (!point_get_affine_coordinates(P, x, y)
		/* x^3 + 5 * u */
		|| !fp2_sqr(t, x, p, ctx)
		|| !fp2_mul(x, x, t, p, ctx)
		|| !fp2_add(x, x, b, p, ctx)
		/* y^2 */
		|| !fp2_sqr(y, y, p, ctx)) {
		r = 0;
		goto end;
	}
	r = fp2_equ(x, y);

end:
	fp2_cleanup(x);
	fp2_cleanup(y);
	fp2_cleanup(t);
	return r;
}

int point_to_octets(const point_t *P, unsigned char to[129], BN_CTX *ctx)
{
	to[0] = 0x04;

	if (fp2_is_one(P->Z)) {
		fp2_to_bin(P->X, to + 1);
		fp2_to_bin(P->Y, to + 65);
	} else {
		fp2_t x, y;
		fp2_init(x, ctx);
		fp2_init(y, ctx);
		point_get_affine_coordinates(P, x, y);

		fp2_to_bin(x, to + 1);
		fp2_to_bin(y, to + 65);
		fp2_cleanup(x);
		fp2_cleanup(y);
	}
	return 1;
}

int point_from_octets(point_t *P, const unsigned char from[129], const BIGNUM *p, BN_CTX *ctx)
{
	if (from[0] != 0x04) {
		return 0;
	}
	fp2_from_bin(P->X, from + 1);
	fp2_from_bin(P->Y, from + 65);
	fp2_set_one(P->Z);
	return point_is_on_curve_sm9(P, p, ctx);
}

static int point_dbl_affine_montgomery(point_t *R, const point_t *P, const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	int r;
	fp2_t x3, y3, z3, x1, y1, z1, tmp, s, m;

	r = 1;
	r &= fp2_init(x1, ctx);
	r &= fp2_init(y1, ctx);
	r &= fp2_init(z1, ctx);
	r &= fp2_init(x3, ctx);
	r &= fp2_init(y3, ctx);
	r &= fp2_init(z3, ctx);
	r &= fp2_init(tmp, ctx);
	r &= fp2_init(s, ctx);
	r &= fp2_init(m, ctx);

	if (!r) {
		goto end;
	}

	if (point_is_at_infinity(P)) {
		r = point_set_to_infinity(R);
		goto end;
	}

	if(!fp2_copy(x1, P->X)
		|| !fp2_copy(y1, P->Y)
		|| !fp2_copy(z1, P->Z))
	{
		r = 0;
		goto end;
	}

	if (/*s = 4XY^2*/
		!fp2_sqr_montgomery(s, y1, p, mont, ctx)
		|| !fp2_mul_montgomery(s, s, x1, p, mont, ctx)
		|| !fp2_dbl(s, s, p, ctx)
		|| !fp2_dbl(s, s, p, ctx)

		/* m = 3X^2 */
		|| !fp2_sqr_montgomery(m, x1, p, mont, ctx)
		|| !fp2_tri(m, m, p, ctx)

		/* x3 = m^2-2s */
		|| !fp2_sqr_montgomery(x3, m, p, mont, ctx)
		|| !fp2_sub(x3, x3, s, p, ctx)
		|| !fp2_sub(x3, x3, s, p, ctx)

		/* y3 = m(s-x3) - 8Y^4 */
		|| !fp2_sub(y3, s, x3, p, ctx)
		|| !fp2_mul_montgomery(y3, y3, m, p, mont, ctx)
		|| !fp2_sqr_montgomery(tmp, y1, p, mont, ctx)
		|| !fp2_dbl(tmp, tmp, p, ctx)
		|| !fp2_sqr_montgomery(tmp, tmp, p, mont, ctx)
		|| !fp2_dbl(tmp, tmp, p, ctx)
		|| !fp2_sub(y3, y3, tmp, p, ctx)

		/* z3 = 2YZ*/
		|| !fp2_mul_montgomery(z3, y1, z1, p, mont, ctx)
		|| !fp2_dbl(z3, z3, p, ctx)) {
		r = 0;
		goto end;
	}

	r = fp2_copy(R->X, x3)
		&& fp2_copy(R->Y, y3)
		&& fp2_copy(R->Z, z3);

end:
	fp2_cleanup(x1);
	fp2_cleanup(y1);
	fp2_cleanup(z1);
	fp2_cleanup(x3);
	fp2_cleanup(y3);
	fp2_cleanup(z3);
	fp2_cleanup(tmp);
	fp2_cleanup(s);
	fp2_cleanup(m);
	return r;
}

static int point_dbl_affine_old(point_t *R, const point_t *P, const BIGNUM *p, BN_CTX *ctx)
{

	int r;
	fp2_t x3, y3, z3, x1, y1, z1, tmp, s, m;

	r = 1;
	r &= fp2_init(x1, ctx);
	r &= fp2_init(y1, ctx);
	r &= fp2_init(z1, ctx);
	r &= fp2_init(x3, ctx);
	r &= fp2_init(y3, ctx);
	r &= fp2_init(z3, ctx);
	r &= fp2_init(tmp, ctx);
	r &= fp2_init(s, ctx);
	r &= fp2_init(m, ctx);

	if (!r) {
		goto end;
	}

	if (point_is_at_infinity(P)) {
		r = point_set_to_infinity(R);
		goto end;
	}

	if(!fp2_copy(x1, P->X)
		|| !fp2_copy(y1, P->Y)
		|| !fp2_copy(z1, P->Z))
	{
		r = 0;
		goto end;
	}

	if (/*s = 4XY^2*/
		!fp2_sqr(s, y1, p, ctx)
		|| !fp2_mul(s, s, x1, p, ctx)
		|| !fp2_dbl(s, s, p, ctx)
		|| !fp2_dbl(s, s, p, ctx)

		/* m = 3X^2 */
		|| !fp2_sqr(m, x1, p, ctx)
		|| !fp2_tri(m, m, p, ctx)

		/* x3 = m^2-2s */
		|| !fp2_sqr(x3, m, p, ctx)
		|| !fp2_sub(x3, x3, s, p, ctx)
		|| !fp2_sub(x3, x3, s, p, ctx)

		/* y3 = m(s-x3) - 8Y^4 */
		|| !fp2_sub(y3, s, x3, p, ctx)
		|| !fp2_mul(y3, y3, m, p, ctx)
		|| !fp2_sqr(tmp, y1, p, ctx)
		|| !fp2_dbl(tmp, tmp, p, ctx)
		|| !fp2_sqr(tmp, tmp, p, ctx)
		|| !fp2_dbl(tmp, tmp, p, ctx)
		|| !fp2_sub(y3, y3, tmp, p, ctx)

		/* z3 = 2YZ*/
		|| !fp2_mul(z3, y1, z1, p, ctx)
		|| !fp2_dbl(z3, z3, p, ctx)) {
		r = 0;
		goto end;
	}

	r = fp2_copy(R->X, x3)
		&& fp2_copy(R->Y, y3)
		&& fp2_copy(R->Z, z3);


end:
	fp2_cleanup(x1);
	fp2_cleanup(y1);
	fp2_cleanup(z1);
	fp2_cleanup(x3);
	fp2_cleanup(y3);
	fp2_cleanup(z3);
	fp2_cleanup(tmp);
	fp2_cleanup(s);
	fp2_cleanup(m);
	return r;
}

static int point_dbl_affine(point_t *R, const point_t *P, const BIGNUM *p, BN_CTX *ctx)
{
	if(!mont)
	{
		mont = BN_MONT_CTX_new();
		BN_MONT_CTX_set(mont, p, ctx);
	}

	int ret = 0;

	point_t tR, tP;
	if(	!point_init(&tR, ctx)
		|| !point_init(&tP, ctx)
	)
	{
		return 0;
	}

	if(!point_to_montgomery(&tP, P, mont, ctx)
		|| !point_dbl_affine_montgomery(&tR, &tP, p, mont, ctx)
		|| !point_from_montgomery(R, &tR, mont, ctx))
		{
			goto end;
		}
	ret = 1;

end:
	point_cleanup(&tR);
	point_cleanup(&tP);
	return ret;	
}

int point_dbl(point_t *R, const point_t *P, const BIGNUM *p, BN_CTX *ctx)
{
	int r;
	fp2_t x3, y3, x1, y1, lambda, t;

	r = 1;
	r &= fp2_init(x1, ctx);
	r &= fp2_init(y1, ctx);
	r &= fp2_init(x3, ctx);
	r &= fp2_init(y3, ctx);
	r &= fp2_init(lambda, ctx);
	r &= fp2_init(t, ctx);
	if (!r) {
		goto end;
	}

	if (point_is_at_infinity(P)) {
		r = point_set_to_infinity(R);
		goto end;
	}

	if (!point_get_affine_coordinates(P, x1, y1)
		/* lambda = 3 * x1^2 / 2 * y1 */
		|| !fp2_sqr(lambda, x1, p, ctx)
		|| !fp2_tri(lambda, lambda, p, ctx)
		|| !fp2_dbl(t, y1, p, ctx)
		|| !fp2_inv(t, t, p, ctx)
		|| !fp2_mul(lambda, lambda, t, p, ctx)

		/* x3 = lambda^2 - 2 * x1 */
		|| !fp2_sqr(x3, lambda, p, ctx)
		|| !fp2_dbl(t, x1, p, ctx)
		|| !fp2_sub(x3, x3, t, p, ctx)

		/* y3 = lambda * (x1 - x3) - y1 */
		|| !fp2_sub(y3, x1, x3, p, ctx)
		|| !fp2_mul(y3, lambda, y3, p, ctx)
		|| !fp2_sub(y3, y3, y1, p, ctx)) {
		r = 0;
		goto end;
	}

	r = point_set_affine_coordinates(R, x3, y3);

end:
	fp2_cleanup(x1);
	fp2_cleanup(y1);
	fp2_cleanup(x3);
	fp2_cleanup(y3);
	fp2_cleanup(lambda);
	fp2_cleanup(t);
	return r;
}

static int point_add_affine_montgomery(point_t *R, const point_t *P, const point_t *Q, const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	/**
	 * P is presented as (X,Y,Z)
	 * while Q is presented as (x,y,1)
	 */
	int r = 0;
	fp2_t x1;
	fp2_t y1;
	fp2_t z1;
	fp2_t x2;
	fp2_t y2;
	fp2_t x3;
	fp2_t y3;
	fp2_t z3;

	fp2_t t1;
	fp2_t t2;
	fp2_t t3;
	fp2_t t4;

	if (point_is_at_infinity(P)) {
		return point_copy_sm9(R, Q);
	}

	if (point_is_at_infinity(Q)) {
		return point_copy_sm9(R, P);
	}



	r = 1;
	r &= fp2_init(x1, ctx);
	r &= fp2_init(y1, ctx);
	r &= fp2_init(z1, ctx);
	r &= fp2_init(x2, ctx);
	r &= fp2_init(y2, ctx);
	r &= fp2_init(x3, ctx);
	r &= fp2_init(y3, ctx);
	r &= fp2_init(z3, ctx);
	r &= fp2_init(t1, ctx);
	r &= fp2_init(t2, ctx);
	r &= fp2_init(t3, ctx);
	r &= fp2_init(t4, ctx);

	if (!r) {
		goto end;
	}

	r = 0;

	if (!fp2_copy(x1, P->X)
		|| !fp2_copy(y1, P->Y)
		|| !fp2_copy(z1, P->Z)
		|| !point_get_affine_coordinates_montgomery(Q, x2, y2)) {
		goto end;
	}

	if(/* x2 = xZ^2 */
		!fp2_sqr_montgomery(t3, z1, p, mont, ctx)
		|| !fp2_mul_montgomery(x2, x2, t3, p, mont, ctx)
		
		/* y2 = yZ^3 */
		|| !fp2_mul_montgomery(t2, t3, z1, p, mont, ctx)
		|| !fp2_mul_montgomery(y2, y2, t2, p, mont, ctx)

		/* t1 = xZ^2 - X, t2 = yZ^3 - Y */
		|| !fp2_sub(t1, x2, x1, p, ctx)
		|| !fp2_sub(t2, y2, y1, p, ctx)) {
			goto end;
	}

	if(fp2_is_zero(t1))
	{
		if(fp2_is_zero(t2))
		{
			// if P = Q, then xZ^2 = X && yZ^3 = Y
			return point_dbl_affine_montgomery(R, P, p, mont, ctx); 
		}

		else 
		{
			// P=-Q
			r = point_set_to_infinity(R);
			goto end;
		}
	}


	if (/* Z3 = Z1 * t1 */
		! fp2_mul_montgomery(z3, z1, t1, p, mont, ctx)

		/* t3 = x1 * (x2 - x1)^2, t4 = (x2 - x1)^3, t1 = 2 * x1 * (x2-x1) */
		|| !fp2_sqr_montgomery(t3, t1, p, mont, ctx)
		|| !fp2_mul_montgomery(t4, t3, t1, p, mont, ctx)
		|| !fp2_mul_montgomery(t3, x1, t3, p, mont, ctx)
		|| !fp2_add(t1, t3, t3, p, ctx)

		/* x3 = x2 ^ 2 - t1 - t4 */
		|| !fp2_sqr_montgomery(x3, t2, p, mont, ctx)
		|| !fp2_sub(x3, x3, t1, p, ctx)
		|| !fp2_sub(x3, x3, t4, p, ctx)

		/* y3 = yZ^3 - t2(t3 - x3) - y1 * t4 */
		|| !fp2_sub(t3, t3, x3, p, ctx)
		|| !fp2_mul_montgomery(t3, t3, t2, p, mont, ctx)
		|| !fp2_mul_montgomery(t4, t4, y1, p, mont, ctx)
		|| !fp2_sub(y3, t3, t4, p, ctx)){
		
		goto end;
	}

	r = fp2_copy(R->X, x3)
		&& fp2_copy(R->Y, y3)
		&& fp2_copy(R->Z, z3);

end:
	fp2_cleanup(x1);
	fp2_cleanup(y1);
	fp2_cleanup(z1);
	fp2_cleanup(x2);
	fp2_cleanup(y2);
	fp2_cleanup(x3);
	fp2_cleanup(y3);
	fp2_cleanup(z3);
	fp2_cleanup(t1);
	fp2_cleanup(t2);
	fp2_cleanup(t3);
	fp2_cleanup(t4);
	return r;
}

static int point_add_affine_montgomery_old(point_t *R, const point_t *P, const point_t *Q, const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	/**
	 * P is presented as (X,Y,Z)
	 * while Q is presented as (x,y,1)
	 */
	int r = 0;
	fp2_t x1;
	fp2_t y1;
	fp2_t z1;
	fp2_t x2;
	fp2_t y2;
	fp2_t x3;
	fp2_t y3;
	fp2_t z3;

	fp2_t t;
	fp2_t s;
	fp2_t tmp;

	if (point_is_at_infinity(P)) {
		return point_copy_sm9(R, Q);
	}

	if (point_is_at_infinity(Q)) {
		return point_copy_sm9(R, P);
	}



	r = 1;
	r &= fp2_init(x1, ctx);
	r &= fp2_init(y1, ctx);
	r &= fp2_init(z1, ctx);
	r &= fp2_init(x2, ctx);
	r &= fp2_init(y2, ctx);
	r &= fp2_init(x3, ctx);
	r &= fp2_init(y3, ctx);
	r &= fp2_init(z3, ctx);
	r &= fp2_init(t, ctx);
	r &= fp2_init(s, ctx);
	r &= fp2_init(tmp, ctx);

	if (!r) {
		goto end;
	}

	r = 0;

	if (!fp2_copy(x1, P->X)
		|| !fp2_copy(y1, P->Y)
		|| !fp2_copy(z1, P->Z)
		|| !point_get_affine_coordinates_montgomery(Q, x2, y2)) {
		goto end;
	}

	if(/* t1 = xZ^2 */
		!fp2_sqr_montgomery(tmp, z1, p, mont, ctx)
		|| !fp2_mul_montgomery(t, x2, tmp, p, mont, ctx)
		
		/* t2 = yZ^3 */
		|| !fp2_mul_montgomery(tmp, tmp, z1, p, mont, ctx)
		|| !fp2_mul_montgomery(s, y2, tmp, p, mont, ctx)

		/* t1 = xZ^2 - X, t2 = yZ^3 - Y */
		|| !fp2_sub(t, t, x1, p, ctx)
		|| !fp2_sub(s, s, y1, p, ctx)) {
			goto end;
	}

	

	if(fp2_is_zero(t))
	{
		if(fp2_is_zero(s))
		{
			// if P = Q, then xZ^2 = X && yZ^3 = Y
			return point_dbl_affine_montgomery(R, P, p, mont, ctx); 
		}

		else 
		{
			// P=-Q
			r = point_set_to_infinity(R);
			goto end;
		}
	}


	if (/* Z3 = Z1 * t1 */
		!fp2_sqr_montgomery(t, z1, p, mont, ctx)
		|| !fp2_mul_montgomery(t, t, x2, p, mont, ctx)
		|| !fp2_sub(t, t, x1, p, ctx)

		/* s = yZ^3 - Y */
		|| !fp2_sqr_montgomery(s, z1, p, mont, ctx)
		|| !fp2_mul_montgomery(s, s, z1, p, mont, ctx)
		|| !fp2_mul_montgomery(s, s, y2, p, mont, ctx)
		|| !fp2_sub(s, s, y1, p, ctx)

		/* x3 = s^2 - t^2(X+xZ^2) */
		|| !fp2_sqr_montgomery(tmp, z1, p, mont, ctx)
		|| !fp2_mul_montgomery(tmp, tmp, x2, p, mont, ctx)
		|| !fp2_add(tmp, tmp, x1, p, ctx)
		|| !fp2_sqr_montgomery(x3, t, p, mont, ctx)
		|| !fp2_mul_montgomery(tmp, x3, tmp, p, mont, ctx)
		|| !fp2_sqr_montgomery(x3, s, p, mont, ctx)
		|| !fp2_sub(x3, x3, tmp, p, ctx)
		
		/*y3 = s(Xt^2-x3)-Yt^3*/
		|| !fp2_sqr_montgomery(y3, t, p, mont, ctx)
		|| !fp2_mul_montgomery(y3, y3, x1, p, mont, ctx)
		|| !fp2_sub(y3, y3, x3, p, ctx)
		|| !fp2_mul_montgomery(y3, y3, s, p, mont, ctx)
		|| !fp2_sqr_montgomery(tmp, t, p, mont, ctx)
		|| !fp2_mul_montgomery(tmp, tmp, t, p, mont, ctx)
		|| !fp2_mul_montgomery(tmp, tmp, y1, p, mont, ctx)
		|| !fp2_sub(y3, y3, tmp, p, ctx)
		
		/*z3 = t * Z1 */
		|| !fp2_mul_montgomery(z3, t, z1, p, mont, ctx)) {
		goto end;
	}

	r = fp2_copy(R->X, x3)
		&& fp2_copy(R->Y, y3)
		&& fp2_copy(R->Z, z3);

end:
	fp2_cleanup(x1);
	fp2_cleanup(y1);
	fp2_cleanup(z1);
	fp2_cleanup(x2);
	fp2_cleanup(y2);
	fp2_cleanup(x3);
	fp2_cleanup(y3);
	fp2_cleanup(z3);
	fp2_cleanup(s);
	fp2_cleanup(t);
	fp2_cleanup(tmp);
	return r;
}

int point_add_affine_old(point_t *R, const point_t *P, const point_t *Q, const BIGNUM *p, BN_CTX *ctx)
{
	/**
	 * P is presented as (X,Y,Z)
	 * while Q is presented as (x,y,1)
	 */

	int r = 0;
	fp2_t x1;
	fp2_t y1;
	fp2_t z1;
	fp2_t x2;
	fp2_t y2;
	fp2_t x3;
	fp2_t y3;
	fp2_t z3;
	fp2_t t;
	fp2_t s;
	fp2_t tmp;

	if (point_is_at_infinity(P)) {
		return point_copy_sm9(R, Q);
	}

	if (point_is_at_infinity(Q)) {
		return point_copy_sm9(R, P);
	}

	if (!fp2_is_one(Q->Z))
	{
		goto end;
	}


	r = 1;
	r &= fp2_init(x1, ctx);
	r &= fp2_init(y1, ctx);
	r &= fp2_init(z1, ctx);
	r &= fp2_init(x2, ctx);
	r &= fp2_init(y2, ctx);
	r &= fp2_init(x3, ctx);
	r &= fp2_init(y3, ctx);
	r &= fp2_init(z3, ctx);
	r &= fp2_init(t, ctx);
	r &= fp2_init(s, ctx);
	r &= fp2_init(tmp, ctx);
	if (!r) {
		goto end;
	}

	r = 0;


	if (!fp2_copy(x1, P->X)
		|| !fp2_copy(y1, P->Y)
		|| !fp2_copy(z1, P->Z)
		|| !point_get_affine_coordinates(Q, x2, y2)) {
		goto end;
	}

	if(/* s = xZ^2 */
		!fp2_sqr(tmp, z1, p, ctx)
		|| !fp2_mul(s, x2, tmp, p, ctx)
		
		/* t = yZ^3 */
		|| !fp2_mul(tmp, tmp, z1, p, ctx)
		|| !fp2_mul(t, y2, tmp, p, ctx)) {
			goto end;
	}

	if(fp2_equ(s, x1))
	{
		if(fp2_equ(t, y1))
		{
			// if P = Q, then xZ^2 = X && yZ^3 = Y
			return point_dbl(R, P, p, ctx); 
		}

		else 
		{
			// P=-Q
			r = point_set_to_infinity(R);
			goto end;
		}
	}


	/* lambda = (y2 - y1)/(x2 - x1) */
	if (/* t = xZ^2 - X */
		!fp2_sqr(t, z1, p, ctx)
		|| !fp2_mul(t, t, x2, p, ctx)
		|| !fp2_sub(t, t, x1, p, ctx)

		/* s = yZ^3 - Y */
		|| !fp2_sqr(s, z1, p, ctx)
		|| !fp2_mul(s, s, z1, p, ctx)
		|| !fp2_mul(s, s, y2, p, ctx)
		|| !fp2_sub(s, s, y1, p, ctx)

		/* x3 = s^2 - t^2(X+xZ^2) */
		|| !fp2_sqr(tmp, z1, p, ctx)
		|| !fp2_mul(tmp, tmp, x2, p, ctx)
		|| !fp2_add(tmp, tmp, x1, p, ctx)
		|| !fp2_sqr(x3, t, p, ctx)
		|| !fp2_mul(tmp, x3, tmp, p, ctx)
		|| !fp2_sqr(x3, s, p, ctx)
		|| !fp2_sub(x3, x3, tmp, p, ctx)
		
		/*y3 = s(Xt^2-x3)-Yt^3*/
		|| !fp2_sqr(y3, t, p, ctx)
		|| !fp2_mul(y3, y3, x1, p, ctx)
		|| !fp2_sub(y3, y3, x3, p, ctx)
		|| !fp2_mul(y3, y3, s, p, ctx)
		|| !fp2_sqr(tmp, t, p, ctx)
		|| !fp2_mul(tmp, tmp, t, p, ctx)
		|| !fp2_mul(tmp, tmp, y1, p, ctx)
		|| !fp2_sub(y3, y3, tmp, p, ctx)
		
		/*z3 = t * Z1 */
		|| !fp2_mul(z3, t, z1, p, ctx)) {
		goto end;
	}

	r = fp2_copy(R->X, x3)
		&& fp2_copy(R->Y, y3)
		&& fp2_copy(R->Z, z3);

end:
	fp2_cleanup(x1);
	fp2_cleanup(y1);
	fp2_cleanup(z1);
	fp2_cleanup(x2);
	fp2_cleanup(y2);
	fp2_cleanup(x3);
	fp2_cleanup(y3);
	fp2_cleanup(z3);
	fp2_cleanup(s);
	fp2_cleanup(t);
	fp2_cleanup(tmp);
	return r;
}

int point_add_affine(point_t *R, const point_t *P, const point_t *Q, const BIGNUM *p, BN_CTX *ctx)
{
	if(!mont)
	{
		mont = BN_MONT_CTX_new();
		BN_MONT_CTX_set(mont, p, ctx);
	}

	int ret = 0;

	point_t tR, tP, tQ;
	if(	!point_init(&tR, ctx)
		|| !point_init(&tP, ctx)
		|| !point_init(&tQ, ctx)
	)
	{
		return 0;
	}

	if(!point_to_montgomery(&tP, P, mont, ctx)
		|| !point_to_montgomery(&tQ, Q, mont, ctx)
		|| !point_add_affine_montgomery(&tR, &tP, &tQ, p, mont, ctx)
		|| !point_from_montgomery(R, &tR, mont, ctx))
		{
			goto end;
		}
	ret = 1;

end:
	point_cleanup(&tR);
	point_cleanup(&tP);
	point_cleanup(&tQ);
	return ret;
}

int point_add(point_t *R, const point_t *P, const point_t *Q, const BIGNUM *p, BN_CTX *ctx)
{
	int r;
	fp2_t x1;
	fp2_t y1;
	fp2_t x2;
	fp2_t y2;
	fp2_t x3;
	fp2_t y3;
	fp2_t lambda;
	fp2_t t;

	if (point_is_at_infinity(P)) {
		return point_copy_sm9(R, Q);

	}

	if (point_is_at_infinity(Q)) {
		return point_copy_sm9(R, P);
	}

	if (point_equ_sm9(P, Q)) {
		return point_dbl(R, P, p, ctx);
	}

	r = 1;
	r &= fp2_init(x1, ctx);
	r &= fp2_init(y1, ctx);
	r &= fp2_init(x2, ctx);
	r &= fp2_init(y2, ctx);
	r &= fp2_init(x3, ctx);
	r &= fp2_init(y3, ctx);
	r &= fp2_init(lambda, ctx);
	r &= fp2_init(t, ctx);
	if (!r) {
		goto end;
	}

	r = 0;

	if (!point_get_affine_coordinates(P, x1, y1)
		|| !point_get_affine_coordinates(Q, x2, y2)
		|| !fp2_add(t, y1, y2, p, ctx)) {
		goto end;
	}

	if (fp2_equ(x1, x2) && fp2_is_zero(t)) {
		r = point_set_to_infinity(R);
		goto end;
	}

	/* lambda = (y2 - y1)/(x2 - x1) */
	if (!fp2_sub(lambda, y2, y1, p, ctx)
		|| !fp2_sub(t, x2, x1, p, ctx)
		|| !fp2_inv(t, t, p, ctx)
		|| !fp2_mul(lambda, lambda, t, p, ctx)

		/* x3 = lambda^2 - x1 - x2 */
		|| !fp2_sqr(x3, lambda, p, ctx)
		|| !fp2_sub(x3, x3, x1, p, ctx)
		|| !fp2_sub(x3, x3, x2, p, ctx)

		/* y3 = lambda * (x1 - x3) - y1 */
		|| !fp2_sub(y3, x1, x3, p, ctx)
		|| !fp2_mul(y3, lambda, y3, p, ctx)
		|| !fp2_sub(y3, y3, y1, p, ctx)) {
		goto end;
	}

	r = point_set_affine_coordinates(R, x3, y3);

end:
	fp2_cleanup(x1);
	fp2_cleanup(y1);
	fp2_cleanup(x2);
	fp2_cleanup(y2);
	fp2_cleanup(x3);
	fp2_cleanup(y3);
	fp2_cleanup(lambda);
	fp2_cleanup(t);
	return r;
}

int point_neg(point_t *R, const point_t *P, const BIGNUM *p, BN_CTX *ctx)
{
	return fp2_copy(R->X, P->X)
		&& fp2_neg(R->Y, P->Y, p, ctx)
		&& fp2_copy(R->Z, P->Z);
}

int point_sub(point_t *R, const point_t *P, const point_t *Q, const BIGNUM *p, BN_CTX *ctx)
{
	point_t T;

	memset(&T, 0, sizeof(T));
	if (!point_init(&T, ctx)
		|| !point_neg(&T, Q, p, ctx)
		|| !point_add(R, P, &T, p, ctx)) {
		point_cleanup(&T);
		return 0;
	}
	point_cleanup(&T);
	return 1;
}

static int point_mul_affine(point_t *R, const BIGNUM *k, const point_t *P, const BIGNUM *p, BN_CTX *ctx)
{
	/* P is presented as (x,y,1) */
	int i, n;

	if (BN_is_zero(k)) {
		return point_set_to_infinity(R);
	}

	if (!point_copy_sm9(R, P)) {
		return 0;
	}
	n = BN_num_bits(k);
	for (i = n - 2; i >= 0; i--) {

		if (!point_dbl_affine(R, R, p, ctx)) {
			return 0;
		}
		if (BN_is_bit_set(k, i)) {
			if (!point_add_affine(R, R, P, p, ctx) /*the order of R and P cannot be change*/) {
				return 0;
			}
		}
	}

	return 1;
}

int point_mul_sm9(point_t *R, const BIGNUM *k, const point_t *P, const BIGNUM *p, BN_CTX *ctx)
{
	int i, n;

	if (BN_is_zero(k)) {
		return point_set_to_infinity(R);
	}

	if (!point_copy_sm9(R, P)) {
		return 0;
	}
	n = BN_num_bits(k);
	for (i = n - 2; i >= 0; i--) {

		if (!point_dbl(R, R, p, ctx)) {
			return 0;
		}
		if (BN_is_bit_set(k, i)) {
			if (!point_add(R, R, P, p, ctx)) {
				return 0;
			}
		}
	}

	return 1;
}

int point_mul_generator_affine(point_t *R, const BIGNUM *k, const BIGNUM *p, BN_CTX *ctx)
{
	point_t G;

	memset(&G, 0, sizeof(G));
	point_init(&G, ctx);
	point_set_affine_coordinates_bignums(&G,
		SM9_get0_generator2_x0(),
		SM9_get0_generator2_x1(),
		SM9_get0_generator2_y0(),
		SM9_get0_generator2_y1());

	return point_mul_affine(R, k, &G, p, ctx);
}

int point_mul_generator(point_t *R, const BIGNUM *k, const BIGNUM *p, BN_CTX *ctx)
{
	point_t tR;
	fp2_t tx, ty; 
	int ret = 0;

	point_init(&tR, ctx);

	if(!point_mul_generator_affine(&tR, k, p, ctx)){
		point_cleanup(&tR);
		return 0;
	}

	fp2_init(tx, ctx);
	fp2_init(ty, ctx);

	if(!point_get_affine_coordinates_affine(&tR, tx, ty, p, ctx)
		|| !point_set_affine_coordinates(R, tx, ty))
	{
		goto end;
	}

	ret = 1;

end:
	point_cleanup(&tR);
	fp2_cleanup(tx);
	fp2_cleanup(ty);

	return ret;

}



static int eval_tangent_affine_montgomery(fp12_t r, const point_t *T, const BIGNUM *xP, const BIGNUM *yP, fp12_t corr, const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	/**
	 * T is represented as (X,Y,Z)
	 * r * 2YZ^3 	= 3X^2(xZ^2-X) - 2Y(yZ^3-Y)
	 * 		 		= 3X^2 * s - 2Y(yZ^3-Y)
	 * 				= r1 - r2
	 */

	int ret;
	fp12_t s, t;
	fp12_t xT, yT, zT;

	ret = 1;
	ret &= fp12_init(s, ctx);
	ret &= fp12_init(t, ctx);
	ret &= fp12_init(xT, ctx);
	ret &= fp12_init(yT, ctx);
	ret &= fp12_init(zT, ctx);
	if (!ret) {
		goto end;
	}

	point_get_ext_affine_coordinates_affine_montgomery(T, xT, yT, zT, p, mont, ctx);

	ret = 0;
	if (/* s = xZ^2 - X */
		!fp12_sqr_montgomery_2(s, zT, 0, p, mont, ctx)
		|| !fp12_mul_num_montgomery(s, s, xP, p, mont, ctx)
		|| !fp12_sub(s, s, xT, p, ctx)

		/* r1 = 3sX^2 */
		|| !fp12_sqr_montgomery_2(r, xT, 4, p, mont, ctx)
		|| !fp12_mul_montgomery(r, s, r, p, mont, ctx)
		|| !fp12_tri(r, r, p, ctx)
		
		/* t = 2Y(yZ^3-Y) */
		|| !fp12_sqr_montgomery_2(t, zT, 0, p, mont, ctx)
		|| !fp12_mul_fp2_montgomery(t, t, zT[0][0], p, mont, ctx)
		|| !fp12_mul_num_montgomery(t, t, yP, p, mont, ctx)
		|| !fp12_sub(t, t, yT, p, ctx)
		|| !fp12_mul_fp2_montgomery(t, t, yT[0][1], p, mont, ctx)
		|| !fp12_mul_w_pow_3(t, t, p, mont, ctx)
		|| !fp12_dbl(t, t, p, ctx)
		
		/* r = r1 - r2*/
		|| !fp12_sub(r, r, t, p, ctx)) {
		goto end;
	}

	ret = 1;
end:
	fp12_cleanup(xT);
	fp12_cleanup(yT);
	fp12_cleanup(zT);
	fp12_cleanup(s);
	fp12_cleanup(t);
	return ret;
}



static int eval_line_affine_montgomery(fp12_t r,  const point_t *T, const point_t *Q,
	const BIGNUM *xP, const BIGNUM *yP,
	fp12_t corr, /* the correct */
	const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	int ret;
	fp12_t x, y, t1, t2;
	fp12_t xT, yT, zT, xQ, yQ;

	ret = 1;
	ret &= fp12_init(x, ctx);
	ret &= fp12_init(y, ctx);
	ret &= fp12_init(t1, ctx);
	ret &= fp12_init(t2, ctx);
	ret &= fp12_init(xT, ctx);
	ret &= fp12_init(yT, ctx);
	ret &= fp12_init(zT, ctx);
	ret &= fp12_init(xQ, ctx);
	ret &= fp12_init(yQ, ctx);
	if (!ret) {
		goto end;
	}

	point_get_ext_affine_coordinates_affine_montgomery(T, xT, yT, zT, p, mont, ctx);
	point_get_ext_affine_coordinates_montgomery(Q, xQ, yQ, p, mont, ctx);

	ret = 0;
	if (!fp12_set_bn(x, xP)
		|| !fp12_set_bn(y, yP)
		/* t1 = zT^2 */
		|| !fp12_sqr_montgomery_2(t1, zT, 0, p, mont, ctx)

		/* t2 = zT (XT - zT^2 * xQ) */
		|| !fp12_mul_fp2_montgomery(t2, t1, Q->X, p, mont, ctx)
		|| !fp12_mul_w_pow_neg_2(t2, t2, p, mont, ctx)
		|| !fp12_sub(t2, xT, t2, p, ctx)
		|| !fp12_mul_fp2_montgomery(t2, t2, T->Z, p, mont, ctx)
		
		/* t1 = yT - zT^3 * yQ */
		|| !fp12_mul_fp2_montgomery(t1, t1, T->Z, p, mont, ctx)
		|| !fp12_mul_fp2_montgomery(t1, t1, yQ[0][1], p, mont, ctx)
		|| !fp12_mul_w_pow_3(t1, t1, p, mont, ctx)
		|| !fp12_sub(t1, yT, t1, p, ctx)

		/* r = t1(xP-xQ) */
		|| !fp12_set_zero(r)
		|| !BN_copy(r[0][0][0], xP)
		|| !fp2_neg(r[1][1], xQ[1][1], p, ctx)
		|| !fp12_mul_montgomery(r, t1, r, p, mont, ctx)
		
		/* t1 = t2 * (yP-yQ) */
		|| !fp12_set_zero(t1)
		|| !BN_copy(t1[0][0][0], yP)
		|| !fp2_neg(t1[0][1], yQ[0][1], p, ctx)
		|| !fp12_mul_montgomery(t1, t1, t2, p, mont, ctx)

		/* r = r-t1 */
		|| !fp12_sub(r, r, t1, p, ctx)
		) {
		goto end;
	}
	ret = 1;


end:
	fp12_cleanup(t1);
	fp12_cleanup(t2);
	return ret;
}




static int frobenius_montgomery(point_t *R, const point_t *P, const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	fp12_t x, y;

	fp12_init(x, ctx);
	fp12_init(y, ctx);

	point_get_ext_affine_coordinates_montgomery(P, x, y, p, mont, ctx);

	fp12_fast_expo_p_montgomery(x, x, p, mont, ctx);
	fp12_fast_expo_p_montgomery(y, y, p, mont, ctx);

	point_set_ext_affine_coordinates_montgomery(R, x, y, p, mont, ctx);

	fp12_cleanup(x);
	fp12_cleanup(y);
	return 1;
}





static int fast_final_expo_montgomery(fp12_t r, const fp12_t a, const BIGNUM *k, const BIGNUM *p, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	int i, n;
	fp12_t t;
	fp12_t aq;
	fp12_t aqq;
	fp12_t aqqq;
	fp12_t t0;
	fp12_t t1;

	long begin, end;

	fp12_init(aq, ctx);
	fp12_init(aqq, ctx);
	fp12_init(aqqq, ctx);
	fp12_init(t, ctx);
	fp12_init(t0, ctx);
	fp12_init(t1, ctx);

	BIGNUM *exp_6t5 = SM9_get0_6t5();
	BIGNUM *exp_6t1 = SM9_get0_6t1();

	if (!fp12_copy(t, a)) {
		return 0;
	}
	if (!fp12_copy(t0, a)) {
		return 0;
	}

	n = BN_num_bits(k);
	
	fp12_fast_expo_p(aq, a, p, mont, ctx);
	fp12_fast_expo_p2(aqq, a, p, mont, ctx);
	fp12_fast_expo_p3(aqqq, a, p, mont, ctx);

	/* a^{q^2} * a^{2q} */
	fp12_mul_montgomery(t, aqq, aq, p, mont, ctx);
	fp12_mul_montgomery(t, t, aq, p, mont, ctx);
	
	/* t0 = a^(-6u-5) */
	fp12_inv(t0, a, p, ctx);

	begin = clock();
	fp12_pow_montgomery(t0, t0, exp_6t5, p, mont, ctx);
	end = clock();
	// printf("pow 1: %f msec\n", (double)(end-begin)/CLOCKS_PER_SEC*1000);

	/* t1 = a^(-6u-5)q */
	fp12_fast_expo_p(t1, t0, p, mont, ctx);

	fp12_mul_montgomery(t, t0, t, p, mont, ctx);
	fp12_mul_montgomery(t, t1, t, p, mont, ctx);

	begin = clock();
	fp12_pow_montgomery(t, t, exp_6t1, p, mont, ctx);
	end = clock();
	// printf("pow 2: %f msec\n", (double)(end-begin)/CLOCKS_PER_SEC*1000);

	fp12_mul_montgomery(t, t0, t, p, mont, ctx);
	fp12_mul_montgomery(t, t0, t, p, mont, ctx);
	fp12_mul_montgomery(t, t1, t, p, mont, ctx);
	fp12_mul_montgomery(t, aqqq, t, p, mont, ctx);

	fp12_sqr_montgomery(t0, a, p, mont, ctx);
	fp12_sqr_montgomery(t0, t0, p, mont, ctx);
	fp12_mul_montgomery(t, t0, t, p, mont, ctx);

	fp12_mul_montgomery(t1, aq, a, p, mont, ctx);
	fp12_sqr_montgomery(t0, t1, p, mont, ctx);
	fp12_sqr_montgomery(t0, t0, p, mont, ctx);
	fp12_sqr_montgomery(t0, t0, p, mont, ctx);
	fp12_mul_montgomery(t0, t1, t0, p, mont, ctx);
	fp12_mul_montgomery(t, t0, t, p, mont, ctx);

	if (!fp12_copy(t0, t)) {
		return 0;
	}

	if(!fp12_fast_expo_p2(t, t, p, mont, ctx)){
		return 0;
	}

	if (!fp12_mul_montgomery(t, t0, t, p, mont, ctx)) {
		return 0;
	}


	if (!fp12_inv(t0, t, p, ctx)) {
		return 0;
	}
	if (!fp12_fast_expo_p6(t, t, p, ctx)) {
		return 0;
	}
	if (!fp12_mul_montgomery(t, t0, t, p, mont, ctx)) {
		return 0;
	}
	if (!fp12_to_montgomery(t, t, mont, ctx)) {
		return 0;
	}

	fp12_copy(r, t);

	fp12_cleanup(t);
	fp12_cleanup(aq);
	fp12_cleanup(aqq);
	fp12_cleanup(aqqq);
	fp12_cleanup(t0);
	fp12_cleanup(t1);
	return 1;
}


static int rate_affine_montgomery(fp12_t f, const point_t *Q, const BIGNUM *xP, const BIGNUM *yP,
	const BIGNUM *a, const BIGNUM *k, const BIGNUM *p, BN_CTX *ctx)
{
	int ret = 0;
	int i, n;
	point_t T, Q1, Q2, tQ;
	fp12_t g, corr /* accumulate the coeffs*/, tmp;
	fp12_t xT, yT, zT;
	BIGNUM *tx, *ty;
	tx = BN_new();
	ty = BN_new();

	memset(&T, 0, sizeof(T));
	memset(&Q1, 0, sizeof(Q1));
	memset(&Q2, 0, sizeof(Q2));

	// initialize the mont ctx
	if(!mont)
	{
		mont = BN_MONT_CTX_new();
		BN_MONT_CTX_set(mont, p, ctx);
	}

	point_init(&T, ctx);
	point_init(&tQ, ctx);
	point_init(&Q1, ctx);
	point_init(&Q2, ctx);
	fp12_init(g, ctx);
	fp12_init(corr, ctx);
	fp12_init(tmp, ctx);
	fp12_init(xT, ctx);
	fp12_init(yT, ctx);
	fp12_init(zT, ctx);
	fp12_set_one(corr);

	fp12_set_one(f);

	point_to_montgomery(&tQ, Q, mont, ctx);
	point_copy_sm9(&T, &tQ);

	BN_to_montgomery(tx, xP, mont, ctx);
	BN_to_montgomery(ty, yP, mont, ctx);
	fp12_to_montgomery(corr, corr, mont, ctx);
	fp12_to_montgomery(f, f, mont, ctx);

	n = BN_num_bits(a);
	
	long begin, end;
	begin = clock();
	for (i = n - 2; i >= 0; i--) {
		/* f = f^2 * g_{T,T}(P) * 2YZ^3 */
	
		eval_tangent_affine_montgomery(g, &T, tx, ty, corr, p, mont, ctx);

		fp12_sqr_montgomery(f, f, p, mont, ctx);
		fp12_mul_montgomery(f, f, g, p, mont, ctx);

		/* T = 2 * T */
		point_dbl_affine_montgomery(&T, &T, p, mont, ctx);

		if (BN_is_bit_set(a, i)) {

			/* f = f * g_{T,Q}(P) */
			eval_line_affine_montgomery(g, &T, &tQ, tx, ty, corr, p, mont, ctx);

			fp12_mul_montgomery(f, f, g, p, mont, ctx);

			/* T = T + Q */
			point_add_affine_montgomery(&T, &T, &tQ, p, mont, ctx);
		}



	} // for
	end = clock();
	// printf("miller loop: %f msec\n", (double)(end-begin)/CLOCKS_PER_SEC*1000);

	begin = clock();
	/* Q1 = (x^p, y^p) */
	frobenius_montgomery(&Q1, &tQ, p, mont, ctx);

	/* Q2 = (x^(p^2), y^(p^2)) */
	frobenius_montgomery(&Q2, &Q1, p, mont, ctx);
	end = clock();
	// printf("frobenius: %f msec\n", (double)(end-begin)/CLOCKS_PER_SEC*1000);

	/* f = f * g_{T, Q1}(P) */
	eval_line_affine_montgomery(g, &T, &Q1, tx, ty, corr, p, mont, ctx);
	fp12_mul_montgomery(f, f, g, p, mont, ctx);

	/* T = T + Q1 */
	point_add_affine_montgomery(&T, &T, &Q1, p, mont, ctx);

	/* f = f * g_{T, -Q2}(P) */
	point_neg(&Q2, &Q2, p, ctx);
	eval_line_affine_montgomery(g, &T, &Q2, tx, ty, corr, p, mont, ctx);
	fp12_mul_montgomery(f, f, g, p, mont, ctx);


	begin = clock();
	fast_final_expo_montgomery(f, f, k, p, mont, ctx);
	end = clock();
	// printf("final expo: %f msec\n", (double)(end-begin)/CLOCKS_PER_SEC*1000);


	point_cleanup(&T);
	point_cleanup(&Q1);
	point_cleanup(&Q2);
	fp12_cleanup(g);
	return ret;
}





static int rate(fp12_t f, const point_t *Q, const BIGNUM *xP, const BIGNUM *yP,
	const BIGNUM *a, const BIGNUM *k, const BIGNUM *p, BN_CTX *ctx)
{

	int ret;
	clock_t start, end;
	start=clock();
	rate_affine_montgomery(f, Q, xP, yP, a, k, p, ctx);
	end=clock();
	// printf("rate time is: %f ms\n",(double)(end-start)/CLOCKS_PER_SEC*1000);


}

static int params_test(void)
{
	const BIGNUM *p = SM9_get0_prime();
	const BIGNUM *a = SM9_get0_loop_count();
	const BIGNUM *k = SM9_get0_final_exponent();

	// printf("p = %s\n", BN_bn2dec(p));
	// printf("a = %s\n", BN_bn2dec(a));
	// printf("k = %s\n", BN_bn2dec(k));

	return 1;
}

int rate_pairing(fp12_t r, const point_t *Q, const EC_POINT *P, BN_CTX *ctx)
{
	int ret = 1;
	const EC_GROUP *group;
	const BIGNUM *p;
	const BIGNUM *a;
	const BIGNUM *k;
	BIGNUM *xP = NULL;
	BIGNUM *yP = NULL;

	group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1);
	p = SM9_get0_prime();
	a = SM9_get0_loop_count();
#ifdef NOSM9_FAST
	k = SM9_get0_final_exponent();
#else
	k = SM9_get0_fast_final_exponent_p3();
#endif
	xP = BN_new();
	yP = BN_new();

	if (!P) {
		EC_POINT_get_affine_coordinates_GFp(group,
			EC_GROUP_get0_generator(group), xP, yP, ctx);
	} else {
		EC_POINT_get_affine_coordinates_GFp(group, P, xP, yP, ctx);
	}

	if (!Q) {
		point_t P2;
		point_init(&P2, ctx);
		point_set_affine_coordinates_bignums(&P2,
			SM9_get0_generator2_x0(),
			SM9_get0_generator2_x1(),
			SM9_get0_generator2_y0(),
			SM9_get0_generator2_y1());

		rate(r, &P2, xP, yP, a, k, p, ctx);

		point_cleanup(&P2);
	} else {
		if(!BN_is_one(Q->Z))
		{	
			fp2_t tx, ty;
			fp2_init(tx, ctx);
			fp2_init(ty, ctx);
			point_get_affine_coordinates_affine(Q, tx, ty, p, ctx);
			point_set_affine_coordinates(Q, tx, ty);
			fp2_cleanup(tx);
			fp2_cleanup(ty);
		}
		rate(r, Q, xP, yP, a, k, p, ctx);
	}

	BN_free(xP);
	BN_free(yP);
	EC_GROUP_clear_free(group);
	return ret;
}

#if SM9_TEST
static int rate_test(void)
{
	const char *Ppubs_str[] = {
		"29DBA116152D1F786CE843ED24A3B573414D2177386A92DD8F14D65696EA5E32",
		"9F64080B3084F733E48AFF4B41B565011CE0711C5E392CFB0AB1B6791B94C408",
		"41E00A53DDA532DA1A7CE027B7A46F741006E85F5CDFF0730E75C05FB4E3216D",
		"69850938ABEA0112B57329F447E3A0CBAD3E2FDB1A77F335E89E1408D0EF1C25"};
	const char *g_str[] = {
		"AAB9F06A4EEBA4323A7833DB202E4E35639D93FA3305AF73F0F071D7D284FCFB",
		"84B87422330D7936EABA1109FA5A7A7181EE16F2438B0AEB2F38FD5F7554E57A",
		"4C744E69C4A2E1C8ED72F796D151A17CE2325B943260FC460B9F73CB57C9014B",
		"B3129A75D31D17194675A1BC56947920898FBF390A5BF5D931CE6CBB3340F66D",
		"93634F44FA13AF76169F3CC8FBEA880ADAFF8475D5FD28A75DEB83C44362B439",
		"1604A3FCFA9783E667CE9FCB1062C2A5C6685C316DDA62DE0548BAA6BA30038B",
		"5A1AE172102EFD95DF7338DBC577C66D8D6C15E0A0158C7507228EFB078F42A6",
		"67E0E0C2EED7A6993DCE28FE9AA2EF56834307860839677F96685F2B44D0911F",
		"A01F2C8BEE81769609462C69C96AA923FD863E209D3CE26DD889B55E2E3873DB",
		"38BFFE40A22D529A0C66124B2C308DAC9229912656F62B4FACFCED408E02380F",
		"28B3404A61908F5D6198815C99AF1990C8AF38655930058C28C21BB539CE0000",
		"4E378FB5561CD0668F906B731AC58FEE25738EDF09CADC7A29C0ABC0177AEA6D"};

	BN_CTX *ctx = NULL;
	EC_GROUP *group = NULL;
	const EC_POINT *P1;
	point_t Ppubs;
	fp12_t g;
	int ok;

	ctx = BN_CTX_new();
	BN_CTX_start(ctx);
	group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1);
	P1 = EC_GROUP_get0_generator(group);

	point_init(&Ppubs, ctx);
	point_set_affine_coordinates_hex(&Ppubs, Ppubs_str);

	fp12_init(g, ctx);
	rate_pairing(g, &Ppubs, P1, ctx);

	ok = fp12_equ_hex(g, g_str, ctx);
	// printf("rate %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp12_cleanup(g);
	point_cleanup(&Ppubs);
	EC_GROUP_free(group);
	BN_CTX_free(ctx);

	return 1;
}
#endif

/* for SM9 sign, the (xP, yP) is the fixed generator of E(Fp)
 */
int SM9_rate_pairing(BIGNUM *r[12], const BIGNUM *xQ[2], const BIGNUM *yQ[2],
	const BIGNUM *xP, const BIGNUM *yP, BN_CTX *ctx)
{
	return 0;
}