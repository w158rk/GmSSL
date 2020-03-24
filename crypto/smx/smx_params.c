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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>


#include "../bn/bn_lcl.h"
#include "internal/cryptlib.h"


#define BN_SMX_BN256_TOP (256+BN_BITS2-1)/BN_BITS2
#define BN_SMX_LOOP_TOP (66+BN_BITS2-1)/BN_BITS2
#define BN_SMX_FINAL_EXPO_TOP (2816+BN_BITS2-1)/BN_BITS2
#define BN_SMX_FAST_FINAL_EXPO_P2_TOP (256+BN_BITS2-1)/BN_BITS2
#define BN_SMX_FAST_FINAL_EXPO_P3_TOP (768+BN_BITS2-1)/BN_BITS2

#if BN_BITS2 == 64
static const BN_ULONG _sm9bn256v1_prime[BN_SMX_BN256_TOP] = {
	0xE56F9B27E351457DULL, 0x21F2934B1A7AEEDBULL,
	0xD603AB4FF58EC745ULL, 0xB640000002A3A6F1ULL,
};

static const BN_ULONG _sm9bn256v1_order[BN_SMX_BN256_TOP] = {
	0xE56EE19CD69ECF25ULL, 0x49F2934B18EA8BEEULL,
	0xD603AB4FF58EC744ULL, 0xB640000002A3A6F1ULL,
};

static const BN_ULONG _sm9bn256v1_order_minus_one[BN_SMX_BN256_TOP] = {
	0xE56EE19CD69ECF24ULL, 0x49F2934B18EA8BEEULL,
	0xD603AB4FF58EC744ULL, 0xB640000002A3A6F1ULL,
};

static const BN_ULONG _sm9bn256v1_loop[BN_SMX_LOOP_TOP] = {
	0x400000000215D93EULL, 0x02ULL,
};

static const BN_ULONG _sm9bn256v1_x2[][BN_SMX_BN256_TOP] = {
	{0xF9B7213BAF82D65BULL, 0xEE265948D19C17ABULL,
	 0xD2AAB97FD34EC120ULL, 0x3722755292130B08ULL},
	{0x54806C11D8806141ULL, 0xF1DD2C190F5E93C4ULL,
	 0x597B6027B441A01FULL, 0x85AEF3D078640C98ULL}
};

static const BN_ULONG _sm9bn256v1_y2[][BN_SMX_BN256_TOP] = {
	{0x6215BBA5C999A7C7ULL, 0x47EFBA98A71A0811ULL,
	 0x5F3170153D278FF2ULL, 0xA7CF28D519BE3DA6ULL},
	{0x856DC76B84EBEB96ULL, 0x0736A96FA347C8BDULL,
	 0x66BA0D262CBEE6EDULL, 0x17509B092E845C12ULL}
};

// (q^12-1)/n
static const BN_ULONG _sm9bn256v1_final_expo[BN_SMX_FINAL_EXPO_TOP] = {
	0x2FACDD0F0D042330ULL, 0xB19FE1764AC0B748ULL,
	0xC6135FEC864E1676ULL, 0x8E4890AB7E824DC7ULL,
	0x5B83E3D7E2D0B969ULL, 0xCBD806A8225955B0ULL,
	0x6FE5E935A4B5F799ULL, 0x0B48EE8FD4C31B8FULL,
	0x8478B1A3E843D1FAULL, 0xBB6793F9FE39F256ULL,
	0xB760558913D719F2ULL, 0xEFE915CAB1B62D11ULL,
	0x1D16182C1D978AD0ULL, 0x5BBD6C4AA78C62F3ULL,
	0xF703B00C9E53535AULL, 0x0F4C6983D64089BDULL,
	0xC3E3945F87BF2203ULL, 0xE804F361D729E88DULL,
	0x6B948EBD4AA170BAULL, 0x4550E98DCA2042C3ULL,
	0x5A54D51E82F7DD63ULL, 0x2FB14FC5412315ECULL,
	0xE2C3601D19F32C69ULL, 0x335D59C358AAC66EULL,
	0x96FD3135583D5AA1ULL, 0xB78BD480FF56FA06ULL,
	0xA4DEFA394C04689AULL, 0xCB5A6B4B9EC19BA7ULL,
	0x80357732739295EDULL, 0x3BED65F00632C9CCULL,
	0x93DC562FA23AFA5AULL, 0xF1C8D7D0598EEE9BULL,
	0xB97559B180EE9629ULL, 0x5ED57CD410455806ULL,
	0x239E0CB2A1387366ULL, 0x96F691269CEB7907ULL,
	0x93B5122D974B7BA1ULL, 0xBE8CB0476C5042CBULL,
	0x9BF41BCB4067AA64ULL, 0xDD9D1D3019DBA153ULL,
	0xC16BE7FBACA54D38ULL, 0xACEF6F4E86411255ULL,
	0x1A09A6AE43ADE454ULL, 0x061835E8B1259499ULL,
};

static const BN_ULONG _sm9bn256v1_fast_final_expo_p2[][BN_SMX_FAST_FINAL_EXPO_P2_TOP] = {
	{0xD5FC11967BE65334ULL, 0x780272354F8B78F4ULL,
	 0xF300000002A3A6F2ULL},
	{0x0F738991676AF249ULL, 0xA9F02115CAEF75E7ULL,
	 0xE303AB4FF2EB2052ULL, 0xB640000002A3A6F0ULL},
	{0xD5FC11967BE65333ULL, 0x780272354F8B78F4ULL,
	 0xF300000002A3A6F2ULL},
	{0x0F738991676AF24AULL, 0xA9F02115CAEF75E7ULL,
	 0xE303AB4FF2EB2052ULL, 0xB640000002A3A6F0ULL}
};

static const BN_ULONG _sm9bn256v1_fast_final_expo_p3[BN_SMX_FAST_FINAL_EXPO_P3_TOP] = {
	0xA9B2ADA593152855ULL, 0x44BF9D0FA74DDFB7ULL,
	0x83687EE0C6D9188CULL, 0xE0D49DE3AA8A4748ULL,
	0x0DA3D71BCDB13FE5ULL, 0xA5782C82FDB6B0A1ULL,
	0x7C0CA02D9B0D8649ULL, 0xBA4CADE09029E471ULL,
	0xDC53E586930846F1ULL, 0xD62CD8FB7B497A0AULL,
	0xF12FCAD3B31FE2B0ULL, 0x5C5E452404034E2AULL,
};




#elif BN_BITS2 == 32
static const BN_ULONG _sm9bn256v1_prime[BN_SMX_BN256_TOP] = {
	0xE351457D, 0xE56F9B27, 0x1A7AEEDB, 0x21F2934B,
	0xF58EC745, 0xD603AB4F, 0x02A3A6F1, 0xB6400000,
};

static const BN_ULONG _sm9bn256v1_order[BN_SMX_BN256_TOP] = {
	0xD69ECF25, 0xE56EE19C, 0x18EA8BEE, 0x49F2934B,
	0xF58EC744, 0xD603AB4F, 0x02A3A6F1, 0xB6400000,
};

static const BN_ULONG _sm9bn256v1_order_minus_one[BN_SMX_BN256_TOP] = {
	0xD69ECF24, 0xE56EE19C, 0x18EA8BEE, 0x49F2934B,
	0xF58EC744, 0xD603AB4F, 0x02A3A6F1, 0xB6400000,
};

static const BN_ULONG _sm9bn256v1_loop[BN_SMX_LOOP_TOP] = {
	0x0215D93E, 0x40000000, 0x02,
};

static const BN_ULONG _sm9bn256v1_x2[][BN_SMX_BN256_TOP] = {
	{0xAF82D65B, 0xF9B7213B, 0xD19C17AB, 0xEE265948,
	 0xD34EC120, 0xD2AAB97F, 0x92130B08, 0x37227552},
	{0xD8806141, 0x54806C11, 0x0F5E93C4, 0xF1DD2C19,
	 0xB441A01F, 0x597B6027, 0x78640C98, 0x85AEF3D0}
};

static const BN_ULONG _sm9bn256v1_y2[][BN_SMX_BN256_TOP] = {
	{0xC999A7C7, 0x6215BBA5, 0xA71A0811, 0x47EFBA98,
	 0x3D278FF2, 0x5F317015, 0x19BE3DA6, 0xA7CF28D5},
	{0x84EBEB96, 0x856DC76B, 0xA347C8BD, 0x0736A96F,
	 0x2CBEE6ED, 0x66BA0D26, 0x2E845C12, 0x17509B09}
};

static const BN_ULONG _sm9bn256v1_final_expo[BN_SMX_FINAL_EXPO_TOP] = {
	0x0D042330, 0x2FACDD0F, 0x4AC0B748, 0xB19FE176,
	0x864E1676, 0xC6135FEC, 0x7E824DC7, 0x8E4890AB,
	0xE2D0B969, 0x5B83E3D7, 0x225955B0, 0xCBD806A8,
	0xA4B5F799, 0x6FE5E935, 0xD4C31B8F, 0x0B48EE8F,
	0xE843D1FA, 0x8478B1A3, 0xFE39F256, 0xBB6793F9,
	0x13D719F2, 0xB7605589, 0xB1B62D11, 0xEFE915CA,
	0x1D978AD0, 0x1D16182C, 0xA78C62F3, 0x5BBD6C4A,
	0x9E53535A, 0xF703B00C, 0xD64089BD, 0x0F4C6983,
	0x87BF2203, 0xC3E3945F, 0xD729E88D, 0xE804F361,
	0x4AA170BA, 0x6B948EBD, 0xCA2042C3, 0x4550E98D,
	0x82F7DD63, 0x5A54D51E, 0x412315EC, 0x2FB14FC5,
	0x19F32C69, 0xE2C3601D, 0x58AAC66E, 0x335D59C3,
	0x583D5AA1, 0x96FD3135, 0xFF56FA06, 0xB78BD480,
	0x4C04689A, 0xA4DEFA39, 0x9EC19BA7, 0xCB5A6B4B,
	0x739295ED, 0x80357732, 0x0632C9CC, 0x3BED65F0,
	0xA23AFA5A, 0x93DC562F, 0x598EEE9B, 0xF1C8D7D0,
	0x80EE9629, 0xB97559B1, 0x10455806, 0x5ED57CD4,
	0xA1387366, 0x239E0CB2, 0x9CEB7907, 0x96F69126,
	0x974B7BA1, 0x93B5122D, 0x6C5042CB, 0xBE8CB047,
	0x4067AA64, 0x9BF41BCB, 0x19DBA153, 0xDD9D1D30,
	0xACA54D38, 0xC16BE7FB, 0x86411255, 0xACEF6F4E,
	0x43ADE454, 0x1A09A6AE, 0xB1259499, 0x061835E8,
};

static const BN_ULONG _sm9bn256v1_fast_final_expo_p2[][BN_SMX_FAST_FINAL_EXPO_P2_TOP] = {
	{0x7BE65334, 0xD5FC1196, 0x4F8B78F4, 0x78027235,
	 0x02A3A6F2, 0xF3000000},
	{0x676AF249, 0x0F738991, 0xCAEF75E7, 0xA9F02115,
	 0xF2EB2052, 0xE303AB4F, 0x02A3A6F0, 0xB6400000},
	{0x7BE65333, 0xD5FC1196, 0x4F8B78F4, 0x78027235,
	 0x02A3A6F2, 0xF3000000},
	{0x676AF24A, 0x0F738991, 0xCAEF75E7, 0xA9F02115,
	 0xF2EB2052, 0xE303AB4F, 0x02A3A6F0, 0xB6400000}
};

static const BN_ULONG _sm9bn256v1_fast_final_expo_p3[BN_SMX_FAST_FINAL_EXPO_P3_TOP] = {
	0x93152855, 0xA9B2ADA5, 0xA74DDFB7, 0x44BF9D0F,
	0xC6D9188C, 0x83687EE0, 0xAA8A4748, 0xE0D49DE3,
	0xCDB13FE5, 0x0DA3D71B, 0xFDB6B0A1, 0xA5782C82,
	0x9B0D8649, 0x7C0CA02D, 0x9029E471, 0xBA4CADE0,
	0x930846F1, 0xDC53E586, 0x7B497A0A, 0xD62CD8FB,
	0xB31FE2B0, 0xF12FCAD3, 0x04034E2A, 0x5C5E4524,
};

#else
# error "unsupported BN_BITS2"
#endif

static const BIGNUM _bignum_sm9bn256v1_prime = {
	(BN_ULONG *)_sm9bn256v1_prime,
	BN_SMX_BN256_TOP,
	BN_SMX_BN256_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_sm9bn256v1_order = {
	(BN_ULONG *)_sm9bn256v1_order,
	BN_SMX_BN256_TOP,
	BN_SMX_BN256_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_sm9bn256v1_order_minus_one = {
	(BN_ULONG *)_sm9bn256v1_order_minus_one,
	BN_SMX_BN256_TOP,
	BN_SMX_BN256_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_sm9bn256v1_loop = {
	(BN_ULONG *)_sm9bn256v1_loop,
	BN_SMX_LOOP_TOP,
	BN_SMX_LOOP_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_sm9bn256v1_final_expo = {
	(BN_ULONG *)_sm9bn256v1_final_expo,
	BN_SMX_FINAL_EXPO_TOP,
	BN_SMX_FINAL_EXPO_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_sm9bn256v1_fast_final_expo_p20 = {
	(BN_ULONG *)_sm9bn256v1_fast_final_expo_p2[0],
	BN_SMX_FAST_FINAL_EXPO_P2_TOP,
	BN_SMX_FAST_FINAL_EXPO_P2_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_sm9bn256v1_fast_final_expo_p21 = {
	(BN_ULONG *)_sm9bn256v1_fast_final_expo_p2[1],
	BN_SMX_FAST_FINAL_EXPO_P2_TOP,
	BN_SMX_FAST_FINAL_EXPO_P2_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_sm9bn256v1_fast_final_expo_p22 = {
	(BN_ULONG *)_sm9bn256v1_fast_final_expo_p2[2],
	BN_SMX_FAST_FINAL_EXPO_P2_TOP,
	BN_SMX_FAST_FINAL_EXPO_P2_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_sm9bn256v1_fast_final_expo_p23 = {
	(BN_ULONG *)_sm9bn256v1_fast_final_expo_p2[3],
	BN_SMX_FAST_FINAL_EXPO_P2_TOP,
	BN_SMX_FAST_FINAL_EXPO_P2_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_sm9bn256v1_fast_final_expo_p3 = {
	(BN_ULONG *)_sm9bn256v1_fast_final_expo_p3,
	BN_SMX_FAST_FINAL_EXPO_P3_TOP,
	BN_SMX_FAST_FINAL_EXPO_P3_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_sm9bn256v1_x20 = {
	(BN_ULONG *)_sm9bn256v1_x2[0],
	BN_SMX_BN256_TOP,
	BN_SMX_BN256_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_sm9bn256v1_x21 = {
	(BN_ULONG *)_sm9bn256v1_x2[1],
	BN_SMX_BN256_TOP,
	BN_SMX_BN256_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_sm9bn256v1_y20 = {
	(BN_ULONG *)_sm9bn256v1_y2[0],
	BN_SMX_BN256_TOP,
	BN_SMX_BN256_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_sm9bn256v1_y21 = {
	(BN_ULONG *)_sm9bn256v1_y2[1],
	BN_SMX_BN256_TOP,
	BN_SMX_BN256_TOP,
	0,
	BN_FLG_STATIC_DATA
};

const BIGNUM *SMX_get0_generator2_x0(void)
{
	return &_bignum_sm9bn256v1_x20;
}

const BIGNUM *SMX_get0_generator2_x1(void)
{
	return &_bignum_sm9bn256v1_x21;
}

const BIGNUM *SMX_get0_generator2_y0(void)
{
	return &_bignum_sm9bn256v1_y20;
}

const BIGNUM *SMX_get0_generator2_y1(void)
{
	return &_bignum_sm9bn256v1_y21;
}

const BIGNUM *SMX_get0_prime(void)
{
	return &_bignum_sm9bn256v1_prime;
}

const BIGNUM *SMX_get0_order(void)
{
	return &_bignum_sm9bn256v1_order;
}

const BIGNUM *SMX_get0_order_minus_one(void)
{
	return &_bignum_sm9bn256v1_order_minus_one;
}

const BIGNUM *SMX_get0_loop_count(void)
{
	return &_bignum_sm9bn256v1_loop;
}

const BIGNUM *SMX_get0_final_exponent(void)
{
	return &_bignum_sm9bn256v1_final_expo;
}

const BIGNUM *SMX_get0_fast_final_exponent_p20(void)
{
	return &_bignum_sm9bn256v1_fast_final_expo_p20;
}

const BIGNUM *SMX_get0_fast_final_exponent_p21(void)
{
	return &_bignum_sm9bn256v1_fast_final_expo_p21;
}

const BIGNUM *SMX_get0_fast_final_exponent_p22(void)
{
	return &_bignum_sm9bn256v1_fast_final_expo_p22;
}

const BIGNUM *SMX_get0_fast_final_exponent_p23(void)
{
	return &_bignum_sm9bn256v1_fast_final_expo_p23;
}

const BIGNUM *SMX_get0_fast_final_exponent_p3(void)
{
	return &_bignum_sm9bn256v1_fast_final_expo_p3;
}



static const BN_ULONG _sm9bn256v1_inv_unit[] = 
{
	0xF2B7CD93F1A8A2BEULL, 0x90F949A58D3D776DULL,
	0xEB01D5A7FAC763A2ULL, 0x5B2000000151D378ULL
};

static const BN_ULONG _sm9bn256v1_inv_unit_montgomery[] = 
{
	0xE56F9B27E351457DULL, 0x21F2934B1A7AEEDBULL,
	0xD603AB4FF58EC745ULL, 0x3640000002A3A6F1ULL
};

static const BN_ULONG _sm9bn256v1_one_montgomery[] = 
{
	0x1A9064D81CAEBA83ULL, 0xDE0D6CB4E5851124ULL,
	0x29FC54B00A7138BAULL, 0x49BFFFFFFD5C590EULL
};



static const BN_ULONG _sm9bn256v1_t[] = 
{
	0x600000000058F98AULL
};

static const BN_ULONG _sm9bn256v1_6t1[] = 
{
	0x0000B98B0CB27659ULL, 0xD8000000019062EDULL
};

static const BN_ULONG _sm9bn256v1_6t5[] = 
{
	0x400000000215D941ULL, 0x2ULL
};


static const BN_ULONG _sm9bn256v1_fast_final_expo_p[][BN_SMX_FAST_FINAL_EXPO_P2_TOP] = {
	{},
	{0xA91D8354377B698BULL, 0x47C5C86E0DDD04EDULL,
	 0x843C6CFA9C086749ULL, 0x3F23EA58E5720BDBULL},
	{0xD5FC11967BE65334ULL, 0x780272354F8B78F4ULL,
	 0xF300000002A3A6F2ULL},
	{0xF5B21FD3DA24D011ULL, 0x9F9D411806DC5177ULL,
	 0xF55ACC93EE0BAF15ULL, 0x6C648DE5DC0A3F2CULL},
	{0xD5FC11967BE65333ULL, 0x780272354F8B78F4ULL,
	 0xF300000002A3A6F2ULL},
	{0x4C949C7FA2A96686ULL, 0x57D778A9F8FF4C8AULL,
	 0x711E5F99520347CCULL, 0x2D40A38CF6983351ULL},
	{},
	{0x3C5217D3ABD5DBF2ULL, 0xDA2CCADD0C9DE9EEULL,
	 0x51C73E5559865FFBULL, 0x771C15A71D319B16ULL},
	{0x0F738991676AF249ULL, 0xA9F02115CAEF75E7ULL,
	 0xE303AB4FF2EB2052ULL, 0xB640000002A3A6F0ULL},
	{0xEFBD7B54092C756CULL, 0x82555233139E9D63ULL,
	 0xE0A8DEBC0783182FULL, 0x49DB721A269967C4ULL},
	{0x0F738991676AF24AULL, 0xA9F02115CAEF75E7ULL,
	 0xE303AB4FF2EB2052ULL, 0xB640000002A3A6F0ULL},
	{0x98DAFEA840A7DEF7ULL, 0xCA1B1AA1217BA251ULL,
	 0x64E54BB6A38B7F78ULL, 0x88FF5C730C0B73A0ULL}
};

#define BN_SMX_T_TOP (64+BN_BITS2-1)/BN_BITS2
#define BN_SMX_6T1_TOP (128+BN_BITS2-1)/BN_BITS2
#define BN_SMX_6T5_TOP (66+BN_BITS2-1)/BN_BITS2
#define BN_SMX_FAST_FINAL_EXPO_P3_TOP BN_SMX_FAST_FINAL_EXPO_P2_TOP

static const BIGNUM _bignum_sm9bn256v1_inv_unit = {
	(BN_ULONG *) _sm9bn256v1_inv_unit,
	BN_SMX_BN256_TOP,
	BN_SMX_BN256_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_sm9bn256v1_inv_unit_montgomery = {
	(BN_ULONG *) _sm9bn256v1_inv_unit_montgomery,
	BN_SMX_BN256_TOP,
	BN_SMX_BN256_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_sm9bn256v1_one_montgomery = {
	(BN_ULONG *) _sm9bn256v1_one_montgomery,
	BN_SMX_BN256_TOP,
	BN_SMX_BN256_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_sm9bn256v1_t = {
	(BN_ULONG *) _sm9bn256v1_t,
	BN_SMX_T_TOP,
	BN_SMX_T_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_sm9bn256v1_fast_final_expo_pto1 = {
	(BN_ULONG *) _sm9bn256v1_fast_final_expo_p[1],
	BN_SMX_BN256_TOP,
	BN_SMX_BN256_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_sm9bn256v1_fast_final_expo_pto2 = {
	(BN_ULONG *) _sm9bn256v1_fast_final_expo_p[2],
	BN_SMX_BN256_TOP,
	BN_SMX_BN256_TOP,
	0,
	BN_FLG_STATIC_DATA
};


static const BIGNUM _bignum_sm9bn256v1_fast_final_expo_pto3 = {
	(BN_ULONG *) _sm9bn256v1_fast_final_expo_p[3],
	BN_SMX_BN256_TOP,
	BN_SMX_BN256_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_sm9bn256v1_fast_final_expo_pto4 = {
	(BN_ULONG *) _sm9bn256v1_fast_final_expo_p[4],
	BN_SMX_BN256_TOP,
	BN_SMX_BN256_TOP,
	0,
	BN_FLG_STATIC_DATA
};


static const BIGNUM _bignum_sm9bn256v1_fast_final_expo_pto5 = {
	(BN_ULONG *) _sm9bn256v1_fast_final_expo_p[5],
	BN_SMX_BN256_TOP,
	BN_SMX_BN256_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_sm9bn256v1_fast_final_expo_pto7 = {
	(BN_ULONG *) _sm9bn256v1_fast_final_expo_p[7],
	BN_SMX_BN256_TOP,
	BN_SMX_BN256_TOP,
	0,
	BN_FLG_STATIC_DATA
};


static const BIGNUM _bignum_sm9bn256v1_fast_final_expo_pto8 = {
	(BN_ULONG *) _sm9bn256v1_fast_final_expo_p[8],
	BN_SMX_BN256_TOP,
	BN_SMX_BN256_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_sm9bn256v1_fast_final_expo_pto9 = {
	(BN_ULONG *) _sm9bn256v1_fast_final_expo_p[9],
	BN_SMX_BN256_TOP,
	BN_SMX_BN256_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_sm9bn256v1_fast_final_expo_pto10 = {
	(BN_ULONG *) _sm9bn256v1_fast_final_expo_p[10],
	BN_SMX_BN256_TOP,
	BN_SMX_BN256_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_sm9bn256v1_fast_final_expo_pto11 = {
	(BN_ULONG *) _sm9bn256v1_fast_final_expo_p[11],
	BN_SMX_BN256_TOP,
	BN_SMX_BN256_TOP,
	0,
	BN_FLG_STATIC_DATA
};


static const BIGNUM _bignum_sm9bn256v1_6t1 = {
	(BN_ULONG *) _sm9bn256v1_6t1,
	BN_SMX_6T1_TOP,
	BN_SMX_6T1_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_sm9bn256v1_6t5 = {
	(BN_ULONG *) _sm9bn256v1_6t5,
	BN_SMX_6T5_TOP,
	BN_SMX_6T5_TOP,
	0,
	BN_FLG_STATIC_DATA
};


const BIGNUM *SMX_get0_inv_unit(void)
{
	return &_bignum_sm9bn256v1_inv_unit;
}

const BIGNUM *SMX_get0_inv_unit_montgomery(void)
{
	return &_bignum_sm9bn256v1_inv_unit_montgomery;
}

const BIGNUM *SMX_get0_one_montgomery(void)
{
	return &_bignum_sm9bn256v1_one_montgomery;
}

const BIGNUM *SMX_get0_t(void)
{
	return &_bignum_sm9bn256v1_t;
}

const BIGNUM *SMX_get0_fast_final_expo_pto1(void)
{
	return &_bignum_sm9bn256v1_fast_final_expo_pto1;
}

const BIGNUM *SMX_get0_fast_final_expo_pto2(void)
{
	return &_bignum_sm9bn256v1_fast_final_expo_pto2;
}

const BIGNUM *SMX_get0_fast_final_expo_pto3(void)
{
	return &_bignum_sm9bn256v1_fast_final_expo_pto3;
}

const BIGNUM *SMX_get0_fast_final_expo_pto4(void)
{
	return &_bignum_sm9bn256v1_fast_final_expo_pto4;
}

const BIGNUM *SMX_get0_fast_final_expo_pto5(void)
{
	return &_bignum_sm9bn256v1_fast_final_expo_pto5;
}

const BIGNUM *SMX_get0_fast_final_expo_pto7(void)
{
	return &_bignum_sm9bn256v1_fast_final_expo_pto7;
}

const BIGNUM *SMX_get0_fast_final_expo_pto8(void)
{
	return &_bignum_sm9bn256v1_fast_final_expo_pto8;
}

const BIGNUM *SMX_get0_fast_final_expo_pto9(void)
{
	return &_bignum_sm9bn256v1_fast_final_expo_pto9;
}

const BIGNUM *SMX_get0_fast_final_expo_pto10(void)
{
	return &_bignum_sm9bn256v1_fast_final_expo_pto10;
}

const BIGNUM *SMX_get0_fast_final_expo_pto11(void)
{
	return &_bignum_sm9bn256v1_fast_final_expo_pto11;
}

const BIGNUM *SMX_get0_6t5(void)
{
	return &_bignum_sm9bn256v1_6t5;
}

const BIGNUM *SMX_get0_6t1(void)
{
	return &_bignum_sm9bn256v1_6t1;
}