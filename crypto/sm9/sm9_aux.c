/*
 * @Date: 2021-02-01 23:04:29
 * @LastEditors: Ruikai Wang
 * @LastEditTime: 2021-02-01 23:20:27
 * @FilePath: /GmSSL/crypto/sm9/sm9_aux.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/sm9.h>
#include "sm9_lcl.h"

/**
 * @description: 
 * @param {BIGNUM} **out
 * @param {char} *id
 * @param {size_t} idlen
 * @param {short} hash   [input]     0 for SM3, 1 for sha256
 * @return {*}
 */
int SM9_aux_hash(BIGNUM **out, char *id, size_t idlen, short hash) {
    
    int ret = 0;
    const EVP_MD *hash_md = NULL;
    BIGNUM *n = SM9_get0_order();
    BN_CTX *bn_ctx = NULL;

	if (!(bn_ctx = BN_CTX_new())) {
		goto end;
	}
	BN_CTX_start(bn_ctx);

    switch (hash)
    {
    case 0:
        hash_md = EVP_sm3();
        break;
    
    default:
        hash_md = EVP_sm3();
        break;
    }

	if (!SM9_hash1(hash_md, out, id, idlen, SM9_HID_ENC, n, bn_ctx)) {
		goto end;
	}    


    ret = 1;

end:

    if (bn_ctx) {
		BN_CTX_end(bn_ctx);
		BN_CTX_free(bn_ctx);
	}

    return ret;

}