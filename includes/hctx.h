#ifndef HCTX_H
#define HCTX_H

#include <openssl/bn.h>


typedef struct hctx_fn_s {
    BN_CTX *ctx;
    BIGNUM* p;
    BIGNUM* a;
    BIGNUM* a_inv;
    BIGNUM* b;
    BIGNUM *x;
    BIGNUM *y;
} HCTX_FN;


typedef struct hctx_s {
    HCTX_FN *p128;
    HCTX_FN *p256;
    HCTX_FN *p512;
} HCTX;


HCTX* create_hctx(const unsigned char *seed, int seedsize);

void destroy_hctx(HCTX* hctx);

#endif // HCTX_H
