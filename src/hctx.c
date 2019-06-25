#include <openssl/evp.h>
#include <assert.h>
#include <string.h>

#include "aes_mix.h"
#include "hctx.h"

static inline void get_irreducible_polynomial(BIGNUM* p, int size) {
    BN_zero(p);

    if (size == 16) {
        /* GF (2^128) -> x^128 + x^7 + x^2 + x + 1 */
        BN_set_bit(p,   0);
        BN_set_bit(p,   1);
        BN_set_bit(p,   2);
        BN_set_bit(p,   7);
        BN_set_bit(p, 128);

    } else if (size == 32) {
        /* GF (2^256) -> x^256 + x^10 + x^5 + x^2 + 1 */
        BN_set_bit(p,   0);
        BN_set_bit(p,   2);
        BN_set_bit(p,   5);
        BN_set_bit(p,  10);
        BN_set_bit(p, 256);

    } else if (size == 64) {
        /* GF (2^512) -> x^512 + x^8 + x^5 + x^2 + 1 */
        BN_set_bit(p,   0);
        BN_set_bit(p,   2);
        BN_set_bit(p,   5);
        BN_set_bit(p,   8);
        BN_set_bit(p, 512);

    } else {
        printf("No hardcoded polynomial for size %d.\n", size);
        exit(1);
    }
}

static HCTX_FN* create_hctx_fn(
        int size, const unsigned char *seed, int seedsize
){
    HCTX_FN* hctx_fn = (HCTX_FN*) malloc(sizeof(HCTX_FN));
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    unsigned char* tmp = OPENSSL_malloc(size);

    hctx_fn->ctx = BN_CTX_new();
    hctx_fn->p = BN_new();
    get_irreducible_polynomial(hctx_fn->p, size);

    const EVP_MD *type = size == 16 ? EVP_md5() :
        (size == 32 ? EVP_sha256() : EVP_sha512());
    D assert(EVP_MD_size(type) == size);

    hctx_fn->a = BN_new();
    EVP_DigestInit_ex(mdctx, type, NULL);
    EVP_DigestUpdate(mdctx, seed, seedsize);
    EVP_DigestFinal_ex(mdctx, tmp, NULL);
    BN_bin2bn(tmp, size, hctx_fn->a);

    hctx_fn->a_inv = BN_new();
    BN_GF2m_mod_inv(hctx_fn->a_inv, hctx_fn->a, hctx_fn->p, hctx_fn->ctx);

    hctx_fn->b = BN_new();
    EVP_DigestInit_ex(mdctx, type, NULL);
    EVP_DigestUpdate(mdctx, tmp, size);
    EVP_DigestFinal_ex(mdctx, tmp, NULL);
    BN_bin2bn(tmp, size, hctx_fn->b);

    hctx_fn->x = BN_new();
    hctx_fn->y = BN_new();

    OPENSSL_free(tmp);
    EVP_MD_CTX_destroy(mdctx);

    return hctx_fn;
}

static void destroy_hctx_fn(
        HCTX_FN* hctx_fn
){
    BN_free(hctx_fn->p);
    BN_free(hctx_fn->a);
    BN_free(hctx_fn->a_inv);
    BN_free(hctx_fn->b);
    BN_free(hctx_fn->x);
    BN_free(hctx_fn->y);
    BN_CTX_free(hctx_fn->ctx);
    free(hctx_fn);
}

HCTX* create_hctx(
        const unsigned char *seed, int seedsize
){
    HCTX* hctx = (HCTX*) malloc(sizeof(HCTX));
    hctx->p128 = create_hctx_fn(16, seed, seedsize);
    hctx->p256 = create_hctx_fn(32, seed, seedsize);
    hctx->p512 = create_hctx_fn(64, seed, seedsize);
    return hctx;
}

void destroy_hctx(
        HCTX* hctx
){
    destroy_hctx_fn(hctx->p128);
    destroy_hctx_fn(hctx->p256);
    destroy_hctx_fn(hctx->p512);
    free(hctx);
}

void do_h(
        HCTX* hctx, int size, const unsigned char* data, unsigned char* out
) {
    int leftbytes;
    HCTX_FN* fn = size == 16 ? hctx->p128 : (size == 32 ? hctx->p256 : hctx->p512);
    BN_bin2bn(data, size, fn->x);
    BN_GF2m_mod_mul(fn->y, fn->a, fn->x, fn->p, fn->ctx);
    BN_GF2m_add(fn->y, fn->y, fn->b);
    leftbytes = size - BN_num_bytes(fn->y);
    memset(out, 0, leftbytes);
    BN_bn2bin(fn->y, out + leftbytes);
}

void do_h_inv(
        HCTX* hctx, int size, const unsigned char* data, unsigned char* out
) {
    int leftbytes;
    HCTX_FN* fn = size == 16 ? hctx->p128 : (size == 32 ? hctx->p256 : hctx->p512);
    BN_bin2bn(data, size, fn->y);
    BN_GF2m_sub(fn->y, fn->y, fn->b);
    BN_GF2m_mod_mul(fn->x, fn->y, fn->a_inv, fn->p, fn->ctx);
    leftbytes = size - BN_num_bytes(fn->x);
    memset(out, 0, leftbytes);
    BN_bn2bin(fn->x, out + leftbytes);
}
