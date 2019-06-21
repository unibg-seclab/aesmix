#include <openssl/evp.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

#include "aes_mix.h"

#define SHUFFLE(STEP, OFF, BP, MACRO, BUFFER, TO, FROM)                       \
    unsigned int j, OFF, mask, start, dist;                                   \
    unsigned char *BP = buffer;                                               \
    mask = ((1 << DOF) - 1) << (STEP * DOF);                                  \
    dist = (1 << (STEP * DOF)) * MINI_SIZE;                                   \
    for (start=0; start < (1<<DIGITS); start=((start|mask)+1)&~mask) {        \
        for (j=0, off=start*MINI_SIZE; j < MINI_PER_BLOCK; ++j, off+=dist) {  \
            memcpy(TO, FROM, MINI_SIZE);                                      \
            BP += MINI_SIZE;                                                  \
        }                                                                     \
    }

static void recursive_mixing(EVP_CIPHER_CTX* ctx,
    const unsigned char* buffer, unsigned char* out, unsigned int size
){
    int outl;
    unsigned long partsize = size / 2;
    const unsigned char *left = buffer;
    const unsigned char *right = buffer + partsize;
    unsigned char *outleft = out;
    unsigned char *outright = out + partsize;
    unsigned char tmp[partsize];

    if (partsize == 16) {
        EVP_EncryptUpdate(ctx, outright, &outl, left, 16);
        D assert(16 == outl);
        memxor(outright, right, 16);

        EVP_EncryptUpdate(ctx, outleft, &outl, outright, 16);
        D assert(16 == outl);
        memxor(outleft, left, 16);

        EVP_EncryptUpdate(ctx, tmp, &outl, outleft, 16);
        D assert(16 == outl);
        memxor(outright, tmp, 16);

    } else if (partsize > 16) {
        exit(1);
        recursive_mixing(ctx, left, outright, partsize);
        memxor(outright, right, partsize);

        recursive_mixing(ctx, outright, outleft, partsize);
        memxor(outleft, left, partsize);

        recursive_mixing(ctx, outleft, tmp, partsize);
        memxor(outright, tmp, partsize);

    } else {  // partsize < BLOCK_SIZE
        printf("plaintext length wrong.");
        exit(EXIT_FAILURE);
    }
}

static inline void mix(EVP_CIPHER_CTX* ctx,
        const unsigned char* input, unsigned char* output
){
    const unsigned char* last = input + MACRO_SIZE;
    unsigned char tmp[BLOCK_SIZE];
    for ( ; input < last; input+=BLOCK_SIZE, output+=BLOCK_SIZE) {
        recursive_mixing(ctx, input, tmp, BLOCK_SIZE);
        memcpy(output, tmp, BLOCK_SIZE);
    }
}

/* static inline void do_step_encrypt(EVP_CIPHER_CTX* ctx, unsigned char* buffer, */
/*     const unsigned char* macro, unsigned char* out, const unsigned int step */
/* ){ */
/*     SHUFFLE(step, off, bp, macro, buffer, bp, macro + off); */
/*     mix(ctx, buffer, out); */
/* } */

/* static inline void do_step_decrypt(EVP_CIPHER_CTX* ctx, unsigned char* buffer, */
/*     const unsigned char* macro, unsigned char* out, const unsigned int step */
/* ){ */
/*     mix(ctx, macro, buffer); */
/*     SHUFFLE(step, off, bp, macro, buffer, out + off, bp); */
/* } */

inline void* memxor(void* dst, const void* src, size_t n){
    char *d =(char *) dst;
    char const *s =(char const*) src;
    for (; n>0; --n) {
        *d++ ^= *s++;
    }
    return dst;
}

static inline void mixencrypt_macroblock(const unsigned char* macro,
    unsigned char* out, unsigned char* buffer,
    const unsigned char* key, const unsigned char* iv
){
    int step;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if ( NULL == ctx ) {
        printf("Cannot allocate needed memory\n");
        exit(EXIT_FAILURE);
    }

    EVP_EncryptInit(ctx, EVP_aes_128_ecb(), key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0); // disable padding

    // Step 0
    memxor((unsigned char*) macro, iv, BLOCK_SIZE);  // add IV to input
    /* memcpy(buffer, macro, MACRO_SIZE); */
    mix(ctx, macro, out);
    memxor((unsigned char*) macro, iv, BLOCK_SIZE);  // add IV to input

    // Steps 1 -> N
    /* for (step=1; step < DIGITS/DOF; ++step) { */
    /*     do_step_encrypt(ctx, buffer, out, out, step); */
    /* } */

    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
}

static inline void mixdecrypt_macroblock(const unsigned char* macro,
    unsigned char* out, unsigned char* buffer,
    const unsigned char* key, const unsigned char* iv
){
    int step;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if ( NULL == ctx ) {
        printf("Cannot allocate needed memory\n");
        exit(EXIT_FAILURE);
    }

    EVP_EncryptInit(ctx, EVP_aes_128_ecb(), key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0); // disable padding

    // Steps N -> 1
    /* for (step = DIGITS/DOF - 1; step >= 1; --step) { */
    /*     do_step_decrypt(ctx, buffer, macro, out, step); */
    /*     macro = out;   // this is needed to avoid a starting memcpy */
    /* } */

    // Step 0
    /* memcpy(buffer, out, MACRO_SIZE); */
    mix(ctx, macro, out);
    memxor(out, iv, BLOCK_SIZE);         // remove IV from output

    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
}

inline void mixprocess(mixfn fn, const unsigned char* data,
    unsigned char* out, const unsigned long size,
    const unsigned char* key, const unsigned char* iv
){
    assert(0 == size % MACRO_SIZE);
    assert(0 == BLOCK_SIZE % 16); // iv is BLOCK_SIZE and passes through AES
    D assert(1 == ISPOWEROF(MINI_PER_MACRO, BLOCK_SIZE / MINI_SIZE)
             && "MINI_PER_MACRO must be a power of (BLOCK_SIZE / MINI_SIZE)");

    int outl;
    const unsigned char* last = data + size;
    unsigned char* buffer = (unsigned char*) malloc(MACRO_SIZE);
    unsigned char* miv = (unsigned char*) malloc(BLOCK_SIZE);

    EVP_CIPHER_CTX *mivctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(mivctx, EVP_aes_128_ecb(), key, iv);
    EVP_CIPHER_CTX_set_padding(mivctx, 0);

    if ( NULL == buffer || NULL == miv || NULL == mivctx) {
        printf("Cannot allocate needed memory\n");
        exit(EXIT_FAILURE);
    }

    memcpy(miv, iv, BLOCK_SIZE);
    for ( ; data < last; data+=MACRO_SIZE, out+=MACRO_SIZE) {
        fn(data, out, buffer, key, miv);
        EVP_EncryptUpdate(mivctx, miv, &outl, miv, BLOCK_SIZE);
        D assert(BLOCK_SIZE == outl);
    }

    EVP_CIPHER_CTX_cleanup(mivctx);
    EVP_CIPHER_CTX_free(mivctx);
    free(buffer);
    free(miv);
}

void mixencrypt(const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
){
    mixprocess(mixencrypt_macroblock, data, out, size, key, iv);
}

void mixdecrypt(const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
){
    mixprocess(mixdecrypt_macroblock, data, out, size, key, iv);
}
