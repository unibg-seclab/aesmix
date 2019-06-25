#include <openssl/evp.h>
#include <openssl/bn.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

#include "aes_mix.h"
#include "hctx.h"


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


#ifndef NO_NAOR
#define MIX recursive_mixing_naor
#define UNMIX recursive_unmixing_naor

static void recursive_mixing_naor(EVP_CIPHER_CTX* ctx,
        const unsigned char* buffer, unsigned char* out,
        unsigned int size, HCTX* hctx1, HCTX* hctx2
){
    int outl;
    unsigned long partsize = size / 2;
    unsigned char *outleft = out;
    unsigned char *outright = out + partsize;
    unsigned char tmp[partsize];

    do_h(hctx1, size, buffer, out);
    D { unsigned char test[size];
        do_h_inv(hctx1, size, out, test);
        assert(0 == memcmp(buffer, test, size)); }

    if (partsize == 16) {
        D printf("16: AES\n");
        EVP_EncryptUpdate(ctx, tmp, &outl, outright, 16);
        D assert(16 == outl);
        memxor(outleft, tmp, 16);

        EVP_EncryptUpdate(ctx, tmp, &outl, outleft, 16);
        D assert(16 == outl);
        memxor(outright, tmp, 16);

    } else if (partsize > 16) {
        D printf("%lu: RECURSE\n", partsize);
        recursive_mixing_naor(ctx, outright, tmp, partsize, hctx1, hctx2);
        memxor(outleft, tmp, partsize);

        recursive_mixing_naor(ctx, outleft, tmp, partsize, hctx1, hctx2);
        memxor(outright, tmp, partsize);

    } else {  // partsize < BLOCK_SIZE
        printf("plaintext length wrong.");
        exit(EXIT_FAILURE);
    }

    do_h_inv(hctx2, size, out, out);
}

static void recursive_unmixing_naor(EVP_CIPHER_CTX* ctx,
        const unsigned char* buffer, unsigned char* out,
        unsigned int size, HCTX* hctx1, HCTX* hctx2
){
    int outl;
    unsigned long partsize = size / 2;
    unsigned char *outleft = out;
    unsigned char *outright = out + partsize;
    unsigned char tmp[partsize];

    do_h(hctx2, size, buffer, out);
    D { unsigned char test[size];
        do_h_inv(hctx1, size, out, test);
        assert(0 == memcmp(buffer, test, size)); }

    if (partsize == 16) {
        D printf("16: AES\n");
        EVP_EncryptUpdate(ctx, tmp, &outl, outleft, 16);
        D assert(16 == outl);
        memxor(outright, tmp, 16);

        EVP_EncryptUpdate(ctx, tmp, &outl, outright, 16);
        D assert(16 == outl);
        memxor(outleft, tmp, 16);

    } else if (partsize > 16) {
        D printf("%lu: RECURSE\n", partsize);
        // this HAS to be mixing and not unmixing!
        recursive_mixing_naor(ctx, outleft, tmp, partsize, hctx1, hctx2);
        memxor(outright, tmp, partsize);

        // this HAS to be mixing and not unmixing!
        recursive_mixing_naor(ctx, outright, tmp, partsize, hctx1, hctx2);
        memxor(outleft, tmp, partsize);

    } else {  // partsize < BLOCK_SIZE
        printf("plaintext length wrong.");
        exit(EXIT_FAILURE);
    }

    do_h_inv(hctx1, size, out, out);
}

#else
#define MIX recursive_mixing
#define UNMIX recursive_mixing

static void recursive_mixing(EVP_CIPHER_CTX* ctx, const unsigned char* buffer,
        unsigned char* out, unsigned int size, HCTX* hctx1, HCTX* hctx2
){
    int outl;
    unsigned long partsize = size / 2;
    const unsigned char *left = buffer;
    const unsigned char *right = buffer + partsize;
    unsigned char *outleft = out;
    unsigned char *outright = out + partsize;
    unsigned char tmp[partsize];

    if (partsize == 16) {
        D printf("16: AES\n");
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
        D printf("%lu: RECURSE\n", partsize);
        recursive_mixing(ctx, left, outright, partsize, hctx1, hctx2);
        memxor(outright, right, partsize);

        recursive_mixing(ctx, outright, outleft, partsize, hctx1, hctx2);
        memxor(outleft, left, partsize);

        recursive_mixing(ctx, outleft, tmp, partsize, hctx1, hctx2);
        memxor(outright, tmp, partsize);

    } else {  // partsize < BLOCK_SIZE
        printf("plaintext length wrong.");
        exit(EXIT_FAILURE);
    }
}
#endif

static inline void mix(EVP_CIPHER_CTX* ctx,
        const unsigned char* input, unsigned char* output,
        HCTX* hctx1, HCTX* hctx2, unsigned short unmix
){
    const unsigned char* last = input + MACRO_SIZE;
    unsigned char tmp[BLOCK_SIZE];
    for ( ; input < last; input+=BLOCK_SIZE, output+=BLOCK_SIZE) {
        D printf("mixing block %p\n", input);
        if (unmix) {
            UNMIX(ctx, input, tmp, BLOCK_SIZE, hctx1, hctx2);
        } else {
            MIX(ctx, input, tmp, BLOCK_SIZE, hctx1, hctx2);
        }
        memcpy(output, tmp, BLOCK_SIZE);
    }
}

static inline void do_step_encrypt(EVP_CIPHER_CTX* ctx, unsigned char* buffer,
    const unsigned char* macro, unsigned char* out, const unsigned int step,
    HCTX* hctx1, HCTX* hctx2
){
    SHUFFLE(step, off, bp, macro, buffer, bp, macro + off);
    mix(ctx, buffer, out, hctx1, hctx2, 0);
}

static inline void do_step_decrypt(EVP_CIPHER_CTX* ctx, unsigned char* buffer,
    const unsigned char* macro, unsigned char* out, const unsigned int step,
    HCTX* hctx1, HCTX* hctx2
){
    mix(ctx, macro, buffer, hctx1, hctx2, 1);
    SHUFFLE(step, off, bp, macro, buffer, out + off, bp);
}

inline void* memxor(void* dst, const void* src, size_t n){
    char *d =(char *) dst;
    char const *s =(char const*) src;
    for (; n>0; --n) {
        *d++ ^= *s++;
    }
    return dst;
}

static inline void mixencrypt_macroblock(const unsigned char* macro,
    unsigned char* out, unsigned char* buffer, const unsigned char* key,
    const unsigned char* iv, HCTX* hctx1, HCTX* hctx2
){
    int step;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if ( !ctx ) {
        printf("Cannot allocate needed memory\n");
        exit(EXIT_FAILURE);
    }

    EVP_EncryptInit(ctx, EVP_aes_128_ecb(), key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0); // disable padding

    // Step 0
    memxor((unsigned char*) macro, iv, IVSIZE);  // add IV to input
    mix(ctx, macro, out, hctx1, hctx2, 0);
    memxor((unsigned char*) macro, iv, IVSIZE);  // add IV to input

    // Steps 1 -> N
    for (step=1; step < DIGITS/DOF; ++step) {
        do_step_encrypt(ctx, buffer, out, out, step, hctx1, hctx2);
    }

    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
}

static inline void mixdecrypt_macroblock(const unsigned char* macro,
    unsigned char* out, unsigned char* buffer, const unsigned char* key,
    const unsigned char* iv, HCTX* hctx1, HCTX* hctx2
){
    int step;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if ( !ctx ) {
        printf("Cannot allocate needed memory\n");
        exit(EXIT_FAILURE);
    }

    EVP_EncryptInit(ctx, EVP_aes_128_ecb(), key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0); // disable padding

    // Steps N -> 1
    for (step = DIGITS/DOF - 1; step >= 1; --step) {
        do_step_decrypt(ctx, buffer, macro, out, step, hctx1, hctx2);
        macro = out;   // this is needed to avoid a starting memcpy
    }

    // Step 0
    mix(ctx, out, out, hctx1, hctx2, 1);
    memxor(out, iv, IVSIZE);         // remove IV from output

    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
}

typedef void (*mixfnv2) (
    const unsigned char* macro, unsigned char* out, unsigned char* buffer,
    const unsigned char* key, const unsigned char* iv, HCTX* hctx1, HCTX* hctx2
);

static inline void mixprocess(mixfnv2 fn, const unsigned char* data,
    unsigned char* out, const unsigned long size,
    const unsigned char* key, const unsigned char* iv
){
    assert(0 == size % MACRO_SIZE && "size must be multiple of MACRO_SIZE");
    D assert(BLOCK_SIZE == MINI_SIZE * 2 && "MINI_SIZE must be 2*BLOCK_SIZE");
    D assert((BLOCK_SIZE == 32 || BLOCK_SIZE == 64)
            && "the supported BLOCK_SIZE are 32 and 64");
    D assert(1 == ISPOWEROF(MINI_PER_MACRO, BLOCK_SIZE / MINI_SIZE)
             && "MINI_PER_MACRO must be a power of (BLOCK_SIZE / MINI_SIZE)");

    const unsigned char* last = data + size;
    unsigned char* buffer = (unsigned char*) malloc(MACRO_SIZE);

    unsigned __int128 keyent;
    memcpy(&keyent, key, KEYSIZE);
    keyent += 1;
    HCTX* hctx1 = create_hctx((unsigned char*) &keyent, KEYSIZE);
    keyent += 1;
    HCTX* hctx2 = create_hctx((unsigned char*) &keyent, KEYSIZE);

    unsigned __int128 miv;

    memcpy(&miv, iv, IVSIZE);
    for ( ; data < last; data+=MACRO_SIZE, out+=MACRO_SIZE, miv+=1) {
        fn(data, out, buffer, key, (unsigned char*) &miv, hctx1, hctx1);
    }

    free(buffer);
    destroy_hctx(hctx1);
    destroy_hctx(hctx2);
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
