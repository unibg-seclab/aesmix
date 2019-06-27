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


#if defined(NAOR)
#define MIX(ctx, in, out, size, h1, h2)                                       \
    recursive_mixing_naor(ctx, in, out, out, out + size/2, size, h1, h2, 1)
#define UNMIX(ctx, in, out, size, h1, h2)                                     \
    recursive_mixing_naor(ctx, in, out, out + size/2, out, size, h1, h2, 0)

static void recursive_mixing_naor(EVP_CIPHER_CTX* ctx,
        const unsigned char* buffer, unsigned char* out,
        unsigned char* outleft, unsigned char* outright,
        unsigned int size, HCTX* hctx1, HCTX* hctx2, int mix
){
    int outl;
    unsigned long partsize = size / 2;
    unsigned char tmp[partsize];

#ifdef NAOR_EXTERNAL_ONLY
    if (size == BLOCK_SIZE) {
        do_h(mix ? hctx1 : hctx2, size, buffer, out);
    } else {
        memcpy(out, buffer, size);
    }
#else
    do_h(mix ? hctx1 : hctx2, size, buffer, out);
#endif

    if (partsize == 16) {
        EVP_EncryptUpdate(ctx, tmp, &outl, outright, 16);
        memxor(outleft, tmp, 16);

        EVP_EncryptUpdate(ctx, tmp, &outl, outleft, 16);
        memxor(outright, tmp, 16);

    } else if (partsize > 16) {
        MIX(ctx, outright, tmp, partsize, hctx1, hctx2);
        memxor(outleft, tmp, partsize);

        MIX(ctx, outleft, tmp, partsize, hctx1, hctx2);
        memxor(outright, tmp, partsize);

    } else {  // partsize < BLOCK_SIZE
        printf("plaintext length wrong.");
        exit(EXIT_FAILURE);
    }

#ifdef NAOR_EXTERNAL_ONLY
    if (size == BLOCK_SIZE) {
        do_h_inv(mix ? hctx2 : hctx1, size, out, out);
    }
#else
    do_h_inv(mix ? hctx2 : hctx1, size, out, out);
#endif

}


#elif defined(CAPKUN)
#define MIX(ctx, in, out, size, hctx1, hctx2)                                 \
    recursive_mixing_capkun(ctx, in, size, out, out, out + size/2)
#define UNMIX(ctx, in, out, size, hctx1, hctx2)                               \
    recursive_mixing_capkun(ctx, in, size, out, out + size/2, out)

static inline void mix_capkun(
        const unsigned char* buffer, unsigned char* out, unsigned int size
){
    unsigned __int128 seam = 0;
    const unsigned __int128 *ptr = (unsigned __int128*) buffer;
    const unsigned __int128 *last = ptr + (size / 16);
    for ( ; ptr < last; ++ptr ) { seam ^= *ptr; }

    unsigned __int128 *outptr = (unsigned __int128*) out;
    ptr = (unsigned __int128*) buffer;
    for ( ; ptr < last; ++ptr, ++outptr) { *outptr = seam ^ *ptr; }
}

static void recursive_mixing_capkun(EVP_CIPHER_CTX* ctx,
        const unsigned char* buffer, unsigned int size,
        unsigned char* out, unsigned char* outleft, unsigned char* outright
){
    int outl;
    unsigned long partsize = size / 2;
    unsigned char tmp[partsize];

    mix_capkun(buffer, out, size);

    if (partsize == 16) {
        EVP_EncryptUpdate(ctx, tmp, &outl, outright, 16);
        memxor(outleft, tmp, 16);

        EVP_EncryptUpdate(ctx, tmp, &outl, outleft, 16);
        memxor(outright, tmp, 16);

    } else if (partsize > 16) {
        MIX(ctx, outright, tmp, partsize, NULL, NULL);
        memxor(outleft, tmp, partsize);

        MIX(ctx, outleft, tmp, partsize, NULL, NULL);
        memxor(outright, tmp, partsize);

    } else {  // partsize < BLOCK_SIZE
        printf("plaintext length wrong.");
        exit(EXIT_FAILURE);
    }

    mix_capkun(out, out, size);
}

#else
#define MIX(ctx, in, out, size, hctx1, hctx2)                                 \
    recursive_mixing(ctx, in, size, out, out + size/2)
#define UNMIX(ctx, in, out, size, hctx1, hctx2)                               \
    recursive_mixing(ctx, in, size, out, out + size/2)

static void recursive_mixing(EVP_CIPHER_CTX* ctx,
        const unsigned char* buffer, unsigned int size,
        unsigned char* outleft, unsigned char* outright
){
    int outl;
    unsigned long partsize = size / 2;
    const unsigned char *left = buffer;
    const unsigned char *right = buffer + partsize;
    unsigned char tmp[partsize];

    if (partsize == 16) {
        EVP_EncryptUpdate(ctx, outright, &outl, left, 16);
        memxor(outright, right, 16);

        EVP_EncryptUpdate(ctx, outleft, &outl, outright, 16);
        memxor(outleft, left, 16);

        EVP_EncryptUpdate(ctx, tmp, &outl, outleft, 16);
        memxor(outright, tmp, 16);

    } else if (partsize > 16) {
        MIX(ctx, left, outright, partsize, NULL, NULL);
        memxor(outright, right, partsize);

        MIX(ctx, outright, outleft, partsize, NULL, NULL);
        memxor(outleft, left, partsize);

        MIX(ctx, outleft, tmp, partsize,NULL, NULL);
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
    (void) hctx1;
    (void) hctx2;
    const unsigned char* last = input + MACRO_SIZE;
    unsigned char tmp[BLOCK_SIZE];
    for ( ; input < last; input+=BLOCK_SIZE, output+=BLOCK_SIZE) {
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
    HCTX *hctx1 = NULL, *hctx2 = NULL;

#ifdef NAOR
    unsigned __int128 keyent;
    memcpy(&keyent, key, KEYSIZE);
    keyent += 1;
    hctx1 = create_hctx((unsigned char*) &keyent, KEYSIZE);
    keyent += 1;
    hctx2 = create_hctx((unsigned char*) &keyent, KEYSIZE);
#endif

    unsigned __int128 miv;

    memcpy(&miv, iv, IVSIZE);
    for ( ; data < last; data+=MACRO_SIZE, out+=MACRO_SIZE, miv+=1) {
        fn(data, out, buffer, key, (unsigned char*) &miv, hctx1, hctx2);
    }

    free(buffer);

#ifdef NAOR
    destroy_hctx(hctx1);
    destroy_hctx(hctx2);
#endif
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
