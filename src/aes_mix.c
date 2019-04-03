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

static inline void do_step_encrypt(EVP_CIPHER_CTX* ctx, unsigned char* buffer,
    const unsigned char* macro, unsigned char* out, const unsigned int step
){
    int outl;
    SHUFFLE(step, off, bp, macro, buffer, bp, macro + off);
    EVP_EncryptUpdate(ctx, out, &outl, buffer, MACRO_SIZE);
    D assert(MACRO_SIZE == outl);
}

static inline void do_step_decrypt(EVP_CIPHER_CTX* ctx, unsigned char* buffer,
    const unsigned char* macro, unsigned char* out, const unsigned int step
){
    int outl;
    EVP_DecryptUpdate(ctx, buffer, &outl, macro, MACRO_SIZE);
    D assert(MACRO_SIZE == outl);
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
    unsigned char* out, unsigned char* buffer,
    const unsigned char* key, const unsigned char* iv
){
    int step, outl;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if ( NULL == ctx ) {
        printf("Cannot allocate needed memory\n");
        exit(EXIT_FAILURE);
    }

    EVP_EncryptInit(ctx, EVP_aes_128_ecb(), key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0); // disable padding

    // Step 0
    memxor((unsigned char*) macro, iv, BLOCK_SIZE);  // add IV to input
    EVP_EncryptUpdate(ctx, out, &outl, macro, MACRO_SIZE);
    memxor((unsigned char*) macro, iv, BLOCK_SIZE);  // remove IV from input
    D assert(MACRO_SIZE == outl);

    // Steps 1 -> N
    for (step=1; step < DIGITS/DOF; ++step) {
        do_step_encrypt(ctx, buffer, out, out, step);
    }

    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
}

static inline void mixdecrypt_macroblock(const unsigned char* macro,
    unsigned char* out, unsigned char* buffer,
    const unsigned char* key, const unsigned char* iv
){
    int step, outl;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if ( NULL == ctx ) {
        printf("Cannot allocate needed memory\n");
        exit(EXIT_FAILURE);
    }

    EVP_DecryptInit(ctx, EVP_aes_128_ecb(), key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0); // disable padding

    // Steps N -> 1
    for (step = DIGITS/DOF - 1; step >= 1; --step) {
        do_step_decrypt(ctx, buffer, macro, out, step);
        macro = out;   // this is needed to avoid a starting memcpy
    }

    // Step 0
    EVP_DecryptUpdate(ctx, out, &outl, out, MACRO_SIZE);
    memxor(out, iv, BLOCK_SIZE);         // remove IV from output
    D assert(MACRO_SIZE == outl);

    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
}

inline void mixprocess(mixfn fn, const unsigned char* data,
    unsigned char* out, const unsigned long size,
    const unsigned char* key, const unsigned char* iv
){
    D assert(1 == ISPOWEROF(MINI_PER_MACRO, BLOCK_SIZE / MINI_SIZE)
             && "MINI_PER_MACRO must be a power of (BLOCK_SIZE / MINI_SIZE)");
    const unsigned char* last = data + size;
    unsigned __int128 miv;
    unsigned char* buffer =(unsigned char*) malloc(MACRO_SIZE);

    if ( NULL == buffer ) {
        printf("Cannot allocate needed memory\n");
        exit(EXIT_FAILURE);
    }

    assert(0 == size % MACRO_SIZE);
    memcpy(&miv, iv, sizeof(miv));

    for ( ; data < last; data+=MACRO_SIZE, out+=MACRO_SIZE, miv++) {
        fn(data, out, buffer, key, (unsigned char*) &miv);
    }

    free(buffer);
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
