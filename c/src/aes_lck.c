#include <openssl/evp.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include "aes_lck.h"

#define SHUFFLE(STEP, OFF, BP, MACRO, BUFFER, FROM, TO)                       \
    unsigned int j, OFF, mask, start, dist;                                   \
    unsigned char *bp = buffer;                                               \
    mask = ((1 << DOF) - 1) << (STEP * DOF);                                  \
    dist = (1 << (STEP * DOF)) * MINI_SIZE;                                   \
    for (start=0; start < (1<<DIGITS); start=((start|mask)+1)&~mask) {        \
        for (j=0, off=start*MINI_SIZE; j < MINI_PER_BLOCK; ++j, off+=dist) {  \
            memcpy(FROM, TO, MINI_SIZE);                                      \
            bp += MINI_SIZE;                                                  \
        }                                                                     \
    }

static inline void do_step_encrypt(EVP_CIPHER_CTX* ctx, unsigned char* macro,
    unsigned char* out, unsigned int step, unsigned char* key, unsigned char* iv
){
    unsigned char buffer[MACRO_SIZE];
    int outl;

    SHUFFLE(step, off, bp, macro, buffer, bp, macro + off);
    EVP_EncryptUpdate(ctx, out, &outl, buffer, MACRO_SIZE);
    D assert(MACRO_SIZE == outl);
}

static inline void do_step_decrypt(EVP_CIPHER_CTX* ctx, unsigned char* macro,
    unsigned char* out, unsigned int step, unsigned char* key, unsigned char* iv
){
    unsigned char buffer[MACRO_SIZE];
    int outl;

    EVP_DecryptUpdate(ctx, buffer, &outl, macro, MACRO_SIZE);
    D assert(MACRO_SIZE == outl);
    SHUFFLE(step, off, bp, macro, buffer, out + off, bp);
}

static inline void* memxor(void* dst, const void* src, size_t n){
    char *d = dst;
    char const *s = src;
    for (; n>0; --n) {
        *d++ ^= *s++;
    }
    return dst;
}

static inline void encrypt_macroblock(unsigned char* macro,
    unsigned char* out, unsigned char* key, unsigned char* iv
){
    int outl;
    unsigned int step;
    EVP_CIPHER_CTX ctx;
    EVP_EncryptInit(&ctx, EVP_aes_128_ecb(), key, iv);
    EVP_CIPHER_CTX_set_padding(&ctx, 0); // disable padding

    // Step 0
    memxor(macro, iv, BLOCK_SIZE);       // add IV to input
    EVP_EncryptUpdate(&ctx, out, &outl, macro, MACRO_SIZE);
    memxor(macro, iv, BLOCK_SIZE);       // remove IV from input
    D assert(MACRO_SIZE == outl);

    // Steps 1 -> N
    for (step=1; step < DIGITS/DOF; ++step) {
        do_step_encrypt(&ctx, out, out, step, key, iv);
    }

    EVP_CIPHER_CTX_cleanup(&ctx);
}

static inline void decrypt_macroblock(unsigned char* macro,
    unsigned char* out, unsigned char* key, unsigned char* iv
){
    int outl;
    unsigned int step;
    EVP_CIPHER_CTX ctx;

    EVP_DecryptInit(&ctx, EVP_aes_128_ecb(), key, iv);
    EVP_CIPHER_CTX_set_padding(&ctx, 0); // disable padding

    // Steps N -> 1
    for (step = DIGITS/DOF - 1; step >= 1; --step) {
        do_step_decrypt(&ctx, macro, out, step, key, iv);
        macro = out;   // this is needed to avoid a starting memcpy
    }

    // Step 0
    EVP_DecryptUpdate(&ctx, out, &outl, out, MACRO_SIZE);
    memxor(out, iv, BLOCK_SIZE);         // remove IV from output
    D assert(MACRO_SIZE == outl);
    EVP_CIPHER_CTX_cleanup(&ctx);
}

static inline void process(short enc, unsigned char* data, unsigned char* out,
    unsigned long size, unsigned char* key, unsigned char* iv
){
    unsigned char miv[BLOCK_SIZE];
    unsigned __int128 n;
    EVP_CIPHER_CTX ctx;
    int outl;

    D assert(0 == size % MACRO_SIZE);
    EVP_EncryptInit(&ctx, EVP_aes_128_cbc(), key, iv);
    EVP_CIPHER_CTX_set_padding(&ctx, 0); // disable padding

    for (n=0; n < size / MACRO_SIZE; ++n) {
        EVP_EncryptUpdate(&ctx, miv, &outl, (unsigned char*) &n, BLOCK_SIZE);
        D assert(BLOCK_SIZE == outl);
        (enc ? encrypt_macroblock : decrypt_macroblock)
            (data + n*MACRO_SIZE, out + n*MACRO_SIZE, key, miv);
    }

    EVP_CIPHER_CTX_cleanup(&ctx);
}

void encrypt(unsigned char* data, unsigned char* out,
    unsigned long size, unsigned char* key, unsigned char* iv
){
    process(1, data, out, size, key, iv);
}

void decrypt(unsigned char* data, unsigned char* out,
    unsigned long size, unsigned char* key, unsigned char* iv
){
    process(0, data, out, size, key, iv);
}