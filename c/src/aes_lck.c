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

static inline void do_step_encrypt(EVP_CIPHER_CTX* ctx,
    const unsigned char* macro, unsigned char* out, const unsigned int step,
    const unsigned char* key, const unsigned char* iv
){
    unsigned char buffer[MACRO_SIZE];
    int outl;

    SHUFFLE(step, off, bp, macro, buffer, bp, macro + off);
    EVP_EncryptUpdate(ctx, out, &outl, buffer, MACRO_SIZE);
    D assert(MACRO_SIZE == outl);
}

static inline void do_step_decrypt(EVP_CIPHER_CTX* ctx,
    const unsigned char* macro, unsigned char* out, const unsigned int step,
    const unsigned char* key, const unsigned char* iv
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

static inline void encrypt_macroblock(const unsigned char* macro,
    unsigned char* out, const unsigned char* key, const unsigned char* iv
){
    int outl;
    unsigned int step;
    EVP_CIPHER_CTX ctx;
    EVP_EncryptInit(&ctx, EVP_aes_128_ecb(), key, iv);
    EVP_CIPHER_CTX_set_padding(&ctx, 0); // disable padding

    // Step 0
    memxor((unsigned char*) macro, iv, BLOCK_SIZE);  // add IV to input
    EVP_EncryptUpdate(&ctx, out, &outl, macro, MACRO_SIZE);
    memxor((unsigned char*) macro, iv, BLOCK_SIZE);  // remove IV from input
    D assert(MACRO_SIZE == outl);

    // Steps 1 -> N
    for (step=1; step < DIGITS/DOF; ++step) {
        do_step_encrypt(&ctx, out, out, step, key, iv);
    }

    EVP_CIPHER_CTX_cleanup(&ctx);
}

static inline void decrypt_macroblock(const unsigned char* macro,
    unsigned char* out, const unsigned char* key, const unsigned char* iv
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

static inline void process(const short enc, const unsigned char* data,
    unsigned char* out, const unsigned long size,
    const unsigned char* key, const unsigned char* iv
){
    const unsigned char* last = data + size;
    unsigned __int128 miv;

    D assert(0 == size % MACRO_SIZE);
    memcpy(&miv, iv, sizeof(miv));

    for ( ; data < last; data+=MACRO_SIZE, out+=MACRO_SIZE, miv++) {
        (enc ? encrypt_macroblock : decrypt_macroblock)
            (data, out, key, (unsigned char*) &miv);
    }
}

void encrypt(const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
){
    process(1, data, out, size, key, iv);
}

void decrypt(const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
){
    process(0, data, out, size, key, iv);
}
