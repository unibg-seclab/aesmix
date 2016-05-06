#include <openssl/evp.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include "aes_lck.h"


static inline void do_step_encrypt(EVP_CIPHER_CTX* ctx, unsigned char* macro,
    unsigned char* out, unsigned int step, unsigned char* key, unsigned char* iv
){
    unsigned int j, off, mask, start, dist;
    unsigned char buffer[MACRO_SIZE];
    unsigned char *bp = buffer;
    int outl;

    mask = ((1 << DOF) - 1) << (step * DOF);
    dist = (1 << (step * DOF)) * MINI_SIZE;
    for (start=0; start < (1<<DIGITS); start=((start|mask)+1)&~mask) {
        for (j=0, off=start*MINI_SIZE; j < MINI_PER_BLOCK; ++j, off+=dist) {
            memcpy(bp, macro + off, MINI_SIZE);
            bp += MINI_SIZE;
        }
    }

    EVP_EncryptUpdate(ctx, out, &outl, buffer, MACRO_SIZE);
    D assert(outl == MACRO_SIZE);
}

static inline void do_step_decrypt(EVP_CIPHER_CTX* ctx, unsigned char* macro,
    unsigned char* out, unsigned int step, unsigned char* key, unsigned char* iv
){
    unsigned int j, off, mask, start, dist;
    unsigned char buffer[MACRO_SIZE];
    unsigned char *bp = buffer;
    int outl;

    EVP_DecryptUpdate(ctx, buffer, &outl, macro, MACRO_SIZE);
    D assert(outl == MACRO_SIZE);

    mask = ((1 << DOF) - 1) << (step * DOF);
    dist = (1 << (step * DOF)) * MINI_SIZE;
    for (start=0; start < (1<<DIGITS); start=((start|mask)+1)&~mask) {
        for (j=0, off=start*MINI_SIZE; j < MINI_PER_BLOCK; ++j, off+=dist) {
            memcpy(out + off, bp, MINI_SIZE);
            bp += MINI_SIZE;
        }
    }
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
    D assert(outl == MACRO_SIZE);

    // Steps 1 -> N
    for (step=1; step < DIGITS/DOF; ++step) {
        do_step_encrypt(&ctx, out, out, step, key, iv);
    }

    EVP_EncryptFinal(&ctx, out + outl, &outl);
    D assert(0 == outl);
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
    D assert(outl == MACRO_SIZE);
    EVP_DecryptFinal(&ctx, out + outl, &outl);
    D assert(0 == outl);
    EVP_CIPHER_CTX_cleanup(&ctx);
}

void encrypt(unsigned char* data, unsigned char* out,
    unsigned long size, unsigned char* key, unsigned char* iv
){
    unsigned char* last = data + size;
    D assert(size % MACRO_SIZE == 0);
    for (; data < last; data+=MACRO_SIZE, out+=MACRO_SIZE) {
        // TODO mix IV with offset
        encrypt_macroblock(data, out, key, iv);
    }
}

void decrypt(unsigned char* data, unsigned char* out,
    unsigned long size, unsigned char* key, unsigned char* iv
){
    unsigned char* last = data + size;
    D assert(size % MACRO_SIZE == 0);
    for (; data < last; data+=MACRO_SIZE, out+=MACRO_SIZE) {
        // TODO mix IV with offset
        decrypt_macroblock(data, out, key, iv);
    }
}
