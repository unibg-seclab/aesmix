#include <openssl/evp.h>
#include <string.h>
#include <assert.h>
#include <math.h>

#include "aes_mix_oaep.h"

#define BIMACRO_SIZE (2*MACRO_SIZE)

#define SHUFFLE(STEP, OFF, BP, MACRO, BUFFER, FROM, TO)                       \
    unsigned int j, OFF, mask, start, dist;                                   \
    unsigned char *BP = buffer;                                               \
    mask = ((1 << DOF) - 1) << (STEP * DOF);                                  \
    dist = (1 << (STEP * DOF)) * MINI_SIZE;                                   \
    for (start=0; start < (1<<DIGITS); start=((start|mask)+1)&~mask) {        \
        for (j=0, off=start*MINI_SIZE; j < MINI_PER_BLOCK; ++j, off+=dist) {  \
            memcpy(FROM, TO, MINI_SIZE);                                      \
            bp += MINI_SIZE;                                                  \
        }                                                                     \
    }

static inline void do_step_G(
    EVP_MD_CTX* ctx, unsigned char* buffer, const unsigned char* macro,
    unsigned char* gout, const unsigned int step
){
    unsigned int outl;
    SHUFFLE(step, off, bp, macro, buffer, bp, macro + off);
    for (off=0; off<MACRO_SIZE; off+=BLOCK_SIZE) {
        EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
        EVP_DigestUpdate(ctx, buffer+off, BLOCK_SIZE);
        EVP_DigestFinal_ex(ctx, gout+off, &outl);
        D assert(BLOCK_SIZE == outl);
    }
}

static inline void oaep_G(
    const unsigned char* macro, unsigned char* gout, unsigned char* buffer
){
    int step;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if ( NULL == ctx ) {
        printf("Cannot allocate needed memory\n");
        exit(EXIT_FAILURE);
    }

    // Steps 1 -> N
    for (step=0; step < DIGITS/DOF; ++step) {
        do_step_G(ctx, buffer, macro, gout, step);
    }

    EVP_MD_CTX_free(ctx);
}

static inline void mixoaep_pad(
    unsigned char* data, unsigned char* buffer
){
    unsigned char *left = data;
    unsigned char *right = data + MACRO_SIZE;
    unsigned char *gout = malloc(MACRO_SIZE);

    if ( !gout ) {
        printf("Cannot allocate needed memory\n");
        exit(EXIT_FAILURE);
    }

    oaep_G(left, gout, buffer);
    memxor(right, gout, MACRO_SIZE);

    oaep_G(right, gout, buffer);
    memxor(left, gout, MACRO_SIZE);

    oaep_G(left, gout, buffer);
    memxor(right, gout, MACRO_SIZE);

    free(gout);
}

// the function below is identical to mixoaep_pad for odd number of
// OAEP steps, but must be changed in case of even steps.
static inline void mixoaep_unpad(
    unsigned char* data, unsigned char* buffer
){
    unsigned char *left = data;
    unsigned char *right = data + MACRO_SIZE;
    unsigned char *gout = malloc(MACRO_SIZE);

    if ( !gout ) {
        printf("Cannot allocate needed memory\n");
        exit(EXIT_FAILURE);
    }

    oaep_G(left, gout, buffer);
    memxor(right, gout, MACRO_SIZE);

    oaep_G(right, gout, buffer);
    memxor(left, gout, MACRO_SIZE);

    oaep_G(left, gout, buffer);
    memxor(right, gout, MACRO_SIZE);

    free(gout);
}


static inline void mixencrypt_bimacroblock_oaep(
    const unsigned char* bimacro, unsigned char* out, unsigned char* buffer,
    const unsigned char* key, const unsigned char* iv
){
    int outl;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if ( !ctx ) {
        printf("Cannot allocate needed memory\n");
        exit(EXIT_FAILURE);
    }

    // add IV
    memcpy(out, bimacro, BIMACRO_SIZE);
    memxor(out, iv, BLOCK_SIZE);

    // OAEP pad
    mixoaep_pad(out, buffer);

    // encrypt
    EVP_EncryptInit(ctx, EVP_aes_128_ecb(), key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0); // disable padding
    EVP_EncryptUpdate(ctx, out, &outl, out, BIMACRO_SIZE);
    D assert(BIMACRO_SIZE == outl);
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
}

static inline void mixdecrypt_bimacroblock_oaep(
    const unsigned char* bimacro, unsigned char* out, unsigned char* buffer,
    const unsigned char* key, const unsigned char* iv
){
    int outl;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if ( !ctx ) {
        printf("Cannot allocate needed memory\n");
        exit(EXIT_FAILURE);
    }

    // decrypt
    EVP_DecryptInit(ctx, EVP_aes_128_ecb(), key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0); // disable padding
    EVP_DecryptUpdate(ctx, out, &outl, bimacro, BIMACRO_SIZE);
    D assert(BIMACRO_SIZE == outl);
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);

    // OAEP unpad
    mixoaep_unpad(out, buffer);

    // remove IV
    memxor(out, iv, BLOCK_SIZE);
}

inline void mixbiprocess(
    mixfn fn, const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
){
    const unsigned char* last = data + size;
    unsigned __int128 miv;
    unsigned char* buffer = malloc(MACRO_SIZE);

    if ( !buffer ) {
        printf("Cannot allocate needed memory\n");
        exit(EXIT_FAILURE);
    }

    assert(0 == size % BIMACRO_SIZE);
    memcpy(&miv, iv, sizeof(miv));

    for ( ; data < last; data+=BIMACRO_SIZE, out+=BIMACRO_SIZE, miv++) {
        fn(data, out, buffer, key, (unsigned char*) &miv);
    }

    free(buffer);
}

void mixencrypt_oaep(const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
){
    mixbiprocess(mixencrypt_bimacroblock_oaep, data, out, size, key, iv);
}

void mixdecrypt_oaep(const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
){
    mixbiprocess(mixdecrypt_bimacroblock_oaep, data, out, size, key, iv);
}
