#include <openssl/evp.h>
#include <string.h>
#include <assert.h>
#include <math.h>

#include "aes_mix_oaep.h"

// avoid using AES specific defines
#define AES_BLOCK_SIZE BLOCK_SIZE
#undef MINI_SIZE
#undef MINI_PER_MACRO
#undef MINI_PER_BLOCK
#undef MACRO_SIZE
#undef DIGITS
#undef DOF


#define SHUFFLE(STEP, OFF, BP, MACRO, BUFFER, TO, FROM)                                 \
    unsigned int j, OFF, mask, start, dist;                                             \
    unsigned char *BP = buffer;                                                         \
    mask = ((1 << OAEP_DOF) - 1) << (STEP * OAEP_DOF);                                  \
    dist = (1 << (STEP * OAEP_DOF)) * OAEP_MINI_SIZE;                                   \
    for (start=0; start < (1<<OAEP_DIGITS); start=((start|mask)+1)&~mask) {             \
        for (j=0, off=start*OAEP_MINI_SIZE; j < OAEP_MINI_PER_BLOCK; ++j, off+=dist) {  \
            memcpy(TO, FROM, OAEP_MINI_SIZE);                                           \
            BP += OAEP_MINI_SIZE;                                                       \
        }                                                                               \
    }

static inline void do_step_G(
    EVP_MD_CTX* ctx, unsigned char* buffer, const unsigned char* macro,
    unsigned char* gout, const unsigned int step
){
    unsigned int outl, off;
    if (step) {
        SHUFFLE(step, off, bp, macro, buffer, bp, macro + off);
    } else {
        buffer = (unsigned char*) macro;
    }

    for (off=0; off<OAEP_MACRO_SIZE; off+=OAEP_BLOCK_SIZE) {
        EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
        EVP_DigestUpdate(ctx, buffer+off, OAEP_BLOCK_SIZE);
        EVP_DigestFinal_ex(ctx, gout+off, &outl);
        D assert(OAEP_BLOCK_SIZE == outl);
    }
}

static inline void oaep_G(
    const unsigned char* macro, unsigned char* gout, unsigned char* buffer
){
    int step;
#if OPENSSL_VERSION_NUMBER < 0x10100000
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
#else
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
#endif

    if ( NULL == ctx ) {
        printf("Cannot allocate needed memory\n");
        exit(EXIT_FAILURE);
    }

    // Steps 0 -> N
    for (step=0; step < OAEP_DIGITS/OAEP_DOF; ++step) {
        do_step_G(ctx, buffer, macro, gout, step);
        macro = gout;   // this is needed to avoid a starting memcpy
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000
    EVP_MD_CTX_destroy(ctx);
#else
    EVP_MD_CTX_free(ctx);
#endif

}

static inline void mixoaep_pad(
    unsigned char* data, unsigned char* buffer
){
    unsigned char *left = data;
    unsigned char *right = data + OAEP_MACRO_SIZE;
    unsigned char *gout = malloc(OAEP_MACRO_SIZE);

    if ( !gout ) {
        printf("Cannot allocate needed memory\n");
        exit(EXIT_FAILURE);
    }

    oaep_G(left, gout, buffer);
    memxor(right, gout, OAEP_MACRO_SIZE);

    oaep_G(right, gout, buffer);
    memxor(left, gout, OAEP_MACRO_SIZE);

    oaep_G(left, gout, buffer);
    memxor(right, gout, OAEP_MACRO_SIZE);

    free(gout);
}

// the function below is identical to mixoaep_pad for odd number of
// OAEP steps, but must be changed in case of even steps.
static inline void mixoaep_unpad(
    unsigned char* data, unsigned char* buffer
){
    unsigned char *left = data;
    unsigned char *right = data + OAEP_MACRO_SIZE;
    unsigned char *gout = malloc(OAEP_MACRO_SIZE);

    if ( !gout ) {
        printf("Cannot allocate needed memory\n");
        exit(EXIT_FAILURE);
    }

    oaep_G(left, gout, buffer);
    memxor(right, gout, OAEP_MACRO_SIZE);

    oaep_G(right, gout, buffer);
    memxor(left, gout, OAEP_MACRO_SIZE);

    oaep_G(left, gout, buffer);
    memxor(right, gout, OAEP_MACRO_SIZE);

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
    memcpy(out, bimacro, OAEP_BIMACRO_SIZE);
    memxor(out, iv, AES_BLOCK_SIZE);

    // OAEP pad
    mixoaep_pad(out, buffer);

    // encrypt
    EVP_EncryptInit(ctx, EVP_aes_128_ctr(), key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0); // disable padding
    EVP_EncryptUpdate(ctx, out, &outl, out, OAEP_BIMACRO_SIZE);
    D assert(OAEP_BIMACRO_SIZE == outl);
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
    EVP_DecryptInit(ctx, EVP_aes_128_ctr(), key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0); // disable padding
    EVP_DecryptUpdate(ctx, out, &outl, bimacro, OAEP_BIMACRO_SIZE);
    D assert(OAEP_BIMACRO_SIZE == outl);
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);

    // OAEP unpad
    mixoaep_unpad(out, buffer);

    // remove IV
    memxor(out, iv, AES_BLOCK_SIZE);
}

inline void mixbiprocess(
    mixfn fn, const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
){
    D assert(1 == ISPOWEROF(OAEP_MINI_PER_MACRO, OAEP_BLOCK_SIZE / OAEP_MINI_SIZE)
             && "OAEP_MINI_PER_MACRO must be a power of (OAEP_BLOCK_SIZE / OAEP_MINI_SIZE)");
    const unsigned char* last = data + size;
    unsigned __int128 miv;
    unsigned char* buffer = malloc(OAEP_MACRO_SIZE);

    if ( !buffer ) {
        printf("Cannot allocate needed memory\n");
        exit(EXIT_FAILURE);
    }

    assert(0 == size % OAEP_BIMACRO_SIZE);
    memcpy(&miv, iv, sizeof(miv));

    for ( ; data < last; data+=OAEP_BIMACRO_SIZE, out+=OAEP_BIMACRO_SIZE, miv++) {
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
