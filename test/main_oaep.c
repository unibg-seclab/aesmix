#include <openssl/rand.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "debug.h"
#include "aes_mix_oaep.h"

#define SIZE   MACRO_SIZE

unsigned char key[] = "SQUEAMISHOSSIFRA";

int main(int argc, char *argv[])
{
    int i, macros;
    unsigned char iv[BLOCK_SIZE];
    unsigned char*   in = malloc(SIZE);
    unsigned char* orig = malloc(SIZE);
    unsigned char*  out = malloc(SIZE);
    unsigned char*  dec = malloc(SIZE);

    if ( !in || !orig || !out || !dec ) {
        printf("Cannot allocate needed memory\n");
        exit(EXIT_FAILURE);
    }

    macros = (argc > 1) ? atoi(argv[1]) : 1;

//    RAND_bytes(in, SIZE);
    memcpy(orig, in, SIZE);

    printf("AESMIX-ing %d * %d macroblocks of size %d ...\n", SIZE/MACRO_SIZE, macros, MACRO_SIZE);
    for (i=0; i < macros; ++i) {
        D RAND_bytes(iv, BLOCK_SIZE);
        D printx("IV: ", iv, BLOCK_SIZE, MINI_SIZE);

        mixencrypt_oaep(in, out, SIZE, key, iv);
        D printf("after encryption\n");
        D printx("orig: ", orig, SIZE, BLOCK_SIZE);
        D printx("in:   ", in, SIZE, BLOCK_SIZE);
        D printx("out:  ", out, SIZE, BLOCK_SIZE);
        D assert(0 != memcmp(in, out, SIZE));
        D assert(0 == memcmp(in, orig, SIZE));

        D mixdecrypt_oaep(out, dec, SIZE, key, iv);
        D printf("after decryption\n");
        D printx("out:  ", out, SIZE, BLOCK_SIZE);
        D printx("dec:  ", dec, SIZE, BLOCK_SIZE);
        D printx("orig: ", orig, SIZE, BLOCK_SIZE);
        D assert(0 == memcmp(in, dec, SIZE));
        D assert(0 == memcmp(in, orig, SIZE));
    }

    free(in);
    free(orig);
    free(out);
    free(dec);

    printf("DONE\n");
    return EXIT_SUCCESS;
}
