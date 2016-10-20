#include <openssl/rand.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "debug.h"
#include "aes_mix.h"

#ifdef DEBUG
#define SIZE  (MACRO_SIZE*4)
#else
#define SIZE   MACRO_SIZE
#endif

unsigned char key[] = "SQUEAMISHOSSIFRA";

int main(int argc, char *argv[])
{
    int i, macros;
    unsigned char iv[BLOCK_SIZE];
    unsigned char*   in = malloc(SIZE);
    unsigned char* orig = malloc(SIZE);
    unsigned char*  out = malloc(SIZE);
    unsigned char*  dec = malloc(SIZE);

    if ( 0 == in || 0 == orig || 0 == out || 0 == dec ) {
        printf("Cannot allocate needed memory\n");
        exit(EXIT_FAILURE);
    }

    macros = (argc > 1) ? atoi(argv[1]) : 1;

    //RAND_pseudo_bytes(in, SIZE);
    memcpy(orig, in, SIZE);

    printf("AESMIX-ing %d * %d macroblocks ...\n", SIZE/MACRO_SIZE, macros);
    for (i=0; i < macros; ++i) {
        D RAND_pseudo_bytes(iv, BLOCK_SIZE);
        D printx("IV: ", iv, BLOCK_SIZE, MINI_SIZE);

        encrypt(in, out, SIZE, key, iv);
        D assert(0 != memcmp(in, out, SIZE));
        D assert(0 == memcmp(in, orig, SIZE));

        D decrypt(out, dec, SIZE, key, iv);
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
