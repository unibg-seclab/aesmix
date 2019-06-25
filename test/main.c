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
    int macros;
    macros = (argc > 1) ? atoi(argv[1]) : 1;

    unsigned char iv[IVSIZE];
    unsigned char*   in = malloc(SIZE * macros);
    unsigned char* orig = malloc(SIZE * macros);
    unsigned char*  out = malloc(SIZE * macros);
    unsigned char*  dec = malloc(SIZE * macros);

    if ( 0 == in || 0 == orig || 0 == out || 0 == dec ) {
        printf("Cannot allocate needed memory\n");
        exit(EXIT_FAILURE);
    }

#ifdef DEBUG
    RAND_bytes(in, SIZE);
#else
    fprintf(stderr, "no debug flag -> no assert performed\n");
#endif

    memcpy(orig, in, SIZE);

    printf("AESMIX-ing %d * %d macroblocks ...\n", SIZE/MACRO_SIZE, macros);
    D RAND_bytes(iv, IVSIZE);
    D printx("IV: ", iv, IVSIZE, MINI_SIZE);

    mixencrypt(in, out, SIZE * macros, key, iv);
    D assert(0 != memcmp(in, out, SIZE * macros));
    D printf("in != out .. verified\n");
    D assert(0 == memcmp(in, orig, SIZE * macros));
    D printf("in == orig .. verified\n");

    D mixdecrypt(out, dec, SIZE * macros, key, iv);
    D assert(0 == memcmp(in, dec, SIZE * macros));
    D printf("in == dec .. verified\n");
    D assert(0 == memcmp(in, orig, SIZE * macros));
    D printf("in == orig .. verified\n");

    free(in);
    free(orig);
    free(out);
    free(dec);

    printf("DONE\n");
    return EXIT_SUCCESS;
}
