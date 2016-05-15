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
    unsigned char   in[SIZE];
    unsigned char orig[SIZE];
    unsigned char  out[SIZE];
    unsigned char  dec[SIZE];
    unsigned char   iv[BLOCK_SIZE];

    macros = (argc > 1) ? atoi(argv[1]) : 1;

    RAND_pseudo_bytes(in, SIZE);
    memcpy(orig, in, SIZE);
    D printx("PLAINTEXT: ", in, SIZE, MINI_SIZE)

    printf("AESMIX-ing %d * %d macroblocks ...\n", SIZE/MACRO_SIZE, macros);
    for (i=0; i < macros; ++i) {
        D RAND_pseudo_bytes(iv, BLOCK_SIZE);
        D printx("IV: ", iv, BLOCK_SIZE, MINI_SIZE);

        encrypt(in, out, SIZE, key, iv);
        D printx("CIPHERTEXT: ", out, SIZE, MINI_SIZE);
        D assert(0 != memcmp(in, out, SIZE));
        D assert(0 == memcmp(in, orig, SIZE));

        D decrypt(out, dec, SIZE, key, iv);
        D printx("DECRYPTED: ", dec, SIZE, MINI_SIZE);
        D assert(0 == memcmp(in, dec, SIZE));
        D assert(0 == memcmp(in, orig, SIZE));
    }

    printf("DONE\n");
    return 0;
}
