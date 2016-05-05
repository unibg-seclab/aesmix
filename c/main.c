#include <openssl/rand.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "debug.h"
#include "lck.h"

unsigned char key[] = "SQUEAMISHOSSIFRA";

int main(int argc, char *argv[])
{
    int i, macros;
    unsigned char  in[MACRO_SIZE];
    unsigned char out[MACRO_SIZE];
    unsigned char dec[MACRO_SIZE];
    unsigned char  iv[BLOCK_SIZE];

    macros = (argc > 1) ? atoi(argv[1]) : 1;

    RAND_pseudo_bytes(in, MACRO_SIZE);
    D printx("PLAINTEXT: ", in, MACRO_SIZE)

    printf("AESLCK-ing %d macroblocks ...\n", macros);
    for (i=0; i < macros; ++i) {
        D RAND_pseudo_bytes(iv, BLOCK_SIZE);
        D printx("IV: ", iv, BLOCK_SIZE);

        encrypt(in, out, MACRO_SIZE, key, iv);
        D printx("CIPHERTEXT: ", out, MACRO_SIZE);
        D assert(0 != strncmp((const char*)in, (const char*)out, MACRO_SIZE));

        decrypt(out, dec, MACRO_SIZE, key, iv);
        D printx("DECRYPTED: ", dec, MACRO_SIZE);
        D assert(0 == strncmp((const char*)in, (const char*)dec, MACRO_SIZE));
    }

    printf("DONE\n");
    return 0;
}
