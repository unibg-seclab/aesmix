#include <openssl/rand.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "lck.h"

#define printx(str, data, size) \
    do { printf(str); print_hex(data, size); } while (0);

unsigned char key[] = "SQUEAMISHOSSIFRA";

void print_hex(const unsigned char *s, unsigned int l)
{
    int i;
    for (i = 0; i < l; ++i)
        printf("%02x", (unsigned int) s[i]);
    printf("\n");
}

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

        decrypt(out, dec, MACRO_SIZE, key, iv);
        D printx("DECRYPTED: ", dec, MACRO_SIZE);

        assert(0 == strncmp((const char*)in, (const char*)dec, MACRO_SIZE));
    }

    printf("DONE\n");
    return 0;
}
