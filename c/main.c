#include <openssl/rand.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "lck.h"

unsigned char key[] = "SQUEAMISHOSSIFRA";
unsigned char iv[]  = "IVIVIVIVIVIVIVIV";

void print_hex(const unsigned char *s, unsigned int l)
{
    int i;
    for (i = 0; i < l; ++i)
        printf("%02x", (unsigned int) s[i]);
    printf("\n");
}

int main()
{
    unsigned char in[MACRO_SIZE], out[MACRO_SIZE], dec[MACRO_SIZE];
    RAND_pseudo_bytes(in, MACRO_SIZE);

    printf("PLAINTEXT:  ");
    print_hex(in, MACRO_SIZE);

    encrypt(in, out, MACRO_SIZE, key, iv);
    printf("CIPHERTEXT: ");
    print_hex(out, MACRO_SIZE);

    decrypt(out, dec, MACRO_SIZE, key, iv);
    printf("DECRYPTED:  ");
    print_hex(dec, MACRO_SIZE);

    assert(0 == strncmp((const char*)in, (const char*)dec, MACRO_SIZE));
    return 0;
}
