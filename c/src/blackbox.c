#include <openssl/rand.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "debug.h"
#include "lck.h"

unsigned char key[] = "SQUEAMISHOSSIFRA";

int main(int argc, char *argv[])
{
    unsigned char  in1[MACRO_SIZE];
    unsigned char  in2[MACRO_SIZE];
    unsigned char out1[MACRO_SIZE];
    unsigned char out2[MACRO_SIZE];
    unsigned char   iv[BLOCK_SIZE];
    int i, j;

    RAND_pseudo_bytes(in1, MACRO_SIZE);
    RAND_pseudo_bytes(iv, BLOCK_SIZE);
    encrypt(in1, out1, MACRO_SIZE, key, iv);

    for (i=0; i<MACRO_SIZE; i+=MINI_SIZE) {
        printf("\n\n%d", i / MINI_SIZE);
        memcpy(in2, in1, MACRO_SIZE);
        do {
            RAND_pseudo_bytes(&in2[i], MINI_SIZE);
        } while (0 == memcmp((const char*)in1, (const char*)in2, MACRO_SIZE));

        encrypt(in2, out2, MACRO_SIZE, key, iv);
        for (j=0; j<MACRO_SIZE; j+=BLOCK_SIZE) {
            printx("out1: ", &out1[j], BLOCK_SIZE);
            printx("out2: ", &out2[j], BLOCK_SIZE);
            assert(0 != memcmp((const char*)&out1[j], (const char*)&out2[j], BLOCK_SIZE));
        }
    }

    printf("DONE\n");
    return 0;
}
