#include <openssl/rand.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "debug.h"
#include "lck.h"

unsigned char key[] = "SQUEAMISHOSSIFRA";

int main(int argc, char *argv[])
{
    unsigned char   in[MACRO_SIZE];
    unsigned char  in2[MACRO_SIZE];
    unsigned char  out[MACRO_SIZE];
    unsigned char out2[MACRO_SIZE];
    unsigned char   iv[BLOCK_SIZE];
    int i, j;

    RAND_pseudo_bytes(in, MACRO_SIZE);
    RAND_pseudo_bytes(iv, BLOCK_SIZE);
    encrypt(in, out, MACRO_SIZE, key, iv);

    for (i=0; i<MACRO_SIZE; i+=MINI_SIZE) {
        memcpy(in2, in, MACRO_SIZE);
        RAND_pseudo_bytes(&in2[i], MINI_SIZE);
        assert(0 != strncmp((const char*)in, (const char*)in2, MACRO_SIZE));
        printx("in1: ", in, MACRO_SIZE);
        printx("in2: ", in2, MACRO_SIZE);

        encrypt(in2, out2, MACRO_SIZE, key, iv);
        for (j=0; j<MACRO_SIZE; j+=BLOCK_SIZE) {
            printx("1: ", &out[j], BLOCK_SIZE);
            printx("2: ", &out2[j], BLOCK_SIZE);
            assert(0 != strncmp((const char*)&out[j], (const char*)&out2[j], BLOCK_SIZE));
        }
    }

    printf("DONE\n");
    return 0;
}
