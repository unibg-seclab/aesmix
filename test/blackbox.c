#include <openssl/rand.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "debug.h"
#include "aes_mix.h"

unsigned char key[] = "SQUEAMISHOSSIFRA";

int main()
{
    unsigned char  in1[MACRO_SIZE];
    unsigned char  in2[MACRO_SIZE*2];
    unsigned char out1[MACRO_SIZE];
    unsigned char out2[MACRO_SIZE*2];
    unsigned char out3[MACRO_SIZE];
    unsigned char  iv1[BLOCK_SIZE];
    unsigned char  iv2[BLOCK_SIZE];
    int i, j;

    RAND_bytes(in1, MACRO_SIZE);
    RAND_bytes(iv1, BLOCK_SIZE);
    RAND_bytes(iv2, BLOCK_SIZE);
    mixencrypt(in1, out1, MACRO_SIZE, key, iv1);

    for (i=0; i<MACRO_SIZE; i+=MINI_SIZE) {
        printf("CHANGING MINIBLOCK %d\n", i / MINI_SIZE);
        memcpy(in2, in1, MACRO_SIZE);
        do { RAND_bytes(&in2[i], MINI_SIZE); }
        while (0 == memcmp((const char*)in1, (const char*)in2, MACRO_SIZE));
        memcpy(in2 + MACRO_SIZE, in2, MACRO_SIZE);

        mixencrypt(in2, out2, MACRO_SIZE*2, key, iv1);
        mixencrypt(in2, out3, MACRO_SIZE,   key, iv2);
        for (j=0; j<MACRO_SIZE; j+=BLOCK_SIZE) {
            D printx("out1: ", &out1[j], BLOCK_SIZE, MINI_SIZE);
            D printx("out2: ", &out2[j], BLOCK_SIZE, MINI_SIZE);
            // test that entropy flows from each block to each other
            assert(0 != memcmp(out1+j, out2+j, BLOCK_SIZE));
            // test that IV affects all the blocks
            assert(0 != memcmp(out2+j, out3+j, BLOCK_SIZE));
            // test that two identical consequent macroblocks cipher differs
            assert(0 != memcmp(out2+j, out2+j+MACRO_SIZE, BLOCK_SIZE));
        }
        printf("ALL OUTPUT BLOCKS CHANGED\n");
    }

    printf("DONE\n");
    return 0;
}
