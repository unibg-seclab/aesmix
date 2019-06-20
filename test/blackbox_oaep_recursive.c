#include <openssl/rand.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "debug.h"
#include "aes_mix_oaep_recursive.h"

unsigned char key[] = "SQUEAMISHOSSIFRA";

int main()
{
    unsigned char  in1[OAEP_BIMACRO_SIZE];
    unsigned char  in2[OAEP_BIMACRO_SIZE*2];
    unsigned char out1[OAEP_BIMACRO_SIZE];
    unsigned char out2[OAEP_BIMACRO_SIZE*2];
    unsigned char out3[OAEP_BIMACRO_SIZE];
    unsigned char  iv1[BLOCK_SIZE];
    unsigned char  iv2[BLOCK_SIZE];
    int i, j;

    RAND_bytes(in1, OAEP_BIMACRO_SIZE);
    RAND_bytes(iv1, BLOCK_SIZE);
    RAND_bytes(iv2, BLOCK_SIZE);
    mixencrypt_oaep_recursive(in1, out1, OAEP_BIMACRO_SIZE, key, iv1);

    for (i=0; i<OAEP_BIMACRO_SIZE; i+=OAEP_MINI_SIZE) {
        printf("CHANGING MINIBLOCK %d\n", i / OAEP_MINI_SIZE);
        memcpy(in2, in1, OAEP_BIMACRO_SIZE);
        do { RAND_bytes(&in2[i], OAEP_MINI_SIZE); }
        while (0 == memcmp((const char*)in1, (const char*)in2, OAEP_BIMACRO_SIZE));
        memcpy(in2 + OAEP_BIMACRO_SIZE, in2, OAEP_BIMACRO_SIZE);

        mixencrypt_oaep_recursive(in2, out2, OAEP_BIMACRO_SIZE*2, key, iv1);
        mixencrypt_oaep_recursive(in2, out3, OAEP_BIMACRO_SIZE,   key, iv2);
        for (j=0; j<OAEP_BIMACRO_SIZE; j+=OAEP_BLOCK_SIZE) {
            D printx("out1: ", &out1[j], OAEP_BLOCK_SIZE, OAEP_MINI_SIZE);
            D printx("out2: ", &out2[j], OAEP_BLOCK_SIZE, OAEP_MINI_SIZE);
            // test that entropy flows from each block to each other
            assert(0 != memcmp(out1+j, out2+j, OAEP_BLOCK_SIZE));
            // test that IV affects all the blocks
            assert(0 != memcmp(out2+j, out3+j, OAEP_BLOCK_SIZE));
            // test that two identical consequent macroblocks cipher differs
            assert(0 != memcmp(out2+j, out2+j+OAEP_BIMACRO_SIZE, OAEP_BLOCK_SIZE));
        }
        printf("ALL OUTPUT BLOCKS CHANGED\n");
    }

    printf("DONE\n");
    return 0;
}
