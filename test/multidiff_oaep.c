#include <openssl/rand.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "debug.h"
#include "aes_mix_multi_oaep.h"

#define SIZE (4L*OAEP_BIMACRO_SIZE)
#define ENC_THREADS 3
#define DEC_THREADS 2

int main(int argc, char *argv[]) {

    (void) argc;
    (void) argv;

    unsigned char key[BLOCK_SIZE];
    unsigned char  iv[BLOCK_SIZE];
    unsigned char *in;
    unsigned char *dec;
    unsigned char *out;

    in = malloc(SIZE);
    dec = malloc(SIZE);
    out = malloc(SIZE);

    RAND_bytes(in, SIZE);
    RAND_bytes(key, BLOCK_SIZE);
    RAND_bytes(iv, BLOCK_SIZE);

    printf("ENCRYPTION with %d threads (SIZE %lu)\n", ENC_THREADS, SIZE);
    t_mixencrypt_oaep(ENC_THREADS, in, out, SIZE, key, iv);

    printf("DECRYPTION with %d threads (SIZE %lu)\n", DEC_THREADS, SIZE);
    t_mixdecrypt_oaep(DEC_THREADS, out, dec, SIZE, key, iv);

    D print_diff(in, dec, SIZE);
    assert(0 == memcmp(in, dec, SIZE));
    printf("TEST OK\n");

    free(in);
    free(out);
    free(dec);

    return EXIT_SUCCESS;
}
