#include <openssl/rand.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "debug.h"
#include "aes_mix_multi.h"

#define SIZE (4L*MACRO_SIZE)
#define ENC_THREADS 3
#define DEC_THREADS 2

int main(int argc, char *argv[]) {

    (void) argc;
    (void) argv;

    unsigned char key[KEYSIZE];
    unsigned char  iv[IVSIZE];
    unsigned char *in;
    unsigned char *dec;
    unsigned char *out;

    in = malloc(SIZE);
    dec = malloc(SIZE);
    out = malloc(SIZE);

    RAND_bytes(in, SIZE);
    RAND_bytes(key, KEYSIZE);
    RAND_bytes(iv, IVSIZE);

    printf("ENCRYPTION with %d threads (SIZE %lu)\n", ENC_THREADS, SIZE);
    t_mixencrypt(ENC_THREADS, in, out, SIZE, key, iv);

    printf("DECRYPTION with %d threads (SIZE %lu)\n", DEC_THREADS, SIZE);
    t_mixdecrypt(DEC_THREADS, out, dec, SIZE, key, iv);

    D print_diff(in, dec, SIZE);
    assert(0 == memcmp(in, dec, SIZE));
    printf("TEST OK\n");

    free(in);
    free(out);
    free(dec);

    return EXIT_SUCCESS;
}
