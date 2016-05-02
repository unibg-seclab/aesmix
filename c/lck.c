#include <stdio.h>
#include <openssl/evp.h>

int main()
{
    EVP_CIPHER_CTX ctx;
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char in[] = "0123456789ABCDEF";
    unsigned char cipher[32]; /* at least one block longer than in[] (PAD) */
    unsigned char plain[32]; /* at least one block longer than in[] (PAD) */
    int outlen1, outlen2;

    EVP_EncryptInit(&ctx, EVP_aes_256_ctr(), key, iv);
    EVP_EncryptUpdate(&ctx, cipher, &outlen1, in, sizeof(in));
    EVP_EncryptFinal(&ctx, &cipher[outlen1], &outlen2);
    printf("ciphertext: %.*s\n", outlen1 + outlen2, cipher);

    EVP_DecryptInit(&ctx, EVP_aes_256_ctr(), key, iv);
    EVP_DecryptUpdate(&ctx, plain, &outlen1, cipher, outlen1 + outlen2);
    EVP_DecryptFinal(&ctx, &plain[outlen1], &outlen2);
    printf("plaintext:  %.*s\n", outlen1 + outlen2, plain);

    return 0;
}
