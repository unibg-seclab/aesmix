#ifndef AES_MIX_OAEP_H
#define AES_MIX_OAEP_H

#include "aes_mix.h"

#ifndef OAEP_BLOCK_SIZE
#define OAEP_BLOCK_SIZE                                          64
#endif
#ifndef OAEP_MINI_SIZE
#define OAEP_MINI_SIZE                                            4
#endif
#ifndef OAEP_MINI_PER_MACRO
#define OAEP_MINI_PER_MACRO                                    4096
#endif


#define OAEP_MINI_PER_BLOCK      (OAEP_BLOCK_SIZE / OAEP_MINI_SIZE)
#define OAEP_MACRO_SIZE      (OAEP_MINI_SIZE * OAEP_MINI_PER_MACRO)
#define OAEP_BIMACRO_SIZE                     (2 * OAEP_MACRO_SIZE)
#define OAEP_DIGITS               ((int) log2(OAEP_MINI_PER_MACRO))
#define OAEP_DOF                  ((int) log2(OAEP_MINI_PER_BLOCK))

void mixencrypt_oaep (
    const unsigned char* data, unsigned char* out, const unsigned long size,
    const unsigned char* key, const unsigned char* iv
);

void mixdecrypt_oaep (
    const unsigned char* data, unsigned char* out, const unsigned long size,
    const unsigned char* key, const unsigned char* iv
);

#endif // AES_MIX_OAEP_H
