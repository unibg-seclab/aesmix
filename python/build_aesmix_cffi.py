#!/usr/bin/env python

import cffi
import os

ffi = cffi.FFI()

ffi.cdef("""

    /* aes_mix.h */
    void mixencrypt(const unsigned char* data, unsigned char* out,
                    const unsigned long size, const unsigned char* key,
                    const unsigned char* iv);
    void mixdecrypt(const unsigned char* data, unsigned char* out,
                    const unsigned long size, const unsigned char* key,
                    const unsigned char* iv);

    /* aes_mix_oaep.h */
    void mixencrypt_oaep(const unsigned char* data, unsigned char* out,
                         const unsigned long size, const unsigned char* key,
                         const unsigned char* iv);
    void mixdecrypt_oaep(const unsigned char* data, unsigned char* out,
                         const unsigned long size, const unsigned char* key,
                         const unsigned char* iv);

    /* aes_mix_multi.h */
    void t_mixencrypt(unsigned int thr, const unsigned char* data,
                      unsigned char* out, const unsigned long size,
                      const unsigned char* key, const unsigned char* iv);
    void t_mixdecrypt(unsigned int thr, const unsigned char* data,
                      unsigned char* out, const unsigned long size,
                      const unsigned char* key, const unsigned char* iv);

    /* aes_mix_oaep.h */
    void t_mixencrypt_oaep(unsigned int thr, const unsigned char* data,
                           unsigned char* out, const unsigned long size,
                           const unsigned char* key, const unsigned char* iv);
    void t_mixdecrypt_oaep(unsigned int thr, const unsigned char* data,
                           unsigned char* out, const unsigned long size,
                           const unsigned char* key, const unsigned char* iv);

    #define BLOCK_SIZE               16
    #define MINI_SIZE                 4
    #define MINI_PER_MACRO         1024
    #define MACRO_SIZE              ...
""")

basepath = os.path.join(os.path.dirname(__file__), os.pardir)

ffi.set_source(
    '_aesmix_cffi',
    """
    #include "aes_mix.h"
    #include "aes_mix_oaep.h"
    #include "aes_mix_multi.h"
    #include "aes_mix_multi_oaep.h"
    """,
    include_dirs=[os.path.join(basepath, 'includes')],
    libraries=['aesmix', 'crypto'],
    library_dirs=[basepath],
    extra_link_args=['-Wl,-rpath=.']
)

ffi.compile()
