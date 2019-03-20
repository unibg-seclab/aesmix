#!/usr/bin/env python

import cffi
import os

ffibuilder = cffi.FFI()

ffibuilder.cdef("""

    /* aes_mix.h */
    void mixencrypt(const unsigned char* data, unsigned char* out,
                    const unsigned long size, const unsigned char* key,
                    const unsigned char* iv);
    void mixdecrypt(const unsigned char* data, unsigned char* out,
                    const unsigned long size, const unsigned char* key,
                    const unsigned char* iv);

    /* aes_mix_multi.h */
    void t_mixencrypt(unsigned int thr, const unsigned char* data,
                      unsigned char* out, const unsigned long size,
                      const unsigned char* key, const unsigned char* iv);
    void t_mixdecrypt(unsigned int thr, const unsigned char* data,
                      unsigned char* out, const unsigned long size,
                      const unsigned char* key, const unsigned char* iv);

    #define BLOCK_SIZE              ...
    #define MINI_SIZE               ...
    #define MINI_PER_MACRO          ...
    #define MACRO_SIZE              ...

""")

basepath = os.path.join(os.path.dirname(__file__), os.pardir)

ffibuilder.set_source(
    'aesmix._aesmix',
    """
    #include "aes_mix.h"
    #include "aes_mix_multi.h"
    """,
    include_dirs=[os.path.join(basepath, 'includes')],
    libraries=['crypto', 'aesmix'],
)

if __name__ == "__main__":
    ffibuilder.compile()
