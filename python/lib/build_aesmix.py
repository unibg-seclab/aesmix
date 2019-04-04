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

    /* aes_mixslice.h */
    void mixslice(unsigned int thr, const unsigned char* data,
                  unsigned char* fragdata, const unsigned long size,
                  const unsigned char* key, const unsigned char* iv);

    void unsliceunmix(unsigned int thr, const unsigned char* fragdata,
                      unsigned char* out, const unsigned long size,
                      const unsigned char* key, const unsigned char* iv);


    #define BLOCK_SIZE              ...
    #define MINI_SIZE               ...
    #define MINI_PER_MACRO          ...
    #define MACRO_SIZE              ...

""")

ffibuilder.set_source(
    'aesmix._aesmix',
    """
    #include "aes_mix.c"
    #include "aes_mix_multi.c"
    #include "aes_mixslice.c"
    """,
    include_dirs=[os.path.join(os.getcwd(), 'lib', 'includes'),
                  os.path.join(os.getcwd(), 'lib', 'src')],
    libraries=['m', 'crypto'],
)

if __name__ == "__main__":
    ffibuilder.compile()
