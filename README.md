# aesmix

Open source base implementation of the _Mix&Slice_ encryption mode described in the paper:
[Mix&Slice: Efficient Access Revocation in the Cloud](http://spdp.di.unimi.it/papers/bdfprs-ccs2016.pdf)
presented at the 23rd ACM Conference on Computer and Communication Security (CCS 2016).

<p align="center">
  <img src="https://cdn.rawgit.com/unibg-seclab/aesmix/master/doc/fragments.svg"
       alt="Mix&Slice" width="80%" />
</p>


## idea

The approach relies on a resource transformation that provides strong mutual
inter-dependency in its encrypted representation. To revoke access on a resource,
it is then sufficient to update a small portion of it, with the guarantee that
the resource as a whole (and any portion of it) will become unintelligible to
those from whom access is revoked.

The approach identifies the following basic concepts:

 * **Block**: a sequence of bits input to a block cipher (it corresponds to the
   classical block concept).

 * **Mini-block**: a sequence of bits, of a specified length, contained in a block.
   It represents our atomic unit of protection (i.e., when removing bits, we will
   operate at the level of mini-block removing all its bits).

 * **Macro-block**: a sequence of blocks. It allows extending the application of
   block cipher on sequences of bits larger than individual blocks. In particular,
   our approach operates mixing bits at the macro-block level, extending
   protection to work against attacks beyond the individual block.

<p align="center">
  <img src="https://cdn.rawgit.com/unibg-seclab/aesmix/master/doc/mixing.svg"
       alt="Mix&Slice blocks" width="60%" />
</p>

## implementation

The implementation is done in C and consists of single-threaded and a
multi-threaded encryption/decryption functions that make use of AES as base
symmetric encryption primitives. The use of OpenSSL EVP APIs leverages
hardware-accelerated AES-NI primitives when available.


## usage

The file `includes/aes_mix.h` contains the following three definitions:

 * `BLOCK_SIZE`: number of bytes in a cipher block (16 bytes for AES).
 * `MINI_SIZE`: number of bytes in a miniblock.
 * `MINI_PER_MACRO`: number of mini-blocks in a macro-block.

*These entities can be modified at compile time to try with different sizes*


### single-thread APIs

The file `includes/aes_mix.h` contains the prototype of the only two
methods that are necessary to use Mix&Slice:

    void mixencrypt(const unsigned char* data, unsigned char* out,
                    const unsigned long size, const unsigned char* key,
                    const unsigned char* iv);

    void mixdecrypt(const unsigned char* data, unsigned char* out,
                    const unsigned long size, const unsigned char* key,
                    const unsigned char* iv);

The parameters are as follows.

 * `data`: pointer to the source buffer (plaintext in case of
   `mixencrypt` and ciphertext in case of `mixdecrypt`)
 * `out`: pointer to the destination buffer
 * `size`: number of bytes in source (and destination) buffers
 * `key`: symmetric key (string) used for the AES functions
 * `iv`: initialization vector for the AES functions

See the file `test/main.c` for an example of use of Mix&Slice.


### multi-thread APIs

The file `includes/aes_mix_multi.h` contains the prototype of the only two
methods that are necessary to use Mix&Slice in multi-threaded mode:

    void t_mixencrypt(unsigned int thr, const unsigned char* data, unsigned char* out,
        const unsigned long size, const unsigned char* key, const unsigned char* iv);

    void t_mixdecrypt(unsigned int thr, const unsigned char* data, unsigned char* out,
        const unsigned long size, const unsigned char* key, const unsigned char* iv);

The only additional parameter is `thr`, the number of threads to use.

See the file `test/multithread.c` for an example of use of Mix&Slice.


## test

There are three test suites:

 * *main*: main test suite that verifies that Mix&Slice principles
   are enforced.

 * *blackbox*: test suite that verifies the Mix&Slice principles in an
   *abstract* sense (without knowledge about the code).

 * *multithread*: test suite that verifies that the Mix&Slice principles
   are enforced in the multi-threaded implementation.


## compile

*Make* is used for compilation and testing purposes. A basic
*compile-and-test* setup is made by the steps:

    make
    make test

See the `Makefile` for all the compile and test targets.


## installation

To compile and install the dynamic library in your system you can:

    make
    sudo make install

To remove the library simply do:

    sudo make uninstall


## python wrapper

The python wrapper based on cffi can be found in the `python` directory. The python implementation contains the slicing phase based on the `libaesmix` library and the key regression mechanism.

Please refer to the `README.md` file contained in the `python` directory for more details.
