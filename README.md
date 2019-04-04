# aesmix

[![Build Status](https://travis-ci.org/unibg-seclab/aesmix.svg?branch=master)](https://travis-ci.org/unibg-seclab/aesmix)

Open source base implementation of the _Mix&Slice_ encryption mode described in the paper:
[Mix&Slice: Efficient Access Revocation in the Cloud](http://spdp.di.unimi.it/papers/bdfprs-ccs2016.pdf)
presented at the 23rd ACM Conference on Computer and Communication Security (CCS 2016).

<p align="center">
  <img src="https://cdn.rawgit.com/unibg-seclab/aesmix/master/doc/fragments.svg"
       alt="Mix&Slice" width="80%" />
</p>


## Idea

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

## Implementation

The implementation is done in C and consists of single-threaded and a
multi-threaded encryption/decryption functions that make use of AES as base
symmetric encryption primitives. The use of OpenSSL EVP APIs leverages
hardware-accelerated AES-NI primitives when available.


## Installation

Before proceeding please install the `openssl/crypto` library source and the
`libtool` binary.  In ubuntu you can proceed as follows:

    sudo apt install libtool-bin libssl-dev

To compile and install the dynamic library in your system you can:

    make
    sudo make install

To remove the library simply do:

    sudo make uninstall


## Python wrapper

The python wrapper based on cffi can be found in the [`python`](python)
directory. The python implementation wraps both the phases and offers a
CLI tool that wraps the `libaesmix` library.

The key regression mechanism is also implemented in the python wrapper.

Please refer to the [`README.rst`](python/README.rst) file contained in the
[`python`](python) directory for more details.


## Usage

The file `includes/aes_mix.h` contains the following three definitions:

 * `BLOCK_SIZE`: number of bytes in a cipher block (16 bytes for AES).
 * `MINI_SIZE`: number of bytes in a miniblock.
 * `MINI_PER_MACRO`: number of mini-blocks in a macro-block.

*These entities can be modified at compile time to try with different sizes*


### Single-thread APIs

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

See the file `test/main.c` for an example.


### Multi-thread APIs

The file `includes/aes_mix_multi.h` contains the prototypes of the only two
methods that are necessary to use Mix&Slice in multi-threaded mode:

    void t_mixencrypt(unsigned int thr, const unsigned char* data,
                      unsigned char* out, const unsigned long size,
                      const unsigned char* key, const unsigned char* iv);

    void t_mixdecrypt(unsigned int thr, const unsigned char* data,
                      unsigned char* out, const unsigned long size,
                      const unsigned char* key, const unsigned char* iv);

The only additional parameter is `thr`, the number of threads to use.

See the file `test/multithread.c` for an example.


### Slicing phase

The mixing phase is the real encryption phase. The slicing phase strongly depends
on the file management and should be implemented according to the ratio of policy
updates with respect to decryption processes and can be easily sped up with as-hoc
file management. Because of this, the performance of the mixing phase is a good
proxy of the performance of the whole Mix&Slice technique.

The version implemented here keeps the fragments together. This benefits the
policy update process, whereas the decryption process has to pay the overhead
for rearranging the bytes before performing the unmixing phase.

The file `includes/aes_mixslice.h` contains the prototypes of the two methods
that perform the whole Mix&Slice encryption:

    void mixslice(unsigned int thr, const unsigned char* data,
                  unsigned char* fragdata, const unsigned long size,
                  const unsigned char* key, const unsigned char* iv);

    void unsliceunmix(unsigned int thr, const unsigned char* fragdata,
                      unsigned char* out, const unsigned long size,
                      const unsigned char* key, const unsigned char* iv);

The `mixslice` method first uses `t_mixencrypt` to perform the mixing phase.
The slicing phase rearranges the output of the mixing phase in slices.
The user is responsible for creating the buffer that will contain the `fragdata`.
The slices are concatenated and written to the `fragdata` buffer. The user
of the function, can read the fragments directly from there as follows:

 * each fragment consists of `fragsize = size / MINI_PER_MACRO` bytes;
 * the first fragment spans the `fragdata` bytes in range `[0, fragsize)`;
 * the second fragment spans the `fragdata` bytes in range `[fragsize, fragsize*2)`;
 * and so on until `[size - fragsize, size)`.


## Test

There are three test suites:

 * *main*: main test suite that verifies that Mix&Slice principles
   are enforced.

 * *blackbox*: test suite that verifies the Mix&Slice principles in an
   *abstract* sense (without knowledge about the code).

 * *multithread*: test suite that verifies that the Mix&Slice principles
   are enforced in the multi-threaded implementation.


*make* is used for compilation and testing purposes. A basic *compile-and-test*
setup is made by the steps:

    make
    make test

See the `Makefile` for all the compile and test targets.
