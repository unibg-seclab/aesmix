# aesmix python wrapper and CLI

Python wrapper and command line tool for the libaesmix mixing library.


## description

This directory contains the python wrapper based on cffi and the command line
tool to use Mix&Slice on your files.

The C implementation has been built with performance in mind, whereas the python
wrapper and the CLI tool has been implemented to offer a more widespread access
of the Mix&Slice capabilities. The mixing and slicing phases use the C
implementation, but the python conversion adds a big overhead since it has
to materialize all the buffers in memory.

Since the tool materializes all the buffers in memory and has to perform both
the mixing and the slicing phases, you should only use the CLI tool on files
that are at maximum as large as a third of your available memory.

Please check the file `python/example.py` to understand how to use the library.


## installation

The python wrapper requires the dynamic library `libaesmix` to be available in
your system. Follow the installation steps in the `REAMDE.md` file in the
parent directory before using the python library.


## example

To run the example (after installing the library in your system) run:

    make run


To install the command line tool in your system (you can also use it from the
virtual environment), first follow the installation steps above, then run:

    make
    sudo make install


Once the `mixslice` tool is installed, you can encrypt a file as follows.

    $ mixslice encrypt sample.txt
    INFO: [*] Encrypting file sample.txt ...
    INFO: Output fragdir:   sample.txt.enc
    INFO: Public key file:  sample.txt.public
    INFO: Private key file: sample.txt.private

To perform a policy update:

    $ mixslice update sample.txt.enc
    INFO: [*] Performing policy update on sample.txt.enc ...
    INFO: Encrypting fragment #68
    INFO: Done

To decrypt a file:

    $ mixslice decrypt sample.txt.enc
    INFO: [*] Decrypting fragdir sample.txt.enc using key sample.txt.public ...
    INFO: Decrypting fragment #68
    INFO: Decrypted file: sample.txt.enc.dec

    $ sha1sum sample.txt sample.txt.enc.dec
    d3e92d3c3bf278e533f75818ee94d472347fa32a  sample.txt
    d3e92d3c3bf278e533f75818ee94d472347fa32a  sample.txt.enc.dec

--------------------------------------------------------------------------------

# key regression mechanism

The key regression mechanism implementation is based on
["Key Regression: Enabling Efficient Key Distribution for Secure Distributed Storage"](https://eprint.iacr.org/2005/303.pdf).


## example

The key regression library can be used as follows.

    from aesmix.keyreg import KeyRegRSA


    iters = 5
    stp = KeyRegRSA()

    print("== WINDING ==")
    for i in range(iters):
        stp, stm = stp.wind()
        print("k%i: %r" % (i, stm.keyder()))

    print("\n== UNWINDING ==")
    for i in range(iters - 1, -1, -1):
        print("k%i: %r" % (i, stm.keyder()))
        stm = stm.unwind()
