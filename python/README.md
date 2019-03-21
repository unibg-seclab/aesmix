# aesmix python wrapper

Python wrapper for the libaesmix mixing library that also implements the slicing phase.

## description

This directory contains the python wrapper based on cffi. Please check the file `python/example.py` to understand how to use the library. The python wrapper requires the dynamic library `libaesmix` to be available in your system. Follow the installation steps in the `REAMDE.md` file in the parent directory before using the python library.


## example

To run the example (after installing the library in your system) run:

    make run


## details

The mixing phase is implemented in C (fast), whereas the slicing phase is implemented in python (not so fast).

Since the slicing phase is only involved in file management and can be speed up easily with ad-hoc file management, if you need to benchmark the solution, we suggest to only benchmark the mixing phase.


# key regression mechanism

The key regression mechanism implementation is based on ["Key Regression: Enabling Efficient Key Distribution for Secure Distributed Storage"](https://eprint.iacr.org/2005/303.pdf).


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
