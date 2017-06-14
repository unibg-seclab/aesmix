from collections import Counter
from functools import reduce
from six.moves import xrange
from operator import add
from math import log

## This module uses counter insted of actual data, to check that at the end
## of the shuffling part, the entropy of each block has reached all the
## blocks in the macroblock (the whole meaning of AES MIX).
## This module is used to test the shuffling part and verify the assertion.


## PARAMETERS
MINI_SIZE = 4
BLOCK_SIZE = 16
MINI_PER_MACRO = 1024

# COMPUTED PARAMETERS (DO NOT TOUCH)
MINI_PER_BLOCK = BLOCK_SIZE // MINI_SIZE
DIGITS = int(log(MINI_PER_MACRO, 2))
DOF = int(log(MINI_PER_BLOCK, 2))


## this is the only function you actually want to change to test the shuffling
def shuffle(macro, mask, dist):
    """shuffle the blocks to be ready for encryption"""
    shuffled = []
    i, start = 0, 0
    while start < (1<<DIGITS):
        j, off = 0, start
        while j < MINI_PER_BLOCK:
            shuffled.append(macro[off])
            j, off = j + 1, off + dist
        i, start = i + 1, ((start|mask)+1) & ~mask
    return shuffled

def mixencrypt(macro):
    """mix the entropy in BLOCK_SIZE // MINI_SIZE consecutive miniblocks"""
    return [reduce(add, macro[off:off+MINI_PER_BLOCK])
            for off in xrange(0, MINI_PER_MACRO, MINI_PER_BLOCK)
            for _ in xrange(MINI_PER_BLOCK)]

def mixencrypt_macroblock(macro):
    """encrypt the whole macroblock"""
    for step in xrange(0, DIGITS // DOF):
        mask = ((1 << DOF) - 1) << (step * DOF);
        dist = 1 << (step * DOF);
        print(step, bin(mask)[2:].zfill(DIGITS), dist)
        macro = mixencrypt(shuffle(macro, mask, dist))
        print(macro[0])
    return macro

if __name__ == "__main__":
    macro = [Counter([i]) for i in xrange(MINI_PER_MACRO)]
    encrypted = mixencrypt_macroblock(macro)

    for mini in encrypted:
        assert(mini == encrypted[0])
        assert(len(mini) == MINI_PER_MACRO)
        assert(all(mini[k] == 1 for k in xrange(MINI_PER_MACRO)))

    print("\n== ALL TESTS PASSED == \n")
