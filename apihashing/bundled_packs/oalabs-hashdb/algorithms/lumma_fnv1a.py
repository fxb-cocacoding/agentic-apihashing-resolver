# Source: https://github.com/OALabs/hashdb/blob/main/algorithms/lumma_fnv1a.py
# License: Apache-2.0
SOURCE = 'https://github.com/OALabs/hashdb/blob/main/algorithms/lumma_fnv1a.py'
LICENSE = "Apache-2.0"

DESCRIPTION = "FNV1a hash with LummaStealer offset, seen in 0cf55c7e1a19a0631b0248fb0e699bbec1d321240208f2862e37f6c9e75894e7"
TYPE = 'unsigned_int'
TEST_1 = 2983287169

def hash(data):
    val = 0x268c190a
    for c in data:
        val = ((val ^ c) * 0x1000193) & 0xffffffff

    return val
