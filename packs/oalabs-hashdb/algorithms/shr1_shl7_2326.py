#!/usr/bin/env python
# Source: https://github.com/OALabs/hashdb/blob/main/algorithms/shr1_shl7_2326.py
# License: Apache-2.0
SOURCE = 'https://github.com/OALabs/hashdb/blob/main/algorithms/shr1_shl7_2326.py'
LICENSE = "Apache-2.0"


DESCRIPTION = "Seed 0x2326 shift right 1 shift left 7"
TYPE = 'unsigned_int'
TEST_1 = 0x9bfc4734


def hash(data):
    out = 0x2326
    for c in data:
        out = (out + c + ((out >> 1) | (out << 7))) & 0xffffffff
    return out
