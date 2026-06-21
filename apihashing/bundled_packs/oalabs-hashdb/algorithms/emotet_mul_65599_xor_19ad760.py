#!/usr/bin/env python
# Source: https://github.com/OALabs/hashdb/blob/main/algorithms/emotet_mul_65599_xor_19ad760.py
# License: Apache-2.0
SOURCE = 'https://github.com/OALabs/hashdb/blob/main/algorithms/emotet_mul_65599_xor_19ad760.py'
LICENSE = "Apache-2.0"


DESCRIPTION = """

    Author = rfLENtlr

    This algorithm was used by Emotet.

    Sample SHA256: 5d267403191a8786db2062584f298478ba59aa7b4d23adcf850a2c14a55c6d97

"""
TYPE = 'unsigned_int'
TEST_1 = 3163386495

def hash(data):
    hash_value = 0
    for c in data:
        hash_value = (c + hash_value * 0x1003f) & 0xFFFFFFFF
    return hash_value ^ 0x19ad760