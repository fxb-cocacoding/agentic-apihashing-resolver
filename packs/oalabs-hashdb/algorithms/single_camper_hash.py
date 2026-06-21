#!/usr/bin/env python
# Source: https://github.com/OALabs/hashdb/blob/main/algorithms/single_camper_hash.py
# License: Apache-2.0
SOURCE = 'https://github.com/OALabs/hashdb/blob/main/algorithms/single_camper_hash.py'
LICENSE = "Apache-2.0"


DESCRIPTION = "Custom API hash using ROR32, constant multiplier 0xBF2E2729, and seed 0xAE54C677"
TYPE = 'unsigned_int'
TEST_1 = 0x79547269


def ror(val, bits):
    return ((val >> bits) | (val << (32 - bits))) & 0xFFFFFFFF

def hash(data):
    h = 0xAE54C677
    result = 0
    for c in data:
        temp = ((c + h) * 0xBF2E2729) & 0xFFFFFFFF
        temp = (ror(temp, 17) + 0xBF2E2729 + h) & 0xFFFFFFFF
        h = (ror(temp, 15) * c) & 0xFFFFFFFF
        doubled = (2 * h) & 0xFFFFFFFF
        result = ror(doubled, 16)
        h = ror(doubled, 14)
    return result
