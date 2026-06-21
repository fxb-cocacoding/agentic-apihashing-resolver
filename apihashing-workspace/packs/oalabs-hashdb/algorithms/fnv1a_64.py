#!/usr/bin/env python
# Source: https://github.com/OALabs/hashdb/blob/main/algorithms/fnv1a_64.py
# License: Apache-2.0
SOURCE = 'https://github.com/OALabs/hashdb/blob/main/algorithms/fnv1a_64.py'
LICENSE = "Apache-2.0"

DESCRIPTION = "FNV1a hash (64-bit)"
TYPE = 'unsigned_long'
TEST_1 = 14074705352429455374


def hash(data):
    val = 0xcbf29ce484222325
    for c in data:
        val = (0x100000001b3 * (c ^ val)) & 0xffffffffffffffff
    return val
