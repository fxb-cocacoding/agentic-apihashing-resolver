#!/usr/bin/env python
# Source: https://github.com/OALabs/hashdb/blob/main/algorithms/fnv1a.py
# License: Apache-2.0
SOURCE = 'https://github.com/OALabs/hashdb/blob/main/algorithms/fnv1a.py'
LICENSE = "Apache-2.0"

DESCRIPTION = "FNV1a hash"
TYPE = 'unsigned_int'
TEST_1 = 2603339342


def hash(data):
    val = 0x811c9dc5
    for c in data:
        val = (0x1000193 * (c ^ val)) & 0xffffffff
    return val
