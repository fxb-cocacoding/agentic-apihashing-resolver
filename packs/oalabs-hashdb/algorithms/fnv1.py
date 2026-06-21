#!/usr/bin/env python
# Source: https://github.com/OALabs/hashdb/blob/main/algorithms/fnv1.py
# License: Apache-2.0
SOURCE = 'https://github.com/OALabs/hashdb/blob/main/algorithms/fnv1.py'
LICENSE = "Apache-2.0"

DESCRIPTION = "FNV1 hash"
TYPE = 'unsigned_int'
TEST_1 = 116207608


def hash(data):
    val = 0x811c9dc5
    for c in data:
        val = ((0x1000193 * val) ^ c) & 0xffffffff
    return val
