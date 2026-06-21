#!/usr/bin/env python
# Source: https://github.com/OALabs/hashdb/blob/main/algorithms/guloader_3C389ABC.py
# License: Apache-2.0
SOURCE = 'https://github.com/OALabs/hashdb/blob/main/algorithms/guloader_3C389ABC.py'
LICENSE = "Apache-2.0"


DESCRIPTION = "Guloader hash with seed 0x1505 and XOR 0x3C389ABC"
TYPE = 'unsigned_int'
TEST_1 = 2819429408


def hash(data):
    out_hash = 0x1505
    for c in data:
        out_hash = ((c + 33 * out_hash) ^ 0x3C389ABC) & 0xffffffff
    return out_hash
