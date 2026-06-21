#!/usr/bin/env python
# Source: https://github.com/OALabs/hashdb/blob/main/algorithms/custom_shift_add.py
# License: Apache-2.0
SOURCE = 'https://github.com/OALabs/hashdb/blob/main/algorithms/custom_shift_add.py'
LICENSE = "Apache-2.0"


DESCRIPTION = "shift+add with a custom initial value seen in a malware."
TYPE = "unsigned_int"
TEST_1 = 4294890437


def hash(data):
    result = 0x733e14f
    for val in data:
        result = (result << 1) + val
        result &= 0xffffffff
    return result
