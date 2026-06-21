#!/usr/bin/env python
# Source: https://github.com/OALabs/hashdb/blob/main/algorithms/revil_010F.py
# License: Apache-2.0
SOURCE = 'https://github.com/OALabs/hashdb/blob/main/algorithms/revil_010F.py'
LICENSE = "Apache-2.0"

# REvil API hashing observed in the following samples:
# 12d8bfa1aeb557c146b98f069f3456cc8392863a2f4ad938722cd7ca1a773b39
# 5f56d5748940e4039053f85978074bde16d64bd5ba97f6f0026ba8172cb29e93
# This highly complex Python code is generously placed in the public domain.
# The authors Lars Wallenborn and Jesko Huettenhain yield all copyrights.
# Please use this code responsibly.

DESCRIPTION = "Lower 21 bits of an LFS with seed 0x2B and multiplier 0x10F"
TYPE = 'unsigned_int'
TEST_1 = 385258


def hash(data):
    result = 0x2b
    for byte in data:
        result = result * 0x010F + byte
    return result & 0x1fffff
