#!/usr/bin/env python
# Source: https://github.com/OALabs/hashdb/blob/main/algorithms/djb2_nokoyawa.py
# License: Apache-2.0
SOURCE = 'https://github.com/OALabs/hashdb/blob/main/algorithms/djb2_nokoyawa.py'
LICENSE = "Apache-2.0"


DESCRIPTION = "Variant of djb2 hash in use by Nokoyawa ransomware"
# Type can be either 'unsigned_int' (32bit) or 'unsigned_long' (64bit)
TYPE = 'unsigned_int'
# Test must match the exact has of the string 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
TEST_1 = 3792689168


def hash(data):
    generated_hash = 5381
    for b in data:
        generated_hash = (generated_hash * 33 + (b if b < 0x61 else (b - 0x20))) & 0xFFFFFFFF
    return generated_hash
