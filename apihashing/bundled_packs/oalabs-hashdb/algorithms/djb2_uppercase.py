#!/usr/bin/env python
# Source: https://github.com/OALabs/hashdb/blob/main/algorithms/djb2_uppercase.py
# License: Apache-2.0
SOURCE = 'https://github.com/OALabs/hashdb/blob/main/algorithms/djb2_uppercase.py'
LICENSE = "Apache-2.0"


DESCRIPTION = "A variant of the DJB2 hash algorithm that converts lowercase letters to uppercase"
TYPE = 'unsigned_int'
TEST_1 = 0x07AB31C2

def hash(data):
    hash_value = 4919
    for char in data:
        if isinstance(char, int):
            char = chr(char)
        if ord('a') <= ord(char) <= ord('z'):
            char = chr(ord(char) - 32)
        hash_value = (hash_value * 33) + ord(char)
    return hash_value & 0xFFFFFFFF
