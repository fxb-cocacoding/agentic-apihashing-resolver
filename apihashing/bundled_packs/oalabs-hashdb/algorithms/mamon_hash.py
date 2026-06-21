#!/usr/bin/env python
# Source: https://github.com/OALabs/hashdb/blob/main/algorithms/mamon_hash.py
# License: Apache-2.0
SOURCE = 'https://github.com/OALabs/hashdb/blob/main/algorithms/mamon_hash.py'
LICENSE = "Apache-2.0"

DESCRIPTION = "Custom hash used in mamon ransomware"
TYPE = 'unsigned_int'
TEST_1 = 3726794573 

def hash(data):
    hash_value = 0x42

    for b in data:
        hash_value = ((hash_value * 33) + b) & 0xFFFFFFFF  # Keep it 32-bit

    return hash_value
