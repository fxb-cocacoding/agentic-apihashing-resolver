#!/usr/bin/env python
# Source: https://github.com/OALabs/hashdb/blob/main/algorithms/add_hiword_add_lowword.py
# License: Apache-2.0
SOURCE = 'https://github.com/OALabs/hashdb/blob/main/algorithms/add_hiword_add_lowword.py'
LICENSE = "Apache-2.0"


DESCRIPTION = """
Sum of characters in hi word and low word combined to DWORD.
Used in Darkside ransomware API hash."""
TYPE = 'unsigned_int'
TEST_1 = 2383353113


def hash(data):
    hash_high = 0xffff
    hash_low = 0xffff
    for ptr in range(len(data)):
        hash_low = (hash_low + data[ptr])
        hash_high = (hash_high + hash_low)
    hash_high %= 0xFFF1
    hash_low %= 0xFFF1
    return (hash_high << 16) + hash_low
