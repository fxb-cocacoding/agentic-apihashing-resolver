#!/usr/bin/env python
# Source: https://github.com/OALabs/hashdb/blob/main/algorithms/emotet.py
# License: Apache-2.0
SOURCE = 'https://github.com/OALabs/hashdb/blob/main/algorithms/emotet.py'
LICENSE = "Apache-2.0"

DESCRIPTION = "Emotet November 2021"
TYPE = 'unsigned_int'
TEST_1 = 3172443423


def hash(data):
    hash_value = 0
    for i in range(len(data)):
        hash_value = (((hash_value << 16) & 0xffffffff)
                      + ((hash_value << 6) & 0xffffffff)
                      + data[i] - hash_value) & 0xffffffff
    return hash_value
