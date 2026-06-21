#!/usr/bin/env python
# Source: https://github.com/OALabs/hashdb/blob/main/algorithms/add_65599.py
# License: Apache-2.0
SOURCE = 'https://github.com/OALabs/hashdb/blob/main/algorithms/add_65599.py'
LICENSE = "Apache-2.0"

DESCRIPTION = "ADD 65599 and MULTIPLY"
TYPE = 'unsigned_int'
TEST_1 = 2480409887

def hash(data):
    result = 0
    for c in data:
        tmp = c + 32
        if(((c - ord('A')) & 0xFFFF) > 26):
            tmp = c
        result = (tmp + 0x1003F * result) & 0xFFFFFFFF
    
    return result
