#!/usr/bin/env python
# Source: https://github.com/OALabs/hashdb/blob/main/algorithms/babbleloader.py
# License: Apache-2.0
SOURCE = 'https://github.com/OALabs/hashdb/blob/main/algorithms/babbleloader.py'
LICENSE = "Apache-2.0"


DESCRIPTION = """

    Author = 0x0d4y

    This hashing algorithm was found during my analysis of a BabbleLoader sample, with the goal of validating that the correct API function was obtained.

    Sample MD5:FA3D03C319A7597712EEFF1338DABF92

    Reference: https://0x0d4y.blog/babbleloader-deep-dive-into-edr-and-machine-learning-based-endpoint-protection-evasion/

"""
TYPE = 'unsigned_int'

TEST_1 = 4238996181

def hash(data):
    if isinstance(data, bytes):
        data = data.decode('utf-8')
    
    final_hash = 0
    for char in data:
        char_orded = ord(char)
        final_hash = (final_hash + char_orded) * (char_orded + 0x4af1e366)
        final_hash &= 0xFFFFFFFF
    
    return final_hash

