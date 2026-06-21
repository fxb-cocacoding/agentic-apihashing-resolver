#!/usr/bin/env python
# Source: https://github.com/OALabs/hashdb/blob/main/algorithms/djb2_vohuk_ransomware_dec_2022.py
# License: Apache-2.0
SOURCE = 'https://github.com/OALabs/hashdb/blob/main/algorithms/djb2_vohuk_ransomware_dec_2022.py'
LICENSE = "Apache-2.0"


DESCRIPTION = "Vohuk Ransomware's variant of DJB2 as of December 2022"
TYPE = 'unsigned_int'
TEST_1 = 1274984080


def hash(data: bytearray) -> int:
    hash = 0x1505
    for b in data:
        if ((b - 0x41) & 0xFFFFFFFF) < 0x20:
            b += 0x20
        hash += b + ((0x20 * hash) & 0xFFFFFFFF)
        hash &= 0xFFFFFFFF
    return hash
