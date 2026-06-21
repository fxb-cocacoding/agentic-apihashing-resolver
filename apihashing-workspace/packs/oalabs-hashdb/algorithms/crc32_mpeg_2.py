#!/usr/bin/env python
# Source: https://github.com/OALabs/hashdb/blob/main/algorithms/crc32_mpeg_2.py
# License: Apache-2.0
SOURCE = 'https://github.com/OALabs/hashdb/blob/main/algorithms/crc32_mpeg_2.py'
LICENSE = "Apache-2.0"


DESCRIPTION = "MPEG-2 version of CRC-32."
TYPE = "unsigned_int"
TEST_1 = 1603001975


def hash(data):
    crc = 0xFFFFFFFF
    for val in data:
        crc ^= val << 24
        for _ in range(8):
            crc = crc << 1 if (crc & 0x80000000) == 0 else (crc << 1) ^ 0x104C11DB7
    return crc
