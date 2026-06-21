#!/usr/bin/env python
# Source: https://github.com/OALabs/hashdb/blob/main/algorithms/crc32.py
# License: Apache-2.0
SOURCE = 'https://github.com/OALabs/hashdb/blob/main/algorithms/crc32.py'
LICENSE = "Apache-2.0"

import zlib

DESCRIPTION = "Standard crc32 hash."
TYPE = 'unsigned_int'
TEST_1 = 532866770


def hash(data):
    return 0xffffffff & zlib.crc32(data)
