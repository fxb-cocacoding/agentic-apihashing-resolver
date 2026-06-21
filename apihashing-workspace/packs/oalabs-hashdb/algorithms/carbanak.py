#!/usr/bin/env python
# Source: https://github.com/OALabs/hashdb/blob/main/algorithms/carbanak.py
# License: Apache-2.0
SOURCE = 'https://github.com/OALabs/hashdb/blob/main/algorithms/carbanak.py'
LICENSE = "Apache-2.0"

from byteops import ByteOps

########################################################################
# Copyright 2012 Mandiant
# Copyright 2014 FireEye
#
# Mandiant licenses this file to you under the Apache License, Version
# 2.0 (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at:
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.
#
# Reference:
# https://github.com/mandiant/flare-ida/blob/master/shellcode_hashes/make_sc_hash_db.py
#
########################################################################

DESCRIPTION = "Carbanak API hashing used by CARBON SPIDER aka FIN7"
TYPE = 'unsigned_int'
TEST_1 = 204821865


BYTEOPS = ByteOps()

def shl32(value, count):
    return int.from_bytes(BYTEOPS.shl_dword((value & 0xffffffff).to_bytes(4, 'little'), count), 'little')

def shr32(value, count):
    return int.from_bytes(BYTEOPS.shr_dword((value & 0xffffffff).to_bytes(4, 'little'), count), 'little')


def hash(data):
    ctr = 0
    for i in data:
        ctr = shl32(ctr, 4) + i
        if (ctr & 0xF0000000):
            ctr = (shr32(ctr & 0xF0000000, 24) ^ ctr) & 0x0FFFFFFF
    return ctr
