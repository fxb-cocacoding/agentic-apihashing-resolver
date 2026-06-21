#!/usr/bin/env python
# Source: https://github.com/OALabs/hashdb/blob/main/algorithms/shr2_shl5_xor.py
# License: Apache-2.0
SOURCE = 'https://github.com/OALabs/hashdb/blob/main/algorithms/shr2_shl5_xor.py'
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

DESCRIPTION = "SHIFT RIGHT 2 and SHIFT LEFT 5 and XOR"
TYPE = 'unsigned_int'
TEST_1 = 629383115


BYTEOPS = ByteOps()

def shl32(value, count):
    return int.from_bytes(BYTEOPS.shl_dword((value & 0xffffffff).to_bytes(4, 'little'), count), 'little')

def shr32(value, count):
    return int.from_bytes(BYTEOPS.shr_dword((value & 0xffffffff).to_bytes(4, 'little'), count), 'little')


def hash(data):
    result = 0x4e67c6a7
    if data.startswith(b"Nt") or data.startswith(b"Zw"):
        data = data[2:]
    for i in data:
        result ^= (i + shr32(result, 2) + shl32(result, 5)) & 0xffffffff
    return result
