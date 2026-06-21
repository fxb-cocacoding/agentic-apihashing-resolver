#!/usr/bin/env python
# Source: https://github.com/OALabs/hashdb/blob/main/algorithms/xor_shr8.py
# License: Apache-2.0
SOURCE = 'https://github.com/OALabs/hashdb/blob/main/algorithms/xor_shr8.py'
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

DESCRIPTION = "XOR and SHIFT RIGHT 21"
TYPE = 'unsigned_int'
TEST_1 = 1054536684


BYTEOPS = ByteOps()

def shr32(value, count):
    return int.from_bytes(BYTEOPS.shr_dword((value & 0xffffffff).to_bytes(4, 'little'), count), 'little')


def hash(data):
    val = 0xFFFFFFFF
    for i in data:
        ci = i
        ci = ci ^ val
        ci = ci * val
        ci_hex = "%16x" % ci
        ci_hex = ci_hex[8:16]
        ci_hex = int(ci_hex, 16)
        shr8 = shr32(val, 8)
        val = ci_hex ^ shr8
    return val & 0xffffffff
