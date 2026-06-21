#!/usr/bin/env python
# Source: https://github.com/OALabs/hashdb/blob/main/algorithms/add_ror13.py
# License: Apache-2.0
SOURCE = 'https://github.com/OALabs/hashdb/blob/main/algorithms/add_ror13.py'
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

DESCRIPTION = "ADD and ROR 13"
TYPE = 'unsigned_int'
TEST_1 = 3953483048


BYTEOPS = ByteOps()


def ror(inVal, numShifts, dataSize=32):
    '''rotate right instruction emulation'''
    if numShifts == 0:
        return inVal
    if (numShifts < 0) or (numShifts > dataSize):
        raise ValueError('Bad numShifts')
    if dataSize != 32:
        raise ValueError('Bad dataSize')
    value = (inVal & 0xffffffff).to_bytes(4, 'little')
    return int.from_bytes(BYTEOPS.ror_dword(value, numShifts), 'little')


def hash(data):
    val = 0
    for i in data:
        val += i
        val = ror(val, 0xd, 32)
    return val
