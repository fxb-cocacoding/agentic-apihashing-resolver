#!/usr/bin/env python
# Source: https://github.com/OALabs/hashdb/blob/main/algorithms/or20_xor_rol19.py
# License: Apache-2.0
SOURCE = 'https://github.com/OALabs/hashdb/blob/main/algorithms/or20_xor_rol19.py'
LICENSE = "Apache-2.0"

from byteops import ByteOps


DESCRIPTION = "OR 0x20 and XOR and ROL 19"
TYPE = 'unsigned_int'
TEST_1 = 0x186f3f38


BYTEOPS = ByteOps()


def rol(inVal, numShifts, dataSize=32):
    '''rotate left instruction emulation'''
    if numShifts == 0:
        return inVal
    if (numShifts < 0) or (numShifts > dataSize):
        raise ValueError('Bad numShifts')
    if dataSize != 32:
        raise ValueError('Bad dataSize')
    value = (inVal & 0xffffffff).to_bytes(4, 'little')
    return int.from_bytes(BYTEOPS.rol_dword(value, numShifts), 'little')


def hash(data):
    val = 0xffffffff
    ors = 0
    for i in data:
        ors = i | 32
        val = ors ^ rol(val, 19, 32)
    return val
