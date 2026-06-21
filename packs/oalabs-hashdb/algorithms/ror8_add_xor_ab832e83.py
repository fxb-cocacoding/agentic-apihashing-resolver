#!/usr/bin/env python
# Source: https://github.com/OALabs/hashdb/blob/main/algorithms/ror8_add_xor_ab832e83.py
# License: Apache-2.0
SOURCE = 'https://github.com/OALabs/hashdb/blob/main/algorithms/ror8_add_xor_ab832e83.py'
LICENSE = "Apache-2.0"

from byteops import ByteOps


DESCRIPTION = "Hash based on ror8, add, xor with initial state 0x832E83AB"
# Type can be either 'unsigned_int' (32bit) or 'unsigned_long' (64bit)
TYPE = 'unsigned_int'
# Test must match the exact has of the string 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
TEST_1 = 0x828E7DBD


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
    state = 0x832E83AB
    for i in range(len(data)):
        val = ror(state, 8)
        if i < len(data) - 1:
            val += data[i] | data[i + 1] << 8
        else:
            val += data[i]
        state ^= val
    return state
