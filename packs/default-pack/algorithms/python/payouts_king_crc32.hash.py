from __future__ import annotations

from apihashing.plugin_api import FunctionHashImplementation

# Source: https://www.zscaler.com/blogs/security-research/payouts-king-takes-aim-ransomware-throne


def payouts_king_crc32(input_string: bytes) -> int:
    checksum = 0
    poly = 0xBDC65592
    for char_val in input_string:
        char_val |= 0x20
        checksum ^= char_val
        for _ in range(8):
            if checksum & 1:
                checksum = (checksum >> 1) ^ poly
            else:
                checksum >>= 1
            checksum &= 0xFFFFFFFF
    return checksum


def _hash(library_name: str, symbol_name: str) -> int:
    del library_name
    return payouts_king_crc32(symbol_name.encode('utf-8'))


HASH_IMPLEMENTATION = FunctionHashImplementation(
    id='payouts_king_crc32',
    display_name='Payouts King CRC32',
    callback=_hash,
    description='Custom CRC checksum algorithm documented by Zscaler for Payouts King.',
    hash_size_bits=32,
    author='Zscaler ThreatLabz',
    source='https://www.zscaler.com/blogs/security-research/payouts-king-takes-aim-ransomware-throne',
)
