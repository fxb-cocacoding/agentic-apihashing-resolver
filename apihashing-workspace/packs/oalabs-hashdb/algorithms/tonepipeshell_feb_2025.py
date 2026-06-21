# Source: https://github.com/OALabs/hashdb/blob/main/algorithms/tonepipeshell_feb_2025.py
# License: Apache-2.0
SOURCE = 'https://github.com/OALabs/hashdb/blob/main/algorithms/tonepipeshell_feb_2025.py'
LICENSE = "Apache-2.0"

DESCRIPTION = "TOnePipeShell hash with seed 0x14096B (1313131)"
TYPE = 'unsigned_int'
TEST_1 = 734769215

def hash(data):
    out_hash = 0
    for c in data:
        out_hash = (c + 0x14096B * out_hash) & 0xffffffff
    return out_hash