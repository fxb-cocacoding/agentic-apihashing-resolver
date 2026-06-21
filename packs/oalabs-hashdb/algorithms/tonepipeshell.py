# Source: https://github.com/OALabs/hashdb/blob/main/algorithms/tonepipeshell.py
# License: Apache-2.0
SOURCE = 'https://github.com/OALabs/hashdb/blob/main/algorithms/tonepipeshell.py'
LICENSE = "Apache-2.0"

# Created by Still Hsu <still@teamt5.org>

DESCRIPTION = "TOnePipeShell hash with seed 0xC85E31 (13131313)"
TYPE = 'unsigned_int'
TEST_1 = 3454880715

def hash(data):
    out_hash = 0
    for c in data:
        out_hash = (c + 0xC85E31 * out_hash) & 0xffffffff
    return out_hash