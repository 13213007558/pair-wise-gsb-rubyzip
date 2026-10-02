"""Generates raw Deflate64 streams that must be rejected by a decoder.

The resulting files are committed under test/data:
* deflate64_beyond64k.bin       - one literal, length 3, distance 65536
                                  with only one byte of history
* deflate64_distance_too_far.bin - one literal, length 3, distance 4 with
                                  only one byte of history

Each stream uses a Kraft-complete set of Huffman tables (verified against
Info-ZIP UnZip's Deflate64 decoder) so the only error is the invalid
back-reference, never a malformed code table.
"""

import os


class BitWriter:
    def __init__(self):
        self.buffer = 0
        self.nbits = 0
        self.out = bytearray()

    def write(self, value, nbits):
        self.buffer |= value << self.nbits
        self.nbits += nbits
        while self.nbits >= 8:
            self.out.append(self.buffer & 0xFF)
            self.buffer >>= 8
            self.nbits -= 8

    def code(self, canonical, nbits):
        for i in range(nbits - 1, -1, -1):
            self.write((canonical >> i) & 1, 1)

    def finish(self):
        if self.nbits:
            self.out.append(self.buffer & 0xFF)
        return bytes(self.out)


ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]


def canonical(lengths):
    max_bits = max(lengths) if any(lengths) else 0
    counts = [0] * (max_bits + 1)
    for length in lengths:
        if length:
            counts[length] += 1
    code = 0
    next_code = [0] * (max_bits + 1)
    for bits in range(1, max_bits + 1):
        code = (code + counts[bits - 1]) << 1
        next_code[bits] = code
    codes = [0] * len(lengths)
    for i, length in enumerate(lengths):
        if length:
            codes[i] = next_code[length]
            next_code[length] += 1
    return codes


def build(distance_symbol, distance_extra_bits, distance_extra_value):
    # Literal Z length 1, three fillers length 3, EOB length 3.
    lit = [0] * 286
    lit[0x5A] = 1
    lit[0x59] = 3
    lit[0x57] = 3
    lit[256] = 3
    lit[257] = 3
    dist = [5] * 32

    seq = lit + dist
    # Code-length values present: 0, 1, 2, 3, 5. One length-1 code and four
    # length-3 codes are Kraft-complete (1/2 + 4/8 = 1).
    cl = [0] * 19
    cl[0] = 1
    cl[1] = 3
    cl[3] = 3
    cl[2] = 3
    cl[5] = 3

    bw = BitWriter()
    bw.write(1, 1)   # BFINAL
    bw.write(2, 2)   # BTYPE dynamic
    bw.write(len(lit) - 257, 5)
    bw.write(len(dist) - 1, 5)
    bw.write(19 - 4, 4)
    for i in range(19):
        bw.write(cl[ORDER[i]], 3)
    cl_codes = canonical(cl)
    for length in seq:
        bw.code(cl_codes[length], cl[length])

    lit_codes = canonical(lit)
    dist_codes = canonical(dist)
    bw.code(lit_codes[0x5A], lit[0x5A])
    bw.code(lit_codes[257], lit[257])  # length 3
    bw.code(dist_codes[distance_symbol], 5)
    bw.write(distance_extra_value, distance_extra_bits)
    bw.code(lit_codes[256], lit[256])
    return bw.finish()


here = os.path.dirname(__file__)
data_dir = os.path.join(here, '..', 'data')

# Distance symbol 31, max extra -> 49153 + 16383 = 65536 with 1 byte of
# history.
with open(os.path.join(data_dir, 'deflate64_beyond64k.bin'), 'wb') as f:
    f.write(build(31, 14, (1 << 14) - 1))

# Distance symbol 3 (base 4, no extra) with 1 byte of history.
with open(os.path.join(data_dir, 'deflate64_distance_too_far.bin'), 'wb') as f:
    f.write(build(3, 0, 0))
