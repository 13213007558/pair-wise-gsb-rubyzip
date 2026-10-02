"""Generate a small static ZIP fixture using ZIP compression method 9
(Deflate64) for every entry.

The compressed streams are assembled directly from Deflate64 bit streams
(stored, fixed Huffman and dynamic Huffman blocks), exercising the parts
of the format that differ from ordinary deflate. The resulting ZIP is
verified to extract correctly with Info-ZIP UnZip 6.00, an independent
implementation of Deflate64.
"""

import struct
import zlib


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

    def align_to_byte(self):
        while self.nbits % 8:
            self.write(0, 1)

    def finish(self):
        if self.nbits:
            self.out.append(self.buffer & 0xFF)
        return bytes(self.out)


def fixed_lit_code(symbol):
    if symbol <= 143:
        return 0b00110000 + symbol, 8
    if symbol <= 255:
        return 0b110010000 + (symbol - 144), 9
    if symbol <= 279:
        return symbol - 256, 7
    return 0b11000000 + (symbol - 280), 8


LENGTH_BASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17,
               19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99,
               115, 131, 163, 195, 227, 258]
LENGTH_EXTRA = [0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
                3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
                0, 0, 0, 16]

DIST_BASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
             257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
             8193, 12289, 16385, 24577, 32769, 49153]
DIST_EXTRA = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
              7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14]


def length_symbol(length):
    for i, base in enumerate(LENGTH_BASE):
        bits = LENGTH_EXTRA[i]
        if base <= length < base + (1 << bits):
            return 257 + i, length - base, bits
    raise ValueError(f'no length symbol for {length}')


def emit_fixed_match(bw, length, distance):
    symbol, extra, bits = length_symbol(length)
    bw.code(*fixed_lit_code(symbol))
    bw.write(extra, bits)
    for code, base in enumerate(DIST_BASE):
        ebits = DIST_EXTRA[code]
        if base <= distance < base + (1 << ebits):
            # Fixed-block distance codes are 5-bit canonical codes sent
            # LSB first; emitting the canonical code bits MSB..LSB is
            # exactly what code() does.
            bw.code(code, 5)
            bw.write(distance - base, ebits)
            return
    raise ValueError(f'no distance symbol for {distance}')


def stored_block(data, final):
    bw = BitWriter()
    bw.write(1 if final else 0, 1)
    bw.write(0, 2)
    bw.align_to_byte()
    bw.write(len(data), 16)
    bw.write(len(data) ^ 0xFFFF, 16)
    bw.out.extend(data)
    return bw.finish()


def fixed_stream(chunks):
    bw = BitWriter()
    bw.write(1, 1)
    bw.write(1, 2)
    for data, distance in chunks:
        if distance == 0:
            for byte in data:
                bw.code(*fixed_lit_code(byte))
        else:
            emit_fixed_match(bw, len(data), distance)
    bw.code(*fixed_lit_code(256))
    return bw.finish()


def simulate(chunks):
    out = bytearray()
    for data, distance in chunks:
        if distance == 0:
            out.extend(data)
        else:
            for _ in data:
                out.append(out[-distance])
    return bytes(out)




CL_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]


def canonical_codes(lengths):
    m = max(lengths) if any(lengths) else 0
    counts = [0] * (m + 1)
    for length in lengths:
        if length:
            counts[length] += 1
    code = 0
    next_code = [0] * (m + 1)
    for bits in range(1, m + 1):
        code = (code + counts[bits - 1]) << 1
        next_code[bits] = code
    codes = [0] * len(lengths)
    for i, length in enumerate(lengths):
        if length:
            codes[i] = next_code[length]
            next_code[length] += 1
    return codes


def dynamic_stream():
    # Kraft-complete literal table with literals C and Z, a length-3 code
    # and EOB. The single 'C' before a distance-1 match produces CCCC.
    lit = [0] * 258
    lit[0x43] = 3
    lit[0x5A] = 3
    lit[255] = 3
    lit[256] = 3
    lit[257] = 1
    dist = [5] * 32

    seq = lit + dist
    # Complete Kraft code for the five code-length values used (0,1,2,3,5).
    cl = [0] * 19
    cl[0] = 1
    cl[1] = 3
    cl[2] = 3
    cl[3] = 3
    cl[5] = 3

    bw = BitWriter()
    bw.write(1, 1)
    bw.write(2, 2)
    bw.write(len(lit) - 257, 5)
    bw.write(len(dist) - 1, 5)
    bw.write(19 - 4, 4)
    for i in range(19):
        bw.write(cl[CL_ORDER[i]], 3)
    cl_codes = canonical_codes(cl)
    for length in seq:
        bw.code(cl_codes[length], cl[length])

    lit_codes = canonical_codes(lit)
    dist_codes = canonical_codes(dist)
    bw.code(lit_codes[0x43], lit[0x43])
    bw.code(lit_codes[257], lit[257])
    bw.code(dist_codes[0], 5)
    bw.code(lit_codes[256], lit[256])
    return bw.finish(), b'CCCC'


def dynamic_window_block(window):
    # Kraft-complete literal table: 256 byte symbols at length 9 use half
    # the space; a single length-1 code fills the other half. We need EOB
    # and a length code, so instead move bytes to length 10 and use short
    # codes for control symbols.
    lit = [0] * 288
    for symbol in range(256):
        lit[symbol] = 10
    lit[256] = 1  # EOB
    lit[257] = 2  # length-3 code
    # Kraft: 256/1024 = 1/4 + 1/2 (EOB) + 1/4 (257) = 1.
    dist = [5] * 32

    seq = lit + dist
    # CL alphabet values: 0,1,2,5,10 (the five distinct code lengths that
    # appear in the literal/distance tables). Lengths 1,2,3,4,4.
    cl = [0] * 19
    cl[0] = 1
    cl[1] = 2
    cl[2] = 3
    cl[5] = 4
    cl[10] = 4

    bw = BitWriter()
    bw.write(1, 1)
    bw.write(2, 2)
    bw.write(len(lit) - 257, 5)
    bw.write(len(dist) - 1, 5)
    bw.write(19 - 4, 4)
    for i in range(19):
        bw.write(cl[CL_ORDER[i]], 3)
    cl_codes = canonical_codes(cl)
    for length in seq:
        bw.code(cl_codes[length], cl[length])

    lc = canonical_codes(lit)
    dc = canonical_codes(dist)
    for byte in window:
        bw.code(lc[byte], lit[byte])
    # Length 3 (symbol 257), distance symbol 31 with 14 extra bits set to
    # 16383 -> distance 49153 + 16383 = 65536.
    bw.code(lc[257], lit[257])
    bw.code(dc[31], 5)
    bw.write((1 << 14) - 1, 14)
    bw.code(lc[256], lit[256])
    return bw.finish()


def dynamic_285_stream():
    # Complete, Kraft-balanced tables. Literal symbols: 0x58 (3), 0x41 (3),
    # 0x59 (3), EOB 256 (3), length 285 (1).
    lit = [0] * 286
    lit[0x58] = 3
    lit[0x41] = 3
    lit[256] = 3
    lit[0x59] = 3
    lit[285] = 1
    # Full 32-code, 5-bit distance table (Deflate64).
    dist = [5] * 32

    seq = lit + dist
    # CL values present: 0,1,3,4,5. Kraft-complete: one length-1 code and
    # four length-3 codes.
    cl = [0] * 19
    cl[0] = 1
    cl[1] = 3
    cl[3] = 3
    cl[4] = 3
    cl[5] = 3

    bw = BitWriter()
    bw.write(1, 1)
    bw.write(2, 2)
    bw.write(len(lit) - 257, 5)
    bw.write(len(dist) - 1, 5)
    bw.write(19 - 4, 4)
    for i in range(19):
        bw.write(cl[CL_ORDER[i]], 3)
    cl_codes = canonical_codes(cl)
    for length in seq:
        bw.code(cl_codes[length], cl[length])

    lc = canonical_codes(lit)
    dc = canonical_codes(dist)
    bw.code(lc[0x58], lit[0x58])
    bw.code(lc[285], lit[285])
    # Deflate64 code 285: length = 3 + 16-bit extra. Use extra=255 for 258.
    bw.write(255, 16)
    bw.code(dc[0], 5)  # distance symbol 0 -> distance 1
    bw.code(lc[256], lit[256])
    return bw.finish(), b'X' * 259


def local_header(name, payload, data):
    crc = zlib.crc32(data) & 0xFFFFFFFF
    # version, flags, method, mtime, mdate, crc, csize, usize, name, extra
    return struct.pack('<IHHHHHIIIHH', 0x04034B50, 20, 0, 9,
                       0x5224, 0x21, crc,
                       len(payload), len(data), len(name), 0) + name


def central_header(name, payload, data, offset):
    crc = zlib.crc32(data) & 0xFFFFFFFF
    # sig, ver-made, ver-needed, flags, method, mtime, mdate, crc, ...
    return struct.pack('<IHHHHHHIIIHHHHHII', 0x02014B50, 20, 20, 0, 9,
                       0x5224, 0x21, crc, len(payload), len(data), len(name),
                       0, 0, 0, 0, 0, offset) + name


def main():
    entries = []

    data1 = b'Hello, Deflate64!' + bytes([10])
    entries.append((b'stored.txt', stored_block(data1, True), data1))

    # Two stored blocks in one stream: a non-final block followed by a
    # final block, proving decoders reset their bit alignment at each block
    # boundary and keep streaming.
    data1a = b'first chunk\n'
    data1b = b'second chunk\n'
    payload_multi = stored_block(data1a, False) + stored_block(data1b, True)
    entries.append((b'stored_multi.txt', payload_multi, data1a + data1b))

    # Fixed Huffman block with short literals and back-references only
    # (length codes below 285, which are identical to ordinary deflate).
    seed = b'abcdefgh'
    # Use only base lengths and the four extra-bit-free distances (1-4).
    chunks2 = [
        (seed, 0),
        (b'gha', 2),      # length 3 (code 257), distance 2
        (b'ghgh', 2),     # length 4 (code 258), distance 2
        (b'hghgh', 2),    # length 5 (code 259), distance 2
        (b'Z', 0),
        (b'ZZZ', 1),     # overlapping distance-1 copy, length 3
    ]
    data2 = simulate(chunks2)
    entries.append((b'fixed_long.txt', fixed_stream(chunks2), data2))

    window = bytes((i * 73 + 17) & 0xFF for i in range(65536))
    data3 = window + window[:3]
    # Dynamic block with the full 32-code distance alphabet so that
    # distance symbol 31 (distance 65536, 14 extra bits) is available.
    payload3 = dynamic_window_block(window)
    entries.append((
        b'fixed_window.txt',
        payload3,
        data3,
    ))

    # Hand-built dynamic Huffman block: literals 'A','B', then a length-3
    # match at distance 2 producing ABABAB.
    payload4, data4 = dynamic_stream()
    entries.append((b'dynamic.txt', payload4, data4))

    # Dynamic Huffman block exercising the Deflate64-only length code 285
    # (16 extra bits -> a 258-byte match) with a distance-1 overlap.
    payload5, data5 = dynamic_285_stream()
    entries.append((b'dynamic_285.txt', payload5, data5))

    output = bytearray()
    central = bytearray()
    for name, payload, data in entries:
        offset = len(output)
        output += local_header(name, payload, data)
        output += payload
        central += central_header(name, payload, data, offset)
    eocd = struct.pack('<IHHHHIIH', 0x06054B50, 0, 0, len(entries),
                       len(entries), len(central), len(output), 0)
    with open('test/data/zipWithDeflate64Compression.zip', 'wb') as f:
        f.write(bytes(output) + bytes(central) + eocd)

    for name, payload, data in entries:
        print(name.decode(), len(payload), len(data))


if __name__ == '__main__':
    main()
