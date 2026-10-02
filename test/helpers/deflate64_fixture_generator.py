#!/usr/bin/env python3
"""Generate the static Deflate64 test fixtures under test/data/.

This is a small, independent, standard-library-only Deflate64 (ZIP
compression method 9) *compressor*. It exists so that the Ruby decoder
tests do not depend on the code under test: the fixtures it writes are
static files that the test suite simply reads.

It is not run by the test suite. Run it by hand from the repository root
if the fixtures ever need regenerating:

    python3 test/helpers/deflate64_fixture_generator.py

It writes:

    test/data/deflate64.zip  - archive with a Deflate64 entry (dynamic,
                               stored and fixed blocks, > 32 KiB distances,
                               > 258 byte matches) and a stored entry
    test/data/deflate64.txt  - the expected content of the Deflate64 entry
"""

import random
import struct
import zlib
from pathlib import Path

# Deflate64 length codes 257-285: base value and extra bit count. Code 285
# encodes a length of 3 plus 16 extra bits (unlike Deflate's fixed 258).
LENGTH_BASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
               35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 3]
LENGTH_EXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
                3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 16]

# Deflate64 has 32 distance codes; codes 30 and 31 carry 14 extra bits,
# allowing distances of up to 65536.
DIST_BASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
             257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
             8193, 12289, 16385, 24577, 32769, 49153]
DIST_EXTRA = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
              7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14]

CODE_LENGTH_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]

WINDOW_SIZE = 65536
MAX_MATCH = 65538


class BitWriter:
    """Packs bits LSB-first, as Deflate requires."""

    def __init__(self):
        self.data = bytearray()
        self.acc = 0
        self.nbits = 0

    def write_bits(self, value, count):
        self.acc |= value << self.nbits
        self.nbits += count
        while self.nbits >= 8:
            self.data.append(self.acc & 0xFF)
            self.acc >>= 8
            self.nbits -= 8

    def write_code(self, code, count):
        """Writes a Huffman code, most significant bit first."""
        for i in range(count - 1, -1, -1):
            self.write_bits((code >> i) & 1, 1)

    def align_to_byte(self):
        if self.nbits:
            self.write_bits(0, 8 - self.nbits)

    def result(self):
        if self.nbits:
            self.write_bits(0, 8 - self.nbits)
        return bytes(self.data)


def fixed_litlen_code(symbol):
    if symbol < 144:
        return 0x30 + symbol, 8
    if symbol < 256:
        return 0x190 + symbol - 144, 9
    if symbol < 280:
        return symbol - 256, 7
    return 0xC0 + symbol - 280, 8


def length_symbol(length):
    if length > 258:
        assert length <= MAX_MATCH
        return 285, length - 3, 16
    for i in range(27, -1, -1):
        if LENGTH_BASE[i] <= length:
            assert length < LENGTH_BASE[i] + (1 << LENGTH_EXTRA[i])
            return 257 + i, length - LENGTH_BASE[i], LENGTH_EXTRA[i]
    raise AssertionError("unreachable")


def distance_symbol(distance):
    assert 1 <= distance <= WINDOW_SIZE
    for i in range(31, -1, -1):
        if DIST_BASE[i] <= distance:
            assert distance < DIST_BASE[i] + (1 << DIST_EXTRA[i])
            return i, distance - DIST_BASE[i], DIST_EXTRA[i]
    raise AssertionError("unreachable")


def lz77(data, emit_start=0):
    """A simple greedy hash-chain matcher.

    Returns a list of ('lit', byte) / ('match', length, distance) tokens
    covering data[emit_start:]. Positions before emit_start only seed the
    matcher's history, so tokens may reference back across that boundary.
    """
    tokens = []
    head = {}
    i = 0
    n = len(data)
    while i < n:
        best_len = 0
        best_dist = 0
        if i + 3 <= n:
            for j in reversed(head.get(data[i:i + 3], [])[-64:]):
                dist = i - j
                if dist > WINDOW_SIZE:
                    break
                length = 0
                max_len = min(MAX_MATCH, n - i)
                while length < max_len and data[j + length] == data[i + length]:
                    length += 1
                if length > best_len:
                    best_len, best_dist = length, dist
                    if length >= max_len:
                        break
        if i >= emit_start:
            if best_len >= 3:
                tokens.append(('match', best_len, best_dist))
            else:
                tokens.append(('lit', data[i]))
        step = best_len if best_len >= 3 else 1
        for k in range(i, min(i + step, n - 2)):
            head.setdefault(data[k:k + 3], []).append(k)
        i += step
    return tokens


def huffman_lengths(freqs, maxbits):
    """Code lengths for the given symbol frequencies (a package-merge-free
    plain Huffman; fine here because our alphabets and data are small)."""
    import heapq
    lengths = [0] * len(freqs)
    syms = [i for i, f in enumerate(freqs) if f > 0]
    if not syms:
        return lengths
    if len(syms) == 1:
        lengths[syms[0]] = 1
        return lengths
    heap = [(freqs[s], s, [s]) for s in syms]
    heapq.heapify(heap)
    depth = {s: 0 for s in syms}
    tiebreak = len(freqs)
    while len(heap) > 1:
        f1, _, s1 = heapq.heappop(heap)
        f2, _, s2 = heapq.heappop(heap)
        for s in s1 + s2:
            depth[s] += 1
        heapq.heappush(heap, (f1 + f2, tiebreak, s1 + s2))
        tiebreak += 1
    for s in syms:
        assert depth[s] <= maxbits, "huffman code deeper than allowed"
        lengths[s] = depth[s]
    return lengths


def canonical_codes(lengths):
    """Assign canonical Huffman codes per RFC 1951 3.2.2."""
    count = {}
    for length in lengths:
        if length:
            count[length] = count.get(length, 0) + 1
    code = 0
    next_code = {}
    for bits in range(1, max(count or {0: 0}) + 1):
        code = (code + count.get(bits - 1, 0)) << 1
        next_code[bits] = code
    codes = {}
    for symbol, length in enumerate(lengths):
        if length:
            codes[symbol] = (next_code[length], length)
            next_code[length] += 1
    return codes


def rle_code_lengths(lengths):
    """Encode a code length sequence with symbols 0-18."""
    out = []
    i = 0
    n = len(lengths)
    while i < n:
        j = i
        if lengths[i] == 0:
            while j < n and lengths[j] == 0:
                j += 1
            run = j - i
            while run >= 11:
                take = min(run, 138)
                out.append((18, take - 11, 7))
                run -= take
            if run >= 3:
                out.append((17, run - 3, 3))
                run = 0
            out.extend([(0, 0, 0)] * run)
        else:
            out.append((lengths[i], 0, 0))
            j = i + 1
            while j < n and lengths[j] == lengths[i]:
                j += 1
            run = j - i - 1
            while run >= 3:
                take = min(run, 6)
                out.append((16, take - 3, 2))
                run -= take
            out.extend([(lengths[i], 0, 0)] * run)
        i = j
    return out


def emit_match(bw, litlen_codes, dist_codes, length, distance):
    symbol, extra, ebits = length_symbol(length)
    bw.write_code(*litlen_codes[symbol])
    if ebits:
        bw.write_bits(extra, ebits)
    dsymbol, dextra, debits = distance_symbol(distance)
    bw.write_code(*dist_codes[dsymbol])
    if debits:
        bw.write_bits(dextra, debits)


def emit_fixed_block(bw, tokens, final):
    bw.write_bits(1 if final else 0, 1)
    bw.write_bits(1, 2)
    for token in tokens:
        if token[0] == 'lit':
            bw.write_code(*fixed_litlen_code(token[1]))
        else:
            emit_match(bw,
                       {s: fixed_litlen_code(s) for s in range(288)},
                       {s: (s, 5) for s in range(32)},
                       token[1], token[2])
    bw.write_code(*fixed_litlen_code(256))


def emit_stored_block(bw, data, final):
    bw.write_bits(1 if final else 0, 1)
    bw.write_bits(0, 2)
    bw.align_to_byte()
    assert len(data) <= 0xFFFF
    bw.write_bits(len(data), 16)
    bw.write_bits(~len(data) & 0xFFFF, 16)
    for byte in data:
        bw.write_bits(byte, 8)


def emit_dynamic_block(bw, tokens, final):
    litlen_freq = [0] * 288
    dist_freq = [0] * 32
    for token in tokens:
        if token[0] == 'lit':
            litlen_freq[token[1]] += 1
        else:
            litlen_freq[length_symbol(token[1])[0]] += 1
            dist_freq[distance_symbol(token[2])[0]] += 1
    litlen_freq[256] += 1

    litlen_lengths = huffman_lengths(litlen_freq, 15)
    dist_lengths = huffman_lengths(dist_freq, 15)
    hlit = max(257, max(i for i, l in enumerate(litlen_lengths) if l) + 1)
    hdist = max(1, max((i for i, l in enumerate(dist_lengths) if l), default=-1) + 1)
    litlen_lengths = litlen_lengths[:hlit]
    dist_lengths = dist_lengths[:hdist]

    rle = rle_code_lengths(litlen_lengths + dist_lengths)
    cl_freq = [0] * 19
    for symbol, _, _ in rle:
        cl_freq[symbol] += 1
    cl_lengths = huffman_lengths(cl_freq, 7)
    hclen = 19
    while hclen > 4 and cl_lengths[CODE_LENGTH_ORDER[hclen - 1]] == 0:
        hclen -= 1

    litlen_codes = canonical_codes(litlen_lengths)
    dist_codes = canonical_codes(dist_lengths)
    cl_codes = canonical_codes(cl_lengths)

    bw.write_bits(1 if final else 0, 1)
    bw.write_bits(2, 2)
    bw.write_bits(hlit - 257, 5)
    bw.write_bits(hdist - 1, 5)
    bw.write_bits(hclen - 4, 4)
    for symbol in CODE_LENGTH_ORDER[:hclen]:
        bw.write_bits(cl_lengths[symbol], 3)
    for symbol, extra, ebits in rle:
        bw.write_code(*cl_codes[symbol])
        if ebits:
            bw.write_bits(extra, ebits)
    for token in tokens:
        if token[0] == 'lit':
            bw.write_code(*litlen_codes[token[1]])
        else:
            emit_match(bw, litlen_codes, dist_codes, token[1], token[2])
    bw.write_code(*litlen_codes[256])


def deflate64_compress(part1, part2, part3):
    """Compress as: dynamic block (part1), stored block (part2), final
    fixed block (part3). Matches in part3 reach back across the stored
    block into part1."""
    data = part1 + part2 + part3
    tokens1 = lz77(part1)
    tokens3 = lz77(data, emit_start=len(part1) + len(part2))
    bw = BitWriter()
    emit_dynamic_block(bw, tokens1, final=False)
    emit_stored_block(bw, part2, final=False)
    emit_fixed_block(bw, tokens3, final=True)
    return bw.result(), data


def make_zip(entries):
    """Build a minimal zip archive. entries: (name, method, compressed,
    crc, size)."""
    out = bytearray()
    central = bytearray()
    dos_time = 12 << 11                 # 12:00:00
    dos_date = (46 << 9) | (1 << 5) | 1  # 2026-01-01
    for name, method, cdata, crc, size in entries:
        name = name.encode('utf-8')
        offset = len(out)
        out += struct.pack('<IHHHHHIIIHH', 0x04034B50, 20, 0, method,
                           dos_time, dos_date, crc, len(cdata), size,
                           len(name), 0)
        out += name
        out += cdata
        central += struct.pack('<IHHHHHHIIIHHHHHII', 0x02014B50, 20, 20, 0,
                               method, dos_time, dos_date, crc, len(cdata),
                               size, len(name), 0, 0, 0, 0, 0, offset)
        central += name
    out += central
    out += struct.pack('<IHHHHIIH', 0x06054B50, 0, 0, len(entries),
                       len(entries), len(central),
                       len(out) - len(central), 0)
    return bytes(out)


def build_fixture_data():
    rng = random.Random(20261001)
    part1 = b''.join(
        b'deflate64 fixture line %03d: the quick brown fox jumps over the lazy dog\n' % i
        for i in range(32))
    gap = b''.join(b'filler record %05d: abcdefghij abcdefghij abcdefghij\n' % i
                   for i in range(1100))
    part2 = bytes(rng.randrange(256) for _ in range(1000))
    part3 = part1 * 3
    return part1, gap, part2, part3


def main():
    root = Path(__file__).resolve().parent.parent.parent
    part1, gap, part2, part3 = build_fixture_data()
    compressed, data = deflate64_compress(part1 + gap, part2, part3)

    stored_content = b'a stored entry in a mixed-method archive\n'
    entries = [
        ('deflate64.txt', 9, compressed, zlib.crc32(data), len(data)),
        ('stored.txt', 0, stored_content, zlib.crc32(stored_content),
         len(stored_content)),
    ]
    # A raw Deflate64 stream of file1.txt, used by the shared decompressor
    # tests (test/helpers/decompressor_tests.rb).
    file1 = (root / 'test' / 'data' / 'file1.txt').read_bytes()
    bw = BitWriter()
    emit_dynamic_block(bw, lz77(file1), final=True)
    (root / 'test' / 'data' / 'file1.txt.deflate64Data').write_bytes(bw.result())

    zip_path = root / 'test' / 'data' / 'deflate64.zip'
    txt_path = root / 'test' / 'data' / 'deflate64.txt'
    zip_path.write_bytes(make_zip(entries))
    txt_path.write_bytes(data)
    print('wrote %s (%d bytes)' % (zip_path, zip_path.stat().st_size))
    print('wrote %s (%d bytes)' % (txt_path, txt_path.stat().st_size))
    print('deflate64 stream: %d bytes -> %d bytes' % (len(data), len(compressed)))


if __name__ == '__main__':
    main()
