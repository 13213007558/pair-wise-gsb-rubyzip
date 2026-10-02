# frozen_string_literal: true

require_relative 'test_helper'
require 'stringio'

class Deflate64DecompressorTest < Minitest::Test
  # Small, hand-checked LSB-first bit streams. Bytes are listed as binary
  # strings so the exact Huffman coding is visible at a glance.

  def test_stored_block
    data = 'Hello, Deflate64!'
    payload = [1, data.bytesize, data.bytesize ^ 0xFFFF].pack('Cvv') + data
    assert_decode(data, payload)
  end

  def test_non_final_block_followed_by_final_block
    first = 'part one|'
    second = 'part two'
    payload =
      stored_block(first, final: false) + stored_block(second, final: true)
    assert_decode(first + second, payload)
  end

  def test_fixed_huffman_literals_and_match
    # Fixed block: literal 'A', length 3 / distance 1 -> "AAAA".
    # bfinal=1 btype=01, then the fixed code for 'A' (10010001 MSB, sent
    # LSB first), length symbol 257 (0000001), 5 zero distance bits, EOB.
    payload = ['73040200'].pack('H*')
    assert_decode('AAAA', payload)
  end

  def test_overlapping_distance_one_copy
    # 'X' followed by length 3 at distance 1 gives XXXX.
    bw = BitStreamBuilder.fixed
    bw.literal('X'.ord)
    bw.match(257, 0, 0, 0)
    bw.eob
    assert_decode('XXXX', bw.bytes)
  end

  def test_reading_in_small_chunks_keeps_back_references_intact
    data = 'Hello, Deflate64!'
    payload = [1, data.bytesize, data.bytesize ^ 0xFFFF].pack('Cvv') + data
    io = StringIO.new(payload)
    original_chunk_size = Zip.inflater_chunk_size
    Zip.inflater_chunk_size = 1
    decompressor = Zip::Deflate64Decompressor.new(io)
    chunks = []
    while (chunk = decompressor.read(3))
      chunks << chunk
    end
    assert_equal(data, chunks.join)
  ensure
    Zip.inflater_chunk_size = original_chunk_size
  end

  def test_back_reference_can_span_several_read_calls
    # Fixed block: literal Q then a length-11 distance-1 overlap, read two
    # bytes at a time so the match spans many read calls and chunk buffers.
    bw = BitStreamBuilder.fixed
    bw.literal('Q'.ord)
    bw.match(265, 0, 1, 0)
    bw.eob
    decompressor = Zip::Deflate64Decompressor.new(StringIO.new(bw.bytes))
    chunks = []
    while (chunk = decompressor.read(2))
      chunks << chunk
    end
    assert_equal('Q' * 12, chunks.join)
  end

  def test_eof_reports_when_stream_ends
    payload = [1, 1, 1 ^ 0xFFFF].pack('Cvv') + 'A'
    decompressor = Zip::Deflate64Decompressor.new(StringIO.new(payload))
    refute(decompressor.eof?)
    assert_equal('A', decompressor.read)
    assert(decompressor.eof?)
    assert_empty(decompressor.read)
  end

  def test_truncated_stream_raises
    # Stored block header claims 10 bytes but only two follow.
    payload = [1, 10, 10 ^ 0xFFFF].pack('Cvv') + 'ab'
    error = assert_raises(Zip::DecompressionError) do
      Zip::Deflate64Decompressor.new(StringIO.new(payload)).read
    end
    assert_match(/unexpected end/i, error.message)
  end

  def test_truncated_dynamic_header_raises
    # bfinal=1 btype=2, then the header is cut short.
    payload = ['0dff'].pack('H*')
    error = assert_raises(Zip::DecompressionError) do
      Zip::Deflate64Decompressor.new(StringIO.new(payload)).read
    end
    assert_match(/unexpected end/i, error.message)
  end

  def test_back_reference_farther_than_window_raises
    # Fixed block: literal 'A', length 3 at distance 5 (only 1 byte of
    # history) -> invalid, must raise rather than emit zeros. Distance
    # symbol 4 has base 5 and one extra bit.
    bw = BitStreamBuilder.fixed
    bw.literal('A'.ord)
    bw.match(257, 0, 0, 4)
    bw.raw_bits(0, 1)
    bw.eob
    error = assert_raises(Zip::DecompressionError) do
      Zip::Deflate64Decompressor.new(StringIO.new(bw.bytes)).read
    end
    assert_match(/distance 5/i, error.message)
  end

  def test_invalid_block_type_raises
    # bfinal=1, btype=3 (reserved).
    payload = ['07'].pack('H*')
    error = assert_raises(Zip::DecompressionError) do
      Zip::Deflate64Decompressor.new(StringIO.new(payload)).read
    end
    assert_match(/block type 3/i, error.message)
  end

  def test_stored_block_with_bad_length_complement_raises
    payload = [1, 5, 0].pack('Cvv') # NLEN should be 0xfffa
    error = assert_raises(Zip::DecompressionError) do
      Zip::Deflate64Decompressor.new(StringIO.new(payload)).read
    end
    assert_match(/LEN\/NLEN/i, error.message)
  end

  def test_oversubscribed_huffman_table_raises
    # Three 1-bit codes cannot coexist (Kraft sum 1.5 > 1).
    assert_raises(Zip::Deflate64::HuffmanTable::InvalidCodeLengthsError) do
      Zip::Deflate64::HuffmanTable.new([1, 1, 1])
    end
  end

  def test_malformed_code_length_table_raises
    # Incomplete code-length alphabet (only one 1-bit code defined).
    payload = ['05000200'].pack('H*')
    error = assert_raises(Zip::DecompressionError) do
      Zip::Deflate64Decompressor.new(StringIO.new(payload)).read
    end
    refute_empty(error.message)
  end

  def test_code_length_repeat_without_previous_value_raises
    # Dynamic block whose first alphabet symbol is code-length repeat 16,
    # which is illegal before any concrete code length has been emitted.
    payload = File.binread('test/data/deflate64_repeat16.bin')
    error = assert_raises(Zip::DecompressionError) do
      Zip::Deflate64Decompressor.new(StringIO.new(payload)).read
    end
    assert_match(/no preceding value/i, error.message)
  end

  def test_dynamic_distance_farther_than_history_raises
    # Complete dynamic block; one literal, length 3, distance symbol 3
    # (distance 4) with only one history byte available.
    payload = File.binread('test/data/deflate64_distance_too_far.bin')
    error = assert_raises(Zip::DecompressionError) do
      Zip::Deflate64Decompressor.new(StringIO.new(payload)).read
    end
    assert_match(/distance 4/i, error.message)
  end

  def test_dynamic_distance_code_31_beyond_small_window_raises
    # One literal, length 3, dynamic distance symbol 31 with max extra
    # (would need 65536 bytes of history, but only one byte exists).
    payload = File.binread('test/data/deflate64_beyond64k.bin')
    error = assert_raises(Zip::DecompressionError) do
      Zip::Deflate64Decompressor.new(StringIO.new(payload)).read
    end
    assert_match(/65536/i, error.message)
  end

  private

  def stored_block(data, final:)
    [final ? 1 : 0, data.bytesize, data.bytesize ^ 0xFFFF].pack('Cvv') + data
  end

  def assert_decode(expected, payload)
    decompressor = Zip::Deflate64Decompressor.new(StringIO.new(payload))
    assert_equal(expected, decompressor.read)
    assert(decompressor.eof?)
  end

  # Builds fixed-Huffman Deflate64 blocks. Codes are written MSB first
  # into an LSB-first bit buffer, which matches the on-wire format.
  class BitStreamBuilder
    def self.fixed
      new
    end

    def initialize
      @buffer = +''.b
      @byte = 0
      @bits = 0
      write_header
    end

    def literal(symbol)
      if symbol <= 143
        code(0b00110000 + symbol, 8)
      else
        raise ArgumentError, 'unsupported literal in test helper'
      end
    end

    def match(length_symbol, extra, extra_bits, distance_code)
      # Length symbols 257-279 use 7-bit fixed codes.
      code(length_symbol - 256, 7)
      raw_bits(extra, extra_bits) if extra_bits.positive?
      code(distance_code, 5)
    end

    def raw_bits(value, count)
      count.times { |i| emit((value >> i) & 1) }
    end

    def eob
      code(0, 7) # symbol 256 fixed code
      flush
    end

    def distance_code(symbol)
      code(symbol, 5)
    end

    def bytes
      @buffer.dup
    end

    def code(value, length)
      length.times { |i| emit((value >> (length - 1 - i)) & 1) }
    end

    private

    def write_header
      emit(1) # bfinal
      emit(1) # btype bit 0
      emit(0) # btype bit 1 -> 01 (fixed)
    end

    def emit(bit)
      @byte |= bit << @bits
      @bits += 1
      return unless @bits == 8

      @buffer << @byte
      @byte = 0
      @bits = 0
    end

    def flush
      return if @bits.zero?

      @buffer << @byte
      @byte = 0
      @bits = 0
    end

  end
end
