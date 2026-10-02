# frozen_string_literal: true

require_relative 'test_helper'
require_relative 'helpers/decompressor_tests'

class Deflate64Test < Minitest::Test
  include DecompressorTests

  # Packs bits LSB-first, as Deflate requires. +write_bits+ writes a value
  # least-significant bit first (used for extra bits and block headers);
  # +write_code+ writes a Huffman code most-significant bit first.
  class BitWriter
    def initialize
      @data = +''.b
      @accumulator = 0
      @bits = 0
    end

    def write_bits(value, count)
      @accumulator |= value << @bits
      @bits += count
      while @bits >= 8
        @data << (@accumulator & 0xFF)
        @accumulator >>= 8
        @bits -= 8
      end
      self
    end

    def write_code(code, count)
      (count - 1).downto(0) { |i| write_bits((code >> i) & 1, 1) }
      self
    end

    def align_to_byte
      write_bits(0, (8 - @bits % 8) % 8)
    end

    def to_s
      data = @data.dup
      data << (@accumulator & 0xFF) if @bits.positive?
      data
    end
  end

  def setup
    super
    @file = File.new('test/data/file1.txt.deflate64Data', 'rb')
    @decompressor = ::Zip::Deflate64.new(@file)
  end

  def teardown
    @file.close
  end

  def test_registered_for_compression_method_9
    assert_equal(::Zip::Deflate64,
                 ::Zip::Decompressor.find_by_compression_method(::Zip::COMPRESSION_METHOD_DEFLATE_64))
  end

  def test_stored_block
    writer = BitWriter.new
    writer.write_bits(1, 1).write_bits(0, 2).align_to_byte # final, stored
    writer.write_bits(5, 16).write_bits(~5 & 0xFFFF, 16)
    'hello'.bytes.each { |byte| writer.write_bits(byte, 8) }

    assert_equal('hello', inflate(writer.to_s))
  end

  def test_fixed_huffman_literals
    writer = fixed_block_writer
    writer.write_code(0x30 + 72, 8) # 'H'
    writer.write_code(0x30 + 105, 8) # 'i'
    writer.write_code(0, 7) # end of block

    assert_equal('Hi', inflate(writer.to_s))
  end

  def test_fixed_huffman_match
    writer = fixed_block_writer
    'abc'.bytes.each { |byte| writer.write_code(0x30 + byte, 8) }
    writer.write_code(1, 7) # length code 257: length 3
    writer.write_code(2, 5) # distance code 2: distance 3
    writer.write_code(0, 7) # end of block

    assert_equal('abcabc', inflate(writer.to_s))
  end

  def test_overlapping_match
    writer = fixed_block_writer
    writer.write_code(0x30 + 97, 8) # 'a'
    writer.write_code(3, 7) # length code 259: length 5
    writer.write_code(0, 5) # distance code 0: distance 1
    writer.write_code(0, 7) # end of block

    assert_equal('aaaaaa', inflate(writer.to_s))
  end

  def test_long_match_length
    # Length code 285 carries 16 extra bits in Deflate64: length 3 + extra.
    writer = fixed_block_writer
    writer.write_code(0x30 + 120, 8) # 'x'
    writer.write_code(0xC5, 8) # length code 285
    writer.write_bits(297, 16) # length 300
    writer.write_code(0, 5) # distance 1
    writer.write_code(0, 7) # end of block

    assert_equal('x' * 301, inflate(writer.to_s))
  end

  def test_maximum_distance
    # 64 KiB of history, then a match at the maximum distance of 65,536
    # (distance code 31, which does not exist in plain Deflate).
    writer = fixed_block_writer
    65_536.times { writer.write_code(0x30 + 65, 8) } # 'A'
    writer.write_code(1, 7) # length code 257: length 3
    writer.write_code(31, 5) # distance code 31
    writer.write_bits(65_536 - 49_153, 14) # distance 65,536
    writer.write_code(0, 7) # end of block

    assert_equal('A' * 65_539, inflate(writer.to_s))
  end

  def test_dynamic_huffman_block
    # Literal/length code: 'A' -> 1 bit, 256 -> 2 bits, 257 -> 2 bits.
    # Distance code: a single 1-bit code (distance 1).
    writer = BitWriter.new
    writer.write_bits(1, 1).write_bits(2, 2) # final, dynamic
    writer.write_bits(1, 5) # HLIT = 258
    writer.write_bits(0, 5) # HDIST = 1
    writer.write_bits(14, 4) # HCLEN = 18
    # Code length code lengths, in the order 16,17,18,0,...,2,14,1:
    # symbol 18 -> 1 bit, symbols 1 and 2 -> 2 bits.
    [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 2].each { |l| writer.write_bits(l, 3) }
    writer.write_code(0, 1).write_bits(54, 7) # 65 zeros
    writer.write_code(2, 2) # symbol 65: length 1
    writer.write_code(0, 1).write_bits(127, 7) # 138 zeros
    writer.write_code(0, 1).write_bits(41, 7) # 52 zeros
    writer.write_code(3, 2) # symbol 256: length 2
    writer.write_code(3, 2) # symbol 257: length 2
    writer.write_code(2, 2) # distance symbol 0: length 1
    3.times { writer.write_code(0, 1) } # 'A'
    writer.write_code(3, 2) # length code 257: length 3
    writer.write_code(0, 1) # distance 1
    writer.write_code(2, 2) # end of block

    assert_equal('AAAAAA', inflate(writer.to_s))
  end

  def test_dynamic_block_without_distance_codes
    # A single zero-length distance code means "no distance codes used";
    # this is valid as long as no match occurs.
    writer = BitWriter.new
    writer.write_bits(1, 1).write_bits(2, 2) # final, dynamic
    writer.write_bits(0, 5) # HLIT = 257
    writer.write_bits(0, 5) # HDIST = 1
    writer.write_bits(14, 4) # HCLEN = 18
    # Code length code: symbol 18 -> 1 bit, symbols 0 and 1 -> 2 bits.
    [0, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2].each { |l| writer.write_bits(l, 3) }
    writer.write_code(0, 1).write_bits(54, 7) # 65 zeros
    writer.write_code(3, 2) # symbol 65: length 1
    writer.write_code(0, 1).write_bits(127, 7) # 138 zeros
    writer.write_code(0, 1).write_bits(41, 7) # 52 zeros
    writer.write_code(3, 2) # symbol 256: length 1
    writer.write_code(2, 2) # distance symbol 0: length 0 (no distance codes)
    writer.write_code(0, 1) # 'A'
    writer.write_code(0, 1) # 'A'
    writer.write_code(1, 1) # end of block

    assert_equal('AA', inflate(writer.to_s))
  end

  def test_match_with_no_distance_codes_raises
    # As above, but the block data contains a match.
    writer = BitWriter.new
    writer.write_bits(1, 1).write_bits(2, 2) # final, dynamic
    writer.write_bits(1, 5) # HLIT = 258
    writer.write_bits(0, 5) # HDIST = 1
    writer.write_bits(14, 4) # HCLEN = 18
    # Code length code: symbols 0, 1, 2 and 18 all 2 bits.
    [0, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 2].each { |l| writer.write_bits(l, 3) }
    writer.write_code(3, 2).write_bits(54, 7) # 65 zeros
    writer.write_code(1, 2) # symbol 65: length 1
    writer.write_code(3, 2).write_bits(127, 7) # 138 zeros
    writer.write_code(3, 2).write_bits(41, 7) # 52 zeros
    writer.write_code(2, 2) # symbol 256: length 2
    writer.write_code(2, 2) # symbol 257: length 2
    writer.write_code(0, 2) # distance symbol 0: length 0 (no distance codes)
    writer.write_code(0, 1) # 'A'
    writer.write_code(3, 2) # length code 257: length 3, needs a distance code

    assert_raises(::Zip::DecompressionError) { inflate(writer.to_s) }
  end

  def test_multiple_block_types_in_one_stream
    writer = BitWriter.new
    writer.write_bits(0, 1).write_bits(0, 2).align_to_byte # not final, stored
    writer.write_bits(3, 16).write_bits(~3 & 0xFFFF, 16)
    'abc'.bytes.each { |byte| writer.write_bits(byte, 8) }
    writer.write_bits(1, 1).write_bits(1, 2) # final, fixed Huffman
    writer.write_code(0x30 + 100, 8) # 'd'
    writer.write_code(0x30 + 101, 8) # 'e'
    writer.write_code(1, 7) # length code 257: length 3
    writer.write_code(4, 5).write_bits(0, 1) # distance code 4: distance 5
    writer.write_code(0, 7) # end of block

    assert_equal('abcdeabc', inflate(writer.to_s))
  end

  def test_read_in_chunks_spanning_matches
    writer = fixed_block_writer
    'abcdefgh'.bytes.each { |byte| writer.write_code(0x30 + byte, 8) }
    writer.write_code(6, 7) # length code 262: length 8
    writer.write_code(5, 5).write_bits(1, 2) # distance code 5: distance 8
    writer.write_code(0, 7) # end of block

    decompressor = ::Zip::Deflate64.new(StringIO.new(writer.to_s))
    output = +''.b
    while (chunk = decompressor.read(3))
      output << chunk
    end
    assert_equal('abcdefghabcdefgh', output)
    assert_nil(decompressor.read(3))
  end

  def test_truncated_stream_raises
    assert_raises(::Zip::DecompressionError) { inflate(''.b) }

    writer = fixed_block_writer
    writer.write_code(0x30 + 97, 8) # 'a', then the stream stops
    assert_raises(::Zip::DecompressionError) { inflate(writer.to_s) }
  end

  def test_truncated_stored_block_raises
    writer = BitWriter.new
    writer.write_bits(1, 1).write_bits(0, 2).align_to_byte # final, stored
    writer.write_bits(10, 16).write_bits(~10 & 0xFFFF, 16)
    writer.write_bits(65, 8) # only one of the ten promised bytes

    assert_raises(::Zip::DecompressionError) { inflate(writer.to_s) }
  end

  def test_invalid_block_type_raises
    writer = BitWriter.new
    writer.write_bits(1, 1).write_bits(3, 2) # block type 3 is reserved

    assert_raises(::Zip::DecompressionError) { inflate(writer.to_s) }
  end

  def test_stored_block_length_mismatch_raises
    writer = BitWriter.new
    writer.write_bits(1, 1).write_bits(0, 2).align_to_byte # final, stored
    writer.write_bits(5, 16).write_bits(5, 16) # NLEN should be ~LEN

    assert_raises(::Zip::DecompressionError) { inflate(writer.to_s) }
  end

  def test_match_distance_too_far_back_raises
    writer = fixed_block_writer
    writer.write_code(0x30 + 97, 8) # 'a'
    writer.write_code(1, 7) # length code 257: length 3
    writer.write_code(1, 5) # distance 2, but only one byte of history
    writer.write_code(0, 7) # end of block

    assert_raises(::Zip::DecompressionError) { inflate(writer.to_s) }
  end

  def test_invalid_literal_length_code_raises
    writer = fixed_block_writer
    writer.write_code(0xC6, 8) # literal/length code 286 is not used

    assert_raises(::Zip::DecompressionError) { inflate(writer.to_s) }
  end

  def test_oversubscribed_code_lengths_raise
    writer = BitWriter.new
    writer.write_bits(1, 1).write_bits(2, 2) # final, dynamic
    writer.write_bits(0, 5).write_bits(0, 5).write_bits(0, 4) # HCLEN = 4
    # Three 1-bit code length codes over-subscribe the code.
    [1, 1, 1, 0].each { |length| writer.write_bits(length, 3) }

    assert_raises(::Zip::DecompressionError) { inflate(writer.to_s) }
  end

  def test_incomplete_code_lengths_raise
    writer = BitWriter.new
    writer.write_bits(1, 1).write_bits(2, 2) # final, dynamic
    writer.write_bits(0, 5).write_bits(0, 5).write_bits(0, 4) # HCLEN = 4
    # A single 3-bit code length code is incomplete.
    [0, 0, 0, 3].each { |length| writer.write_bits(length, 3) }

    assert_raises(::Zip::DecompressionError) { inflate(writer.to_s) }
  end

  def test_zip_file_fixture
    # test/data/deflate64.zip is generated by the independent
    # test/helpers/deflate64_fixture_generator.py.
    expected = File.binread('test/data/deflate64.txt')
    ::Zip::File.open('test/data/deflate64.zip') do |zip|
      entry = zip.find_entry('deflate64.txt')
      assert_equal(::Zip::COMPRESSION_METHOD_DEFLATE_64, entry.compression_method)
      assert_equal(expected.bytesize, entry.size)
      assert_equal(expected, zip.read(entry))
      assert_equal("a stored entry in a mixed-method archive
", zip.read('stored.txt'))
    end
  end

  def test_input_stream_fixture_reads_in_chunks
    expected = File.binread('test/data/deflate64.txt')
    ::Zip::InputStream.open('test/data/deflate64.zip') do |stream|
      assert_equal('deflate64.txt', stream.get_next_entry.name)
      output = +''.b
      while (chunk = stream.read(1000))
        output << chunk
      end
      assert_equal(expected, output)

      assert_equal('stored.txt', stream.get_next_entry.name)
      assert_equal("a stored entry in a mixed-method archive
", stream.read)
    end
  end

  private

  def fixed_block_writer
    BitWriter.new.write_bits(1, 1).write_bits(1, 2) # final, fixed Huffman
  end

  def inflate(data)
    ::Zip::Deflate64.new(StringIO.new(data)).read
  end
end
