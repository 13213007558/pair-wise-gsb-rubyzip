# frozen_string_literal: true

module Zip
  # A pure-Ruby decompressor for Deflate64 (ZIP compression method 9).
  #
  # Deflate64 is PKWARE's extension of Deflate (RFC 1951) with a 64 KiB
  # history window, longer matches (up to 65,538 bytes) and two extra
  # distance codes, allowing distances of up to 65,536 bytes. Only
  # decompression is supported; rubyzip cannot write Deflate64 entries.
  class Deflate64 < Decompressor # :nodoc:all
    WINDOW_SIZE   = 65_536
    MAX_CODE_BITS = 15

    # Base match lengths and extra bit counts for length codes 257-285.
    # Unlike Deflate, code 285 encodes a length of 3 plus 16 extra bits.
    LENGTH_BASE  = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
                    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 3].freeze
    LENGTH_EXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
                    3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 16].freeze

    # Base distances and extra bit counts for the 32 distance codes. Codes
    # 30 and 31 do not exist in Deflate; here they allow distances of up to
    # 65,536 bytes.
    DISTANCE_BASE  = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
                      257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
                      8193, 12_289, 16_385, 24_577, 32_769, 49_153].freeze
    DISTANCE_EXTRA = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
                      7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14].freeze

    # The order in which code lengths for the code length code are stored.
    CODE_LENGTH_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15].freeze

    # Code lengths for the fixed literal/length and distance codes. The
    # fixed distance code has 32 five-bit codes, rather than 30 in Deflate.
    FIXED_LITERAL_LENGTHS  = (Array.new(144, 8) + Array.new(112, 9) +
                              Array.new(24, 7) + Array.new(8, 8)).freeze
    FIXED_DISTANCE_LENGTHS = Array.new(32, 5).freeze

    def initialize(input_stream, decompressed_size = nil)
      super

      @output      = +''.b
      @history     = +''.b
      @input       = +''.b
      @input_pos   = 0
      @bit_buffer  = 0
      @bit_count   = 0
      @final_block = false
      @state       = :block_header
      @finished    = false
    end

    def read(maxlen = nil)
      return (maxlen.nil? || maxlen.zero? ? '' : nil) if eof?

      decode_step while !@finished && (maxlen.nil? || @output.bytesize < maxlen)

      @output.slice!(0...(maxlen || @output.bytesize))
    end

    def eof?
      @output.empty? && @finished
    end

    # Alias for compatibility. Remove for version 4.
    alias eof eof?

    def self.error(message)
      raise ::Zip::DecompressionError, ::Zip::Error.new("Deflate64 stream: #{message}")
    end

    def self.fixed_literal_tree
      @fixed_literal_tree ||= HuffmanTree.new(FIXED_LITERAL_LENGTHS)
    end

    def self.fixed_distance_tree
      @fixed_distance_tree ||= HuffmanTree.new(FIXED_DISTANCE_LENGTHS)
    end

    # A canonical Huffman code, built from a list of code lengths.
    class HuffmanTree
      attr_reader :count, :symbols

      def initialize(lengths)
        @count = [0] * (Deflate64::MAX_CODE_BITS + 1)
        lengths.each { |length| @count[length] += 1 }
        @count[0] = 0

        check_lengths

        symbols = lengths.each_index.select { |i| lengths[i].positive? }
        @symbols = symbols.sort_by { |i| [lengths[i], i] }
      end

      private

      # Over-subscribed codes are always an error. Incomplete codes are only
      # permitted when there are no codes at all (decoding then always
      # fails) or there is a single code of one bit.
      def check_lengths
        left = 1
        max  = 0
        (1..Deflate64::MAX_CODE_BITS).each do |bits|
          left = (left << 1) - @count[bits]
          Deflate64.error('over-subscribed set of code lengths') if left.negative?
          max = bits if @count[bits].positive?
        end
        return if left.zero? || max.zero? || max == 1

        Deflate64.error('incomplete set of code lengths')
      end
    end

    private

    def decode_step
      case @state
      when :block_header     then decode_block_header
      when :stored_block     then decode_stored_block
      when :compressed_block then decode_compressed_symbol
      end
    end

    def decode_block_header
      @final_block = read_bits(1) == 1
      case read_bits(2)
      when 0 then start_stored_block
      when 1 then start_fixed_block
      when 2 then start_dynamic_block
      else self.class.error('invalid block type')
      end
    end

    def start_stored_block
      align_to_byte
      @stored_remaining = read_bits(16)
      if @stored_remaining != (~read_bits(16) & 0xFFFF)
        self.class.error('stored block length mismatch')
      end

      @state = :stored_block
    end

    def decode_stored_block
      while @stored_remaining.positive?
        if @bit_count >= 8
          emit_byte(@bit_buffer & 0xFF)
          @bit_buffer >>= 8
          @bit_count -= 8
          @stored_remaining -= 1
        else
          chunk = read_input([@stored_remaining, CHUNK_SIZE].min)
          emit(chunk)
          @stored_remaining -= chunk.bytesize
        end
      end
      end_block
    end

    def start_fixed_block
      @literal_tree  = self.class.fixed_literal_tree
      @distance_tree = self.class.fixed_distance_tree
      @state = :compressed_block
    end

    def start_dynamic_block
      hlit  = read_bits(5) + 257
      hdist = read_bits(5) + 1
      hclen = read_bits(4) + 4
      lengths = read_code_lengths(hlit + hdist, hclen)
      @literal_tree  = HuffmanTree.new(lengths.first(hlit))
      @distance_tree = HuffmanTree.new(lengths.last(hdist))
      @state = :compressed_block
    end

    def read_code_lengths(total, hclen)
      code_length_lengths = Array.new(19, 0)
      CODE_LENGTH_ORDER.first(hclen).each do |symbol|
        code_length_lengths[symbol] = read_bits(3)
      end
      tree = HuffmanTree.new(code_length_lengths)

      lengths = []
      lengths.concat(read_code_length(tree, lengths)) while lengths.size < total
      self.class.error('too many code lengths') if lengths.size > total

      lengths
    end

    def read_code_length(tree, lengths)
      symbol = decode_huffman(tree)
      case symbol
      when 0..15
        [symbol]
      when 16
        self.class.error('repeat of a code length with no previous length') if lengths.empty?

        [lengths.last] * (read_bits(2) + 3)
      when 17
        [0] * (read_bits(3) + 3)
      else # 18
        [0] * (read_bits(7) + 11)
      end
    end

    def decode_compressed_symbol
      symbol = decode_huffman(@literal_tree)
      if symbol < 256
        emit_byte(symbol)
      elsif symbol == 256
        end_block
      elsif symbol <= 285
        decode_match(symbol - 257)
      else
        self.class.error("invalid literal/length code #{symbol}")
      end
    end

    def decode_match(code)
      length        = LENGTH_BASE[code] + read_bits(LENGTH_EXTRA[code])
      distance_code = decode_huffman(@distance_tree)
      distance      = DISTANCE_BASE[distance_code] + read_bits(DISTANCE_EXTRA[distance_code])
      copy_match(length, distance)
    end

    # Decodes one symbol from the given Huffman tree.
    def decode_huffman(tree)
      code  = 0
      first = 0
      index = 0
      (1..MAX_CODE_BITS).each do |bits|
        code |= read_bit
        count = tree.count[bits]
        return tree.symbols[index + code - first] if (code - first) < count

        index += count
        first  = (first + count) << 1
        code <<= 1
      end
      self.class.error('invalid huffman code')
    end

    def copy_match(length, distance)
      self.class.error('match distance too far back') if distance > @history.bytesize

      if length <= distance
        emit(@history.byteslice(-distance, length))
      else
        # The match overlaps itself: the last `distance` bytes repeat.
        pattern = @history.byteslice(-distance..)
        emit(pattern * (length / distance) + pattern.byteslice(0, length % distance))
      end
    end

    def end_block
      if @final_block
        @finished = true
      else
        @state = :block_header
      end
    end

    def emit(chunk)
      @output << chunk
      @history << chunk
      trim_history
    end

    def emit_byte(byte)
      @output << byte
      @history << byte
      trim_history
    end

    def trim_history
      @history = @history.byteslice(-WINDOW_SIZE..) if @history.bytesize > WINDOW_SIZE * 2
    end

    def align_to_byte
      drop = @bit_count % 8
      @bit_buffer >>= drop
      @bit_count -= drop
    end

    def read_bits(count)
      while @bit_count < count
        @bit_buffer |= next_input_byte << @bit_count
        @bit_count += 8
      end
      result = @bit_buffer & ((1 << count) - 1)
      @bit_buffer >>= count
      @bit_count -= count
      result
    end

    def read_bit
      if @bit_count.zero?
        @bit_buffer = next_input_byte
        @bit_count  = 8
      end
      bit = @bit_buffer & 1
      @bit_buffer >>= 1
      @bit_count -= 1
      bit
    end

    def next_input_byte
      fill_input if @input_pos >= @input.bytesize
      byte = @input.getbyte(@input_pos)
      @input_pos += 1
      byte
    end

    def read_input(length)
      result = +''.b
      while result.bytesize < length
        fill_input if @input_pos >= @input.bytesize
        take = [@input.bytesize - @input_pos, length - result.bytesize].min
        result << @input.byteslice(@input_pos, take)
        @input_pos += take
      end
      result
    end

    def fill_input
      chunk = input_stream.read(CHUNK_SIZE)
      self.class.error('unexpected end of stream') if chunk.nil? || chunk.empty?

      @input     = chunk.b
      @input_pos = 0
    end
  end

  ::Zip::Decompressor.register(::Zip::COMPRESSION_METHOD_DEFLATE_64, ::Zip::Deflate64)
end
