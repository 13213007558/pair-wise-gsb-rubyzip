# frozen_string_literal: true

module Zip
  module Deflate64
    # Streaming Deflate64 (PKWARE method 9) decoder.
    #
    # The block format is the same as ordinary deflate, except that:
    # * length code 285 carries 16 extra bits (lengths up to 65538),
    # * the distance alphabet has 32 codes (codes 30 and 31 carry 14 extra
    #   bits, allowing distances up to 65536),
    # * the back-reference window is 64 KiB.
    class Engine
      MAX_MATCH_LENGTH = 65_538
      MAX_DISTANCE = 65_536
      END_OF_BLOCK = 256

      # Maximum bytes one call to #inflate can add to its output. A single
      # match can produce 65538 bytes, so allow one full match plus a little
      # headroom. This keeps buffering bounded even on pathological input.
      OUTPUT_LIMIT = MAX_MATCH_LENGTH + 1024

      LENGTH_BASE = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17,
        19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99,
        115, 131, 163, 195, 227, 3
      ].freeze

      LENGTH_EXTRA_BITS = [
        0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
        3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5,
        0, 0, 0, 0, 16
      ].freeze

      DISTANCE_BASE = [
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
        257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
        8193, 12_289, 16_385, 24_577, 32_769, 49_153
      ].freeze

      DISTANCE_EXTRA_BITS = [
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
        7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
        14, 14
      ].freeze

      CODE_LENGTH_ORDER = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
      ].freeze

      def initialize(&read_bytes)
        @bit_reader = BitReader.new(&read_bytes)
        @window = +''.b
        @final_block = false
        @state = :block_header
        @stored_remaining = 0
        @pending_match = nil
        @literal_table = nil
        @distance_table = nil
      end

      def finished?
        @state == :finished
      end

      # Inflates up to OUTPUT_LIMIT bytes into `output` (a binary String).
      # Returns when the limit is reached or the stream ends.
      def inflate(output)
        produced = 0

        until produced >= OUTPUT_LIMIT || finished?
          new_bytes = step(output, OUTPUT_LIMIT - produced)
          produced += new_bytes
        end
        produced
      rescue TruncatedInputError, HuffmanTable::InvalidCodeLengthsError => e
        raise DecompressionError, e.message
      end

      private

      # Performs one state transition and returns the number of bytes added.
      def step(output, budget)
        case @state
        when :block_header then read_block_header
        when :stored then read_stored_bytes(output, budget)
        when :huffman then decode_symbol(output, budget)
        when :copy_match then copy_match(output, budget)
        end
      end

      def read_block_header
        @final_block = @bit_reader.read_bit == 1
        block_type = @bit_reader.read_bits(2)

        case block_type
        when 0 then start_stored_block
        when 1 then start_fixed_block
        when 2 then start_dynamic_block
        else
          raise DecompressionError,
                "invalid Deflate64 block type #{block_type} (must be 0, 1 or 2)"
        end
        0
      end

      def start_stored_block
        @bit_reader.align_to_byte
        length = @bit_reader.read_bits(16)
        complement = @bit_reader.read_bits(16)
        unless complement == (length ^ 0xffff)
          raise DecompressionError,
                'invalid stored Deflate64 block (LEN/NLEN mismatch)'
        end

        @stored_remaining = length
        @state = :stored
      end

      def read_stored_bytes(output, budget)
        count = [@stored_remaining, budget].min
        chunk = +''.b
        count.times { chunk << @bit_reader.read_byte }
        emit(output, chunk)
        @stored_remaining -= count
        end_block if @stored_remaining.zero?
        count
      end

      def start_fixed_block
        @literal_table = FIXED_LITERAL_TABLE
        @distance_table = FIXED_DISTANCE_TABLE
        @state = :huffman
      end

      def start_dynamic_block
        literal_count = @bit_reader.read_bits(5) + 257
        distance_count = @bit_reader.read_bits(5) + 1
        code_length_count = @bit_reader.read_bits(4) + 4

        code_length_lengths = Array.new(19, 0)
        CODE_LENGTH_ORDER.first(code_length_count).each_with_index do |symbol, _i|
          code_length_lengths[symbol] = @bit_reader.read_bits(3)
        end

        code_length_table = HuffmanTable.new(code_length_lengths)
        lengths = read_alphabet_lengths(code_length_table,
                                        literal_count + distance_count)
        validate_code_length_alphabet(code_length_lengths)

        literal_lengths = lengths.first(literal_count)
        distance_lengths = lengths.last(distance_count)
        @literal_table = HuffmanTable.new(literal_lengths)
        @distance_table = build_distance_table(distance_lengths)
        @state = :huffman
      end

      def read_alphabet_lengths(table, total)
        lengths = []
        while lengths.length < total
          symbol = table.decode(@bit_reader)
          case symbol
          when 0..15 then lengths << symbol
          when 16
            previous = lengths.last
            raise DecompressionError,
                  'Deflate64 code length repeat with no preceding value' if previous.nil?

            repeat = @bit_reader.read_bits(2) + 3
            lengths.concat([previous] * repeat)
          when 17
            repeat = @bit_reader.read_bits(3) + 3
            lengths.concat([0] * repeat)
          when 18
            repeat = @bit_reader.read_bits(7) + 11
            lengths.concat([0] * repeat)
          else
            raise DecompressionError,
                  "invalid Deflate64 code length symbol #{symbol}"
          end
        end
        raise DecompressionError, 'Deflate64 code length data is too long' if lengths.length > total

        lengths
      end

      # An incomplete code-length alphabet is always invalid (zlib rejects it
      # too); an empty one is caught here as well.
      def validate_code_length_alphabet(lengths)
        return if complete?(lengths)

        raise HuffmanTable::InvalidCodeLengthsError,
              'incomplete Deflate64 code length Huffman table'
      end

      def build_distance_table(lengths)
        return EMPTY_HUFFMAN_TABLE if lengths.all?(&:zero?)

        table = HuffmanTable.new(lengths)
        return table if complete?(lengths)

        # The only incomplete distance table zlib accepts is a single code of
        # length 1.
        non_zero = lengths.reject(&:zero?)
        if non_zero.length == 1 && non_zero.first == 1
          return table
        end

        raise HuffmanTable::InvalidCodeLengthsError,
              'incomplete Deflate64 distance Huffman table'
      end

      def complete?(lengths)
        non_zero = lengths.reject(&:zero?)
        return false if non_zero.empty?

        max_length = non_zero.max
        sum = non_zero.sum { |length| 1 << (max_length - length) }
        sum == (1 << max_length)
      end

      def decode_symbol(output, budget)
        symbol = @literal_table.decode(@bit_reader)

        if symbol < END_OF_BLOCK
          byte = symbol.chr(Encoding::BINARY)
          emit(output, byte)
          return 1
        end

        end_block and return 0 if symbol == END_OF_BLOCK

        start_match(symbol)
        0
      end

      def start_match(length_symbol)
        length = match_length(length_symbol)
        distance_symbol = @distance_table.decode(@bit_reader)
        distance = match_distance(distance_symbol)

        if distance > @window.bytesize
          raise DecompressionError,
                "Deflate64 back-reference distance #{distance} is greater than " \
                "the #{@window.bytesize} bytes decoded so far"
        end

        @pending_match = { length: length, distance: distance }
        @state = :copy_match
      end

      def match_length(symbol)
        index = symbol - 257
        if symbol == 286 || symbol == 287 || !index.between?(0, LENGTH_BASE.length - 1)
          raise DecompressionError, "invalid Deflate64 length code #{symbol}"
        end

        extra_bits = LENGTH_EXTRA_BITS[index]
        LENGTH_BASE[index] + @bit_reader.read_bits(extra_bits)
      end

      def match_distance(symbol)
        if symbol >= DISTANCE_BASE.length
          raise DecompressionError, "invalid Deflate64 distance code #{symbol}"
        end

        extra_bits = DISTANCE_EXTRA_BITS[symbol]
        distance = DISTANCE_BASE[symbol] + @bit_reader.read_bits(extra_bits)
        if distance > MAX_DISTANCE
          raise DecompressionError,
                "Deflate64 distance #{distance} exceeds the 64 KiB window"
        end

        distance
      end

      def copy_match(output, budget)
        match = @pending_match
        count = [match[:length], budget].min
        distance = match[:distance]

        copy_overlapping(distance, count, output)
        match[:length] -= count
        if match[:length].zero?
          @pending_match = nil
          @state = :huffman
        end
        count
      end

      def copy_overlapping(distance, count, output)
        # Fast path: the whole match lies entirely in the existing window with
        # no overlap into bytes produced by this match.
        if distance >= count
          chunk = @window.byteslice(-distance, count)
          emit(output, chunk)
          return
        end

        # Overlapping copies repeat like `memcpy` with distance-1 matches;
        # grow a seed by doubling to avoid byte-by-byte copying.
        seed = @window.byteslice(-distance, distance)
        chunk = +seed
        while chunk.bytesize < count
          chunk << chunk
        end
        emit(output, chunk.byteslice(0, count))
      end


      def emit(output, bytes)
        output << bytes
        @window << bytes
        if @window.bytesize > MAX_DISTANCE
          @window.slice!(0, @window.bytesize - MAX_DISTANCE)
        end
      end

      def end_block
        if @final_block
          @state = :finished
        else
          @state = :block_header
        end
      end

      fixed_literal_lengths = Array.new(288, 0)
      (0..143).each { |symbol| fixed_literal_lengths[symbol] = 8 }
      (144..255).each { |symbol| fixed_literal_lengths[symbol] = 9 }
      (256..279).each { |symbol| fixed_literal_lengths[symbol] = 7 }
      (280..287).each { |symbol| fixed_literal_lengths[symbol] = 8 }
      FIXED_LITERAL_TABLE = HuffmanTable.new(fixed_literal_lengths)
      # Fixed-block distance codes: 32 codes of 5 bits (the same layout as
      # ordinary deflate). Symbols 30 and 31 are reserved in fixed blocks
      # and rejected through the distance table when a match reads them.
      FIXED_DISTANCE_TABLE = HuffmanTable.new(Array.new(32, 5))

      # A distance alphabet with no codes: literals/EOB decode fine, but any
      # length code that tries to read a distance must fail.
      EMPTY_HUFFMAN_TABLE = Object.new.tap do |table|
        def table.decode(_reader)
          raise HuffmanTable::InvalidCodeLengthsError,
                'distance code used with an empty Deflate64 distance table'
        end
      end
    end
  end
end
