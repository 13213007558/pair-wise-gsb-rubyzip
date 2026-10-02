# frozen_string_literal: true

module Zip
  module Deflate64
    # Raised internally when the compressed input ends before a complete
    # element (header, code or extra bits) could be read.
    class TruncatedInputError < StandardError; end

    # Reads individual bits from a byte stream, LSB first. Bytes are pulled in
    # from the provided block in chunks, like Zip::Inflater reads from the
    # underlying IO.
    class BitReader
      def initialize(&read_bytes)
        @read_bytes = read_bytes
        @bytes = +''.b
        @bit_pos = 0
      end

      def read_bit
        bit = (current_byte >> (@bit_pos % 8)) & 1
        @bit_pos += 1
        bit
      end

      def read_bits(count)
        value = 0
        count.times do |i|
          value |= (read_bit << i)
        end
        value
      end

      # Discards the unused bits of the current byte, aligning the stream on a
      # byte boundary (used before reading stored blocks).
      def align_to_byte
        @bit_pos = ((@bit_pos + 7) & ~7)
      end

      def read_byte
        byte = current_byte
        @bit_pos += 8
        compact
        byte
      end

      # Drops bytes that lie entirely before the current bit position. This
      # keeps memory bounded to a small number of input chunks regardless
      # of how large the decompressed entry is.
      def compact
        # Only call this on a byte boundary; drops all bytes before the
        # one at the current position.
        consumed_bytes = @bit_pos / 8
        return if consumed_bytes.zero?

        @bytes.slice!(0, consumed_bytes)
        @bit_pos -= consumed_bytes * 8
      end

      private

      def current_byte
        index = @bit_pos / 8
        while index >= @bytes.bytesize
          chunk = @read_bytes.call
          raise TruncatedInputError, 'unexpected end of Deflate64 input' if chunk.nil? || chunk.empty?

          @bytes << chunk
        end
        @bytes.getbyte(index)
      end
    end
  end
end
