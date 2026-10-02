# frozen_string_literal: true

module Zip
  module Deflate64
    # A canonical Huffman table built from an array of code lengths (as
    # described in RFC 1951 section 3.2.2). Symbols are decoded LSB first.
    class HuffmanTable
      class InvalidCodeLengthsError < StandardError; end

      def initialize(lengths)
        @lengths = lengths
        @max_length = lengths.max || 0
        build
      end

      # Decodes one symbol. Bits arrive LSB first; reading them in order and
      # shifting into the high position reconstructs each canonical code.
      def decode(reader)
        code = 0
        (1..@max_length).each do |bits|
          code = (code << 1) | reader.read_bit
          symbol = @lookup[[bits, code]]
          return symbol unless symbol.nil?
        end

        raise InvalidCodeLengthsError, 'invalid Huffman code in Deflate64 stream'
      end

      private

      def build
        @counts = Array.new(@max_length + 1, 0)
        @lengths.each { |length| @counts[length] += 1 if length.positive? }
        @counts[0] = 0

        check_for_oversubscription

        @first_codes = Array.new(@max_length + 1, 0)
        code = 0
        (1..@max_length).each do |bits|
          code = (code + @counts[bits - 1]) << 1
          @first_codes[bits] = code
        end

        @lookup = build_symbol_index
      end

      # An over-subscribed set of code lengths (Kraft sum > 1) is never
      # legal, regardless of which alphabet it describes.
      def check_for_oversubscription
        # Over-subscription means the Kraft inequality sum(2^-length) > 1.
        # Compute it with integers to avoid floating-point rounding.
        sum = @counts.each_with_index.sum do |count, bits|
          bits.zero? ? 0 : count << (@max_length - bits)
        end
        if sum > (1 << @max_length)
          raise InvalidCodeLengthsError,
                'over-subscribed Huffman code lengths in Deflate64 stream'
        end
      end

      def build_symbol_index
        next_code = @first_codes.dup
        lookup = {}
        @lengths.each_with_index do |length, symbol|
          next if length.zero?

          lookup[[length, next_code[length]]] = symbol
          next_code[length] += 1
        end
        lookup
      end
    end
  end
end
