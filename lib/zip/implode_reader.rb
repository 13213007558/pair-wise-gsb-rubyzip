# frozen_string_literal: true

module Zip
  class ImplodeReader < Decompressor
    class << self
      attr_accessor :decompression_flags
    end

    attr_accessor :entry_name

    self.decompression_flags = 0

    DISTANCE_CODE_LENGTHS = Array.new(6, 7) + Array.new(6, 8) + Array.new(52, 9)
    LENGTH_LENGTHS = (3..66).flat_map { |length| [length, length] }

    def initialize(*args, flags: nil, **keywords)
      super(*args, **keywords)
      @flags = flags || self.class.decompression_flags
      @literal_tree = @flags.anybits?(0x1)
      @large_window = @flags.anybits?(0x2)
      @window_size = @large_window ? 0x2000 : 0x1000
      @distance_bits = @large_window ? 4 : 3
      @bit_buffer = 0
      @available_bits = 0
      @output = +''.b
      @remaining_size = nil
      @trees_loaded = false
      @output_position = 0
      @secondary_length_codes = build_codes(LENGTH_LENGTHS)
      @primary_length_codes = build_codes(Array.new(256, 8))
      @distance_codes = nil
      input_stream.readbyte
      @remaining_size = decompressed_size
    end

    def read(maxlen = nil)
      raise DecompressionError, 'unsupported Implode flags' unless valid_flags?

      decode_next while @remaining_size.nil? || @remaining_size.positive?
      slice_output(maxlen || @output.bytesize)
    rescue EOFError
      raise DecompressionError, 'unexpected end of Implode data'
    rescue KeyError, IndexError
      raise DecompressionError, 'corrupt Implode data'
    rescue DecompressionError => e
      raise e if entry_name.nil? || e.message.include?(entry_name)

      raise DecompressionError, "decompression failed for entry '#{entry_name}': #{e.message}"
    end

    def eof?
      @remaining_size && @remaining_size.zero?
    end

    alias eof eof?

    private

    def valid_flags?
      (@flags & ~0x3).zero?
    end

    def decode_next
      return if @remaining_size&.zero?

      load_trees
      read_bit.zero? ? decode_literal : decode_match
    end

    def load_trees
      return if @trees_loaded

      if @literal_tree
        @literal_lengths = read_code_tree(256)
        @literal_codes = build_codes(@literal_lengths)
      end
      @trees_loaded = true
    end

    def read_code_tree(symbol_count)
      first = read_tree_byte
      maximum_length = first & 0x0f
      initial_count = first >> 4
      lengths = []
      initial_count.times { lengths << maximum_length }
      while lengths.length < symbol_count
        byte = read_tree_byte
        length = byte >> 4
        repeat = byte & 0x0f
        repeat += 1
        raise DecompressionError, 'corrupt Implode code tree' if length.zero? || length > maximum_length

        lengths.concat(Array.new(repeat, length))
      end
      raise DecompressionError, 'corrupt Implode code tree' unless lengths.length == symbol_count

      lengths
    end

    def read_tree_byte
      read_bits(8)
    rescue EOFError
      raise DecompressionError, 'unexpected end of Implode data'
    end


    def build_codes(lengths)
      counts = Array.new(lengths.max.to_i + 1, 0)
      lengths.each { |length| counts[length] += 1 if length.to_i.positive? }
      next_code = {}
      code = 0
      counts.each_index do |length|
        next if length.zero?

        code >>= 1 if length > 1
        next_code[length] = code
        code += counts[length] << (16 - length)
      end
      lengths.map do |length|
        next nil if length.zero?

        value = next_code[length]
        next_code[length] += 1 << (16 - length)
        value >> (16 - length)
      end
    end

    def decode_literal
      value = @literal_tree ? decode_symbol(@literal_codes, @literal_lengths) : read_bits(8)
      emit_byte(value)
    end

    def decode_match
      low_length = read_bits(6)
      codes = low_length < 8 ? @secondary_length_codes : @primary_length_codes
      length_lengths = low_length < 8 ? LENGTH_LENGTHS : Array.new(256, 8)
      length = 3 + decode_symbol(codes, length_lengths)
      length += low_length - 8 if low_length >= 8
      @distance_codes ||= build_codes(DISTANCE_CODE_LENGTHS)
      distance_symbol = decode_symbol(@distance_codes, DISTANCE_CODE_LENGTHS)
      distance = ((distance_symbol << @distance_bits) | read_bits(@distance_bits)) + 1
      raise DecompressionError, 'Implode back-reference distance is out of range' if distance > @output.bytesize

      copy_match(distance, length)
    end

    def decode_symbol(codes, lengths)
      raise KeyError if codes.nil?

      value = 0
      lengths.uniq.sort.each do |length|
        value = 0
        length.times { |bit| value |= read_bit << bit }
        symbol = codes.index(value)
        return symbol unless symbol.nil?
        value = 0
      end
      raise KeyError
    end

    def copy_match(distance, length)
      position = @output.bytesize
      length.times do
        source = position - distance
        raise DecompressionError, 'Implode back-reference distance is out of range' if source.negative?

        @output << @output.byteslice(source, 1)
        position += 1
      end
      @remaining_size -= length if @remaining_size
    end

    def emit_byte(value)
      @output << value.chr(Encoding::BINARY)
      @remaining_size -= 1 if @remaining_size
    end

    def slice_output(length)
      end_position = [@output_position + length, @output.bytesize].min
      result = @output.byteslice(@output_position...end_position)
      @output_position = end_position
      result
    end

    def read_bit
      fill_buffer if @available_bits.zero?
      value = @bit_buffer & 1
      @bit_buffer >>= 1
      @available_bits -= 1
      value
    end

    def read_bits(count)
      value = 0
      count.times { |bit| value |= read_bit << bit }
      value
    end

    def fill_buffer
      @bit_buffer = input_stream.readbyte
      @available_bits = 8
    end
  end

  Decompressor.register(COMPRESSION_METHOD_IMPLODE, ImplodeReader)
end
