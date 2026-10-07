# frozen_string_literal: true

module Zip
  # Decompressor for the "Implode" compression method (method 6), used by
  # PKZIP 1.x. Read-only support: 4K and 8K sliding dictionaries, with or
  # without a literal Shannon-Fano tree.
  class Imploder < Decompressor # :nodoc:all
    # General purpose bit flag bits interpreted by Implode.
    DICTIONARY_SIZE_GP_BIT = 0x02 # set: 8K dictionary, clear: 4K
    THREE_TREES_GP_BIT     = 0x04 # set: 3 Shannon-Fano trees, clear: 2

    MAX_CODE_LENGTH = 16

    def initialize(input_stream, decompressed_size, entry = nil)
      super

      gp_flags = @entry ? @entry.gp_flags : 0
      @dict_size   = (gp_flags & DICTIONARY_SIZE_GP_BIT).zero? ? 4096 : 8192
      @three_trees = (gp_flags & THREE_TREES_GP_BIT) != 0
      @min_match   = @three_trees ? 3 : 2
      @low_bits    = @dict_size == 4096 ? 6 : 7

      @output   = +''.b
      @finished = false
      @error    = nil

      decompress
    end

    def read(maxlen = nil)
      raise @error if @error
      return (maxlen.nil? || maxlen.zero? ? '' : nil) if eof?

      @output.slice!(0...(maxlen || @output.bytesize))
    end

    def eof?
      @output.empty? && @finished
    end

    # Alias for compatibility. Remove for version 4.
    alias eof eof?

    private

    def decompress
      @data     = read_compressed_data
      @byte_pos = 0
      @bit_pos  = 0

      @literal_decoder  = read_tree(256) if @three_trees
      @length_decoder   = read_tree(64)
      @distance_decoder = read_tree(64)

      decode_records
      check_complete
    rescue ::Zip::DecompressionError => e
      @error = e
    end

    # Reads exactly this entry's compressed data, so that decoding never
    # runs past the end of the entry into the rest of the archive.
    def read_compressed_data
      size = @entry ? @entry.compressed_size : nil
      data = size && size.positive? ? @input_stream.read(size) : @input_stream.read
      data || +''.b
    end

    def decode_records
      while @output.bytesize < decompressed_size
        flag = read_bit
        break if flag.nil?

        if flag == 1
          @output << read_literal
        else
          decode_match
          break if @finished
        end
      end
    end

    def check_complete
      if @output.bytesize < decompressed_size
        return fail_decode('imploded data ended before the entry was fully decoded')
      end

      @output = @output[0, decompressed_size] if @output.bytesize > decompressed_size
      @finished = true
    end

    def read_literal
      if @three_trees
        sym = decode_symbol(@literal_decoder)
        fail_decode('invalid literal Shannon-Fano code') if sym.nil?
        sym
      else
        byte = read_bits(8)
        fail_decode('imploded data ended mid-literal') if byte.nil?
        byte
      end
    end

    def decode_match
      low = read_bits(@low_bits)
      fail_decode('imploded data ended mid-match') if low.nil?
      dist_high = decode_symbol(@distance_decoder)
      fail_decode('invalid distance Shannon-Fano code') if dist_high.nil?
      len_sym = decode_symbol(@length_decoder)
      fail_decode('invalid length Shannon-Fano code') if len_sym.nil?

      length = len_sym + @min_match
      if len_sym == 63
        extra = read_bits(8)
        fail_decode('imploded data ended mid-match') if extra.nil?

        length += extra
      end
      distance = ((dist_high << @low_bits) | low) + 1

      # A match at exactly the dictionary size marks the end of the stream.
      @finished = true and return if distance == @dict_size

      if distance > @output.bytesize
        fail_decode("back-reference distance #{distance} beyond #{@output.bytesize} bytes")
      end

      length.times do
        break if @output.bytesize >= decompressed_size

        @output << @output[-distance]
      end
    end

    # Reads one Shannon-Fano tree: a count byte followed by that many packed
    # bytes. Each packed byte holds a run length (high nibble, minus 1) and a
    # code length (low nibble, minus 1) for a run of consecutive symbols.
    def read_tree(alphabet_size)
      count = read_bits(8)
      fail_decode('imploded data ended while reading a Shannon-Fano tree') if count.nil?

      lengths = []
      (count + 1).times do
        byte = read_bits(8)
        fail_decode('imploded data ended while reading a Shannon-Fano tree') if byte.nil?

        ((byte >> 4) + 1).times { lengths << (byte & 0x0f) + 1 }
      end

      if lengths.size != alphabet_size
        fail_decode("Shannon-Fano tree has #{lengths.size} symbols, expected #{alphabet_size}")
      end

      build_decoder(lengths)
    end

    # Builds a canonical decoding table from the code lengths. Codes are
    # assigned canonically (by length, then symbol order) and transmitted
    # complemented (all bits inverted), most-significant bit first.
    def build_decoder(lengths)
      kraft = lengths.sum { |len| 1 << (MAX_CODE_LENGTH - len) }
      if kraft != (1 << MAX_CODE_LENGTH)
        fail_decode('Shannon-Fano tree is not a complete code')
      end

      count = Array.new(MAX_CODE_LENGTH + 1, 0)
      lengths.each { |len| count[len] += 1 }

      code = 0
      next_code = [0]
      (1..MAX_CODE_LENGTH).each do |bits|
        code = (code + count[bits - 1]) << 1
        next_code[bits] = code
      end

      table = {}
      lengths.each_with_index do |len, sym|
        canonical = next_code[len]
        next_code[len] += 1
        table[[len, (1 << len) - 1 - canonical]] = sym
      end
      table
    end

    def decode_symbol(table)
      value = 0
      (1..MAX_CODE_LENGTH).each do |len|
        bit = read_bit
        return nil if bit.nil?

        value = (value << 1) | bit
        sym = table[[len, value]]
        return sym if sym
      end
      nil
    end

    def read_bit
      return nil if @byte_pos >= @data.bytesize

      bit = (@data.getbyte(@byte_pos) >> @bit_pos) & 1
      @bit_pos += 1
      if @bit_pos == 8
        @bit_pos = 0
        @byte_pos += 1
      end
      bit
    end

    def read_bits(count)
      value = 0
      count.times do |i|
        bit = read_bit
        return nil if bit.nil?

        value |= bit << i
      end
      value
    end

    def fail_decode(reason)
      name = @entry ? "entry '#{@entry.name}'" : 'entry'
      raise ::Zip::DecompressionError.new(
        nil, entry: @entry, message: "Implode decoding of #{name} failed: #{reason}."
      )
    end
  end

  ::Zip::Decompressor.register(::Zip::COMPRESSION_METHOD_IMPLODE, ::Zip::Imploder)
end
