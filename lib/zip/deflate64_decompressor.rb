# frozen_string_literal: true

require_relative 'deflate64/reader'
require_relative 'deflate64/huffman_table'
require_relative 'deflate64/engine'

module Zip
  # A pure-Ruby decompressor for Deflate64 (ZIP compression method 9).
  #
  # Deflate64 uses the same block structure as ordinary deflate (fixed and
  # dynamic Huffman blocks, plus stored blocks) but with a 64 KiB history
  # window, longer matches (up to 65538 bytes) and two additional distance
  # codes. This class implements the reading side only; Deflate64 archives
  # are created by external tools.
  class Deflate64Decompressor < Decompressor # :nodoc:all
    def initialize(*args)
      super
      @buffer = +''.b
      @engine = Deflate64::Engine.new do
        input_stream.read(Zip.inflater_chunk_size)
      end
    end

    def read(maxlen = nil)
      return (maxlen.nil? || maxlen.zero? ? '' : nil) if eof?

      while maxlen.nil? || @buffer.bytesize < maxlen
        break if input_finished?

        produced = +''.b
        count = @engine.inflate(produced)
        @buffer << produced if count.positive?
      end

      @buffer.slice!(0...(maxlen || @buffer.bytesize))
    end

    def eof?
      @buffer.empty? && input_finished?
    end

    # Alias for compatibility. Remove for version 4.
    alias eof eof?

    private

    def input_finished?
      @engine.finished?
    end
  end

  ::Zip::Decompressor.register(
    ::Zip::COMPRESSION_METHOD_DEFLATE_64, ::Zip::Deflate64Decompressor
  )
end
