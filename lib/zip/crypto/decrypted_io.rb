# frozen_string_literal: true

module Zip
  class DecryptedIo # :nodoc:all
    CHUNK_SIZE = 32_768

    def initialize(io, decrypter, compressed_size)
      @io = io
      @decrypter = decrypter
      @bytes_remaining = compressed_size
      @buffer = +''.b
      # Ensures that integrity is only checked once,
      # even if read is called multiple times after the input has finished.
      @integrity_verified = false
    end

    def read(maxlen = nil)
      @buffer << produce_input while !input_finished? && (maxlen.nil? || @buffer.bytesize < maxlen)

      verify_integrity if input_finished?

      return (maxlen.nil? || maxlen.zero? ? '' : nil) if eof?

      @buffer.slice!(0...(maxlen || @buffer.bytesize))
    end

    private

    def eof?
      @buffer.empty? && input_finished?
    end

    def input_finished?
      !@bytes_remaining.positive?
    end

    # Integrity is checked exactly once, as soon as the input has finished -
    # even for empty entries, and even if read is called again afterwards.
    def verify_integrity
      return if @integrity_verified

      @decrypter.check_integrity!(@io)
      @integrity_verified = true
    end

    def produce_input
      chunk_size = [@bytes_remaining, CHUNK_SIZE].min
      return '' unless chunk_size.positive?

      data = read_fully(chunk_size)
      @bytes_remaining -= data.bytesize
      @decrypter.decrypt(data)
    end

    # Reads exactly `length` bytes from the underlying IO, looping over any
    # short reads it returns. Never reads past the entry's ciphertext, so
    # the trailing authentication code is left untouched for
    # `check_integrity!`. A truncated entry is an error, not a normal end
    # of input.
    def read_fully(length)
      data = +''.b
      while data.bytesize < length
        chunk = @io.read(length - data.bytesize)
        raise ::Zip::Error, 'Truncated encrypted data' if chunk.nil? || chunk.empty?

        data << chunk
      end
      data
    end
  end
end
