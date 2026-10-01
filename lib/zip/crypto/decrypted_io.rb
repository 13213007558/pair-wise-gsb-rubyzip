# frozen_string_literal: true

module Zip
  class DecryptedIo # :nodoc:all
    CHUNK_SIZE = 32_768

    def initialize(io, decrypter, compressed_size)
      @io = io
      @decrypter = decrypter
      @bytes_remaining = compressed_size
      @buffer = +''.b
      @finalized = false
      # Ensures that integrity is only checked once,
      # even if read is called multiple times after the input has finished.
      @integrity_verified = false
    end

    def read(maxlen = nil)
      return nil if maxlen&.positive? && eof?

      while maxlen.nil? || (@buffer.bytesize < maxlen)
        break if input_finished?

        @buffer << produce_input
      end

      finish_input! if input_finished?

      return nil if maxlen&.positive? && @buffer.empty?

      @buffer.slice!(0, maxlen || @buffer.bytesize)
    end

    private

    # The stream is only exhausted once every declared ciphertext byte has
    # been read, the decrypter has flushed any buffered tail and the
    # authentication code has been verified. Checking before finalization
    # would (for example) wrongly report an empty AES entry at EOF without
    # ever validating its integrity.
    def eof?
      @buffer.empty? && input_finished? && @integrity_verified
    end

    def input_finished?
      !@bytes_remaining.positive?
    end

    def produce_input
      chunk_size = [@bytes_remaining, CHUNK_SIZE].min
      return ''.b unless chunk_size.positive?

      ciphertext = read_exactly(chunk_size)
      @bytes_remaining -= ciphertext.bytesize
      @decrypter.decrypt(ciphertext)
    end

    # The underlying IO is allowed to return fewer bytes than requested on a
    # single call (a "short read"), so keep reading until the full amount is
    # available. Running out of bytes here means the entry is truncated -
    # that is a fault, not a normal end of stream.
    def read_exactly(length)
      data = +''.b
      while data.bytesize < length
        chunk = @io.read(length - data.bytesize)
        raise Error, 'Unexpected end of encrypted stream' if chunk.nil? || chunk.empty?

        data << chunk
      end
      data
    end

    # Feeds the decrypter its buffered final partial block (if any) and then
    # verifies the authentication code that trails the ciphertext. The
    # authentication code is never part of the ciphertext, so it is only
    # touched here, after all `compressed_size` bytes have been consumed.
    def finish_input!
      return if @integrity_verified

      @buffer << @decrypter.finalize unless @finalized
      @finalized = true
      @decrypter.check_integrity!(@io)
      @integrity_verified = true
    end
  end
end
