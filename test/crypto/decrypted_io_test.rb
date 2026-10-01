# frozen_string_literal: true

require_relative '../test_helper'
require 'securerandom'

class DecryptedIoTest < Minitest::Test
  PASSWORD = 'password'
  STRENGTH = Zip::AESEncryption::STRENGTH_256_BIT
  AUTH_CODE_LENGTH = Zip::AESEncryption::AUTHENTICATION_CODE_LENGTH

  # An IO that never returns more than `max` bytes per read call,
  # simulating the short reads a pipe or socket may produce.
  class ShortReadIO < StringIO
    def initialize(string, max)
      super(string)
      @max = max
    end

    def read(len = nil, outbuf = nil)
      len &&= [len, @max].min
      super
    end
  end

  # A decrypter that records how many bytes of ciphertext it was fed.
  class RecordingDecrypter < Zip::AESDecrypter
    attr_reader :decrypted_bytesize

    def reset!(header)
      @decrypted_bytesize = 0
      super
    end

    def decrypt(data)
      @decrypted_bytesize += data.bytesize
      super
    end
  end

  def setup
    # 4099 bytes: spans many 16-byte cipher blocks (and the 32 KiB read
    # chunking of DecryptedIo is not exercised here, but block boundaries
    # are) and ends with a final partial block of 3 bytes.
    @plaintext = SecureRandom.random_bytes(4099)

    encrypter = Zip::AESEncrypter.new(PASSWORD, STRENGTH)
    encrypter.reset!
    @header = encrypter.header('ignored')
    @ciphertext = encrypter.encrypt(@plaintext)
    trailer = encrypter.trailer
    @ciphertext << trailer[0...-AUTH_CODE_LENGTH]
    @auth_code = trailer[-AUTH_CODE_LENGTH..]
  end

  def decrypted_io(io, compressed_size: @ciphertext.bytesize)
    decrypter = Zip::AESDecrypter.new(PASSWORD, STRENGTH)
    decrypter.reset!(@header)
    Zip::DecryptedIo.new(io, decrypter, compressed_size)
  end

  def string_io
    StringIO.new(@ciphertext + @auth_code)
  end

  def read_in_chunks(io, maxlens)
    decrypted = +''.b
    maxlens.cycle do |maxlen|
      chunk = io.read(maxlen)
      break if chunk.nil?

      decrypted << chunk
    end
    decrypted
  end

  def test_read_returns_the_whole_plaintext
    assert_equal @plaintext, decrypted_io(string_io).read
  end

  def test_read_in_chunks_matches_whole_read
    whole = decrypted_io(string_io).read

    # Chunk sizes crossing 16-byte block boundaries, plus alternating lengths.
    [[1], [7], [16], [31], [3, 17, 1, 64, 8]].each do |maxlens|
      decrypted = read_in_chunks(decrypted_io(string_io), maxlens)
      assert_equal whole, decrypted, "read chunk sizes #{maxlens.inspect}"
    end
  end

  def test_read_handles_short_reads_from_the_underlying_io
    [1, 5, 16, 100].each do |max|
      io = ShortReadIO.new(@ciphertext + @auth_code, max)
      assert_equal @plaintext, decrypted_io(io).read, "underlying reads capped at #{max} bytes"
    end
  end

  def test_read_with_short_reads_and_small_maxlen
    io = ShortReadIO.new(@ciphertext + @auth_code, 5)
    assert_equal @plaintext, read_in_chunks(decrypted_io(io), [7])
  end

  def test_empty_entry
    encrypter = Zip::AESEncrypter.new(PASSWORD, STRENGTH)
    encrypter.reset!
    header = encrypter.header('ignored')
    ciphertext = +encrypter.encrypt('')
    trailer = encrypter.trailer
    ciphertext << trailer[0...-AUTH_CODE_LENGTH]
    auth_code = trailer[-AUTH_CODE_LENGTH..]
    assert_empty ciphertext

    decrypter = Zip::AESDecrypter.new(PASSWORD, STRENGTH)
    decrypter.reset!(header)
    io = Zip::DecryptedIo.new(StringIO.new(ciphertext + auth_code), decrypter, 0)

    assert_equal '', io.read
    assert_nil io.read(7)
    assert_equal '', io.read
  end

  def test_repeated_reads_to_eof
    io = decrypted_io(string_io)

    decrypted = +''.b
    while (chunk = io.read(7))
      decrypted << chunk
    end
    assert_equal @plaintext, decrypted

    # Further reads at EOF keep returning nil (or '' without a length),
    # and must not raise or re-check integrity.
    assert_nil io.read(7)
    assert_nil io.read(1)
    assert_equal '', io.read
    assert_equal '', io.read(0)
  end

  def test_truncated_ciphertext_raises_instead_of_ending_normally
    truncated = @ciphertext[0...100]
    io = decrypted_io(StringIO.new(truncated))

    error = assert_raises(Zip::Error) { io.read }
    assert_equal 'Truncated encrypted data', error.message
  end

  def test_truncated_ciphertext_raises_mid_stream
    # An entry larger than DecryptedIo::CHUNK_SIZE, so the first chunk is
    # read successfully and the truncation is only hit on a later read.
    plaintext = SecureRandom.random_bytes(40_000)
    encrypter = Zip::AESEncrypter.new(PASSWORD, STRENGTH)
    encrypter.reset!
    header = encrypter.header('ignored')
    ciphertext = encrypter.encrypt(plaintext)
    ciphertext << encrypter.trailer[0...-AUTH_CODE_LENGTH]

    decrypter = Zip::AESDecrypter.new(PASSWORD, STRENGTH)
    decrypter.reset!(header)
    truncated = ciphertext[0...(Zip::DecryptedIo::CHUNK_SIZE + 100)]
    io = Zip::DecryptedIo.new(StringIO.new(truncated), decrypter, ciphertext.bytesize)

    decrypted = +''.b
    error = assert_raises(Zip::Error) do
      while (chunk = io.read(1024))
        decrypted << chunk
      end
    end
    assert_equal 'Truncated encrypted data', error.message
    assert_equal Zip::DecryptedIo::CHUNK_SIZE, decrypted.bytesize
    assert_equal plaintext[0, decrypted.bytesize], decrypted
  end

  def test_authentication_code_is_not_consumed_as_ciphertext
    recording_decrypter = RecordingDecrypter.new(PASSWORD, STRENGTH)
    recording_decrypter.reset!(@header)
    io = Zip::DecryptedIo.new(string_io, recording_decrypter, @ciphertext.bytesize)

    assert_equal @plaintext, io.read
    # Exactly the ciphertext - no more, no less - was passed to the
    # decrypter; the 10-byte authentication tail was not treated as
    # ciphertext (and the integrity check still passed).
    assert_equal @ciphertext.bytesize, recording_decrypter.decrypted_bytesize
  end

  def test_tampered_ciphertext_fails_integrity_check
    tampered = @ciphertext.dup
    tampered.setbyte(0, tampered.getbyte(0) ^ 0xFF)

    error = assert_raises(Zip::Error) do
      decrypted_io(StringIO.new(tampered + @auth_code)).read
    end
    assert_equal 'Integrity fault', error.message
  end

  def test_tampered_ciphertext_fails_integrity_check_when_read_in_chunks
    tampered = @ciphertext.dup
    tampered.setbyte(2000, tampered.getbyte(2000) ^ 0xFF)

    io = decrypted_io(StringIO.new(tampered + @auth_code))
    error = assert_raises(Zip::Error) { read_in_chunks(io, [7]) }
    assert_equal 'Integrity fault', error.message
  end
end
