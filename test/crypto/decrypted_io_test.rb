# frozen_string_literal: true

require_relative '../test_helper'
require 'stringio'

# Exercises `Zip::DecryptedIo` - the IO wrapper around an `AESDecrypter`
# that feeds it ciphertext and verifies the trailing authentication code.
# The plaintext it yields must not depend on how callers choose to size
# their reads, and a truncated or tampered entry must never look like a
# clean end-of-file.
class DecryptedIoTest < Minitest::Test
  PASSWORD = 'password'

  STRENGTHS = [
    Zip::AESEncryption::STRENGTH_128_BIT,
    Zip::AESEncryption::STRENGTH_192_BIT,
    Zip::AESEncryption::STRENGTH_256_BIT
  ].freeze

  # Read lengths deliberately include 1 (smaller than a block), 7 (never
  # block aligned), 16 (exactly one block) and 31 (block plus an odd tail),
  # plus an alternating sequence.
  READ_PATTERNS = [1, 7, 16, 31, [1, 7, 31, 16, 3]].freeze

  # Underlying IO that hands out at most `limit` bytes per `read` call, so
  # every read has to cope with short reads.
  class ShortReadIO
    def initialize(data, limit)
      @io = StringIO.new(data)
      @limit = limit
    end

    def read(length)
      @io.read([length, @limit].min)
    end
  end

  # Underlying IO that alternates between 1 and 2 byte short reads.
  class AlternatingShortReadIO
    SIZES = [1, 2].freeze

    def initialize(data)
      @io = StringIO.new(data)
      @sizes = SIZES.cycle
    end

    def read(length)
      @io.read([length, @sizes.next].min)
    end
  end

  def setup
    @plaintexts = {
      empty:               ''.b,
      single_byte:         'a',
      smaller_than_block:  SecureRandom.random_bytes(15),
      one_block:           SecureRandom.random_bytes(16),
      block_plus_tail:     SecureRandom.random_bytes(17),
      crosses_boundaries:  SecureRandom.random_bytes(10_003),
      two_blocks_minus_one: SecureRandom.random_bytes(31)
    }
  end

  # Builds a fixed (for the duration of one assertion matrix) ciphertext for
  # a plaintext and returns a fresh, reset decrypter plus everything needed
  # to wrap it in a `DecryptedIo`.
  def encrypted(plaintext, strength, encrypt_chunk: 4097)
    encrypter = Zip::AESEncrypter.new(PASSWORD, strength)
    encrypter.reset!
    header = encrypter.header('ignored')

    ciphertext = +''.b
    plaintext.bytes.each_slice(encrypt_chunk) do |chunk|
      ciphertext << encrypter.encrypt(chunk.pack('C*'))
    end
    trailer = encrypter.trailer
    auth_code = trailer[-Zip::AESEncryption::AUTHENTICATION_CODE_LENGTH..]
    ciphertext << trailer[0...-Zip::AESEncryption::AUTHENTICATION_CODE_LENGTH]

    [header, ciphertext, auth_code]
  end

  def decrypter_for(header, strength)
    decrypter = Zip::AESDecrypter.new(PASSWORD, strength)
    decrypter.reset!(header)
    decrypter
  end

  # Drains `io` using the given read pattern (an integer, or an array whose
  # values are cycled) and returns the reassembled bytes.
  def drain(io, pattern)
    sizes = pattern.is_a?(Array) ? pattern.cycle : nil
    result = +''.b
    loop do
      length = sizes ? sizes.next : pattern
      chunk = io.read(length)
      break if chunk.nil?

      result << chunk
    end
    result
  end

  def test_output_is_identical_for_every_read_pattern_and_key_strength
    STRENGTHS.each do |strength|
      @plaintexts.each do |name, plaintext|
        header, ciphertext, auth_code = encrypted(plaintext, strength)

        reference =
          Zip::DecryptedIo.new(
            StringIO.new(ciphertext + auth_code),
            decrypter_for(header, strength),
            ciphertext.bytesize
          ).read
        assert_equal plaintext, reference, "whole-read mismatch for #{name}"

        READ_PATTERNS.each do |pattern|
          # Both with a normal underlying IO and one that short-reads.
          [
            StringIO.new(ciphertext + auth_code),
            ShortReadIO.new(ciphertext + auth_code, 7),
            AlternatingShortReadIO.new(ciphertext + auth_code)
          ].each_with_index do |io, io_kind|
            dio = Zip::DecryptedIo.new(
              io, decrypter_for(header, strength), ciphertext.bytesize
            )
            result = drain(dio, pattern)
            assert_equal reference, result,
                         "mismatch for #{name}, strength #{strength}, " \
                         "pattern #{pattern.inspect}, io kind #{io_kind}"
          end
        end
      end
    end
  end

  def test_read_without_length_returns_everything
    plaintext = SecureRandom.random_bytes(5000)
    header, ciphertext, auth_code =
      encrypted(plaintext, Zip::AESEncryption::STRENGTH_256_BIT)
    dio = Zip::DecryptedIo.new(
      StringIO.new(ciphertext + auth_code),
      decrypter_for(header, Zip::AESEncryption::STRENGTH_256_BIT),
      ciphertext.bytesize
    )
    assert_equal plaintext, dio.read
  end

  def test_empty_entry_is_verified_and_then_reports_eof
    header, ciphertext, auth_code =
      encrypted(''.b, Zip::AESEncryption::STRENGTH_256_BIT)
    assert_equal 0, ciphertext.bytesize

    dio = Zip::DecryptedIo.new(
      StringIO.new(auth_code),
      decrypter_for(header, Zip::AESEncryption::STRENGTH_256_BIT),
      0
    )
    # Reading an empty entry with no length argument verifies integrity and
    # returns an empty string rather than nil.
    assert_equal ''.b, dio.read
    # Repeated length-reads at EOF return nil without re-running anything.
    assert_nil dio.read(1)
    assert_nil dio.read(16)
    assert_nil dio.read(31)
    # A no-argument read at EOF keeps returning ''.
    assert_equal ''.b, dio.read
    assert_equal ''.b, dio.read(0)
  end

  def test_repeated_reads_after_eof_keep_returning_nil_or_empty
    plaintext = SecureRandom.random_bytes(1234)
    header, ciphertext, auth_code =
      encrypted(plaintext, Zip::AESEncryption::STRENGTH_128_BIT)
    dio = Zip::DecryptedIo.new(
      StringIO.new(ciphertext + auth_code),
      decrypter_for(header, Zip::AESEncryption::STRENGTH_128_BIT),
      ciphertext.bytesize
    )

    assert_equal plaintext, drain(dio, 7)
    assert_nil dio.read(8)
    assert_nil dio.read(1)
    assert_equal ''.b, dio.read
  end

  def test_authentication_tail_is_never_returned_as_plaintext
    plaintext = SecureRandom.random_bytes(100)
    header, ciphertext, auth_code =
      encrypted(plaintext, Zip::AESEncryption::STRENGTH_256_BIT)
    dio = Zip::DecryptedIo.new(
      StringIO.new(ciphertext + auth_code),
      decrypter_for(header, Zip::AESEncryption::STRENGTH_256_BIT),
      ciphertext.bytesize
    )
    # Asking for far more than the plaintext length must not swallow the
    # ten authentication bytes into the returned data.
    result = dio.read(10_000)
    assert_equal plaintext.bytesize, result.bytesize
    assert_equal plaintext, result
    assert_nil dio.read(1)
  end

  def test_truncated_ciphertext_is_an_error_not_eof
    plaintext = SecureRandom.random_bytes(100)
    header, ciphertext, _auth_code =
      encrypted(plaintext, Zip::AESEncryption::STRENGTH_256_BIT)
    # The stream ends 50 ciphertext bytes early; the wrapper was still told
    # to expect the full declared length.
    dio = Zip::DecryptedIo.new(
      StringIO.new(ciphertext[0...50]),
      decrypter_for(header, Zip::AESEncryption::STRENGTH_256_BIT),
      ciphertext.bytesize
    )
    error = assert_raises(Zip::Error) { dio.read }
    assert_equal 'Unexpected end of encrypted stream', error.message
  end

  def test_truncated_ciphertext_during_chunked_reads_is_an_error
    plaintext = SecureRandom.random_bytes(100)
    header, ciphertext, _auth_code =
      encrypted(plaintext, Zip::AESEncryption::STRENGTH_256_BIT)
    dio = Zip::DecryptedIo.new(
      ShortReadIO.new(ciphertext[0...60], 3),
      decrypter_for(header, Zip::AESEncryption::STRENGTH_256_BIT),
      ciphertext.bytesize
    )
    assert_raises(Zip::Error) { drain(dio, 7) }
  end

  def test_truncated_authentication_code_fails_integrity
    plaintext = SecureRandom.random_bytes(100)
    header, ciphertext, auth_code =
      encrypted(plaintext, Zip::AESEncryption::STRENGTH_256_BIT)
    dio = Zip::DecryptedIo.new(
      StringIO.new(ciphertext + auth_code[0...3]),
      decrypter_for(header, Zip::AESEncryption::STRENGTH_256_BIT),
      ciphertext.bytesize
    )
    error = assert_raises(Zip::Error) { dio.read }
    assert_equal 'Integrity fault', error.message
  end

  def test_tampered_ciphertext_byte_fails_integrity
    plaintext = SecureRandom.random_bytes(100)
    header, ciphertext, auth_code =
      encrypted(plaintext, Zip::AESEncryption::STRENGTH_192_BIT)
    tampered = ciphertext.dup
    tampered.setbyte(20, tampered.getbyte(20) ^ 0x01)

    # No matter how the (wrong) data is read, the check at the end rejects it.
    [nil, 1, 7, 16, 31, [31, 1, 7]].each do |pattern|
      dio = Zip::DecryptedIo.new(
        StringIO.new(tampered + auth_code),
        decrypter_for(header, Zip::AESEncryption::STRENGTH_192_BIT),
        ciphertext.bytesize
      )
      error = assert_raises(Zip::Error) do
        pattern.nil? ? dio.read : drain(dio, pattern)
      end
      assert_equal 'Integrity fault', error.message
    end
  end

  # End to end through `Zip::InputStream`, including a rewind that rebuilds
  # the decryption pipeline against the same fixed archive.
  def test_input_stream_chunked_reads_rewind_and_eof
    plaintext = SecureRandom.random_bytes(5000)

    encrypted_zip = Zip::OutputStream.write_buffer(
      StringIO.new,
      encrypter: Zip::AESEncrypter.new(
        PASSWORD, Zip::AESEncryption::STRENGTH_256_BIT
      )
    ) do |out|
      out.put_next_entry('secret.bin')
      out.write(plaintext)
    end
    encrypted_zip.rewind

    open_stream(encrypted_zip) do |zis|
      assert_equal 'secret.bin', zis.get_next_entry.name

      seven_bytes_at_a_time = drain(zis, 7)
      assert_equal plaintext, seven_bytes_at_a_time
      assert_nil zis.read(8)
      assert_equal ''.b, zis.read

      # Rewind must reset decryption state so the entry reads identically.
      zis.rewind
      one_byte_at_a_time = drain(zis, 1)
      assert_equal plaintext, one_byte_at_a_time

      zis.rewind
      assert_equal plaintext, zis.read
      assert_nil zis.read(1)
    end
  end

  # The same checks against a real, fixed-on-disk AES archive produced by
  # another tool, so the ciphertext genuinely never changes between runs.
  def test_fixture_archive_chunked_reads_match_whole_read
    data_dir = File.join(__dir__, '..', 'data')
    zip_path = File.join(data_dir, 'zip-aes-256.zip')
    expected = File.binread(File.join(data_dir, 'zip-aes-256.txt'))

    READ_PATTERNS.each do |pattern|
      Zip::InputStream.open(
        zip_path,
        decrypter: Zip::AESDecrypter.new(
          'password', Zip::AESEncryption::STRENGTH_256_BIT
        )
      ) do |zis|
        zis.get_next_entry
        assert_equal expected, drain(zis, pattern),
                     "fixture mismatch with pattern #{pattern.inspect}"
      end
    end
  end

  private

  def open_stream(io)
    zis = Zip::InputStream.open(
      io,
      decrypter: Zip::AESDecrypter.new(
        PASSWORD, Zip::AESEncryption::STRENGTH_256_BIT
      )
    )
    return zis unless block_given?

    begin
      yield zis
    ensure
      zis.close
    end
  end
end
