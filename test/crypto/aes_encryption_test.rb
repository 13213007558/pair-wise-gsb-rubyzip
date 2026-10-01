# frozen_string_literal: true

require_relative '../test_helper'
require 'securerandom'
require 'stringio'

class AESDecrypterTest < Minitest::Test
  def setup
    @decrypter256 = ::Zip::AESDecrypter.new('password', ::Zip::AESEncryption::STRENGTH_256_BIT)
    @decrypter128 = ::Zip::AESDecrypter.new('password', ::Zip::AESEncryption::STRENGTH_128_BIT)
  end

  def test_header_bytesize
    assert_equal 18, @decrypter256.header_bytesize
  end

  def test_gp_flags
    assert_equal 1, @decrypter256.gp_flags
  end

  def test_decrypt_aes256
    header = [125, 138, 163, 42, 19, 1, 155, 66, 203, 174, 183, 235, 197, 122, 232, 68, 252, 225].pack('C*')
    @decrypter256.reset!(header)
    # The plaintext is only a single byte, so it is held back as a partial
    # final block and is only emitted by `finalize`.
    assert_equal '', @decrypter256.decrypt([161].pack('C'))
    assert_equal 'a', @decrypter256.finalize
  end

  def test_decrypt_aes128
    header = [127, 254, 117, 113, 255, 209, 171, 131, 179, 106].pack('C*')
    @decrypter128.reset!(header)
    # Three bytes is a partial block, so `decrypt` produces nothing until the
    # stream is finalized.
    assert_equal '', @decrypter128.decrypt([34, 33, 106].pack('C*'))
    assert_equal [75, 4, 0].pack('C*'), @decrypter128.finalize
  end

  def test_reset!
    header = [125, 138, 163, 42, 19, 1, 155, 66, 203, 174, 183, 235, 197, 122, 232, 68, 252, 225].pack('C*')
    @decrypter256.reset!(header)
    @decrypter256.decrypt([161].pack('C'))
    assert_equal 'a', @decrypter256.finalize

    header = [118, 221, 166, 27, 165, 141, 24, 122, 227, 197, 52, 135, 222, 67, 221, 92, 231, 117].pack('C*')
    @decrypter256.reset!(header)
    @decrypter256.decrypt([135].pack('C'))
    assert_equal 'b', @decrypter256.finalize
  end
end

class AESEncrypterTest < Minitest::Test
  STRENGTHS = [
    Zip::AESEncryption::STRENGTH_128_BIT,
    Zip::AESEncryption::STRENGTH_192_BIT,
    Zip::AESEncryption::STRENGTH_256_BIT
  ].freeze

  def setup
    @password = 'password'
  end

  def test_header_bytesize
    encrypter = Zip::AESEncrypter.new(@password, Zip::AESEncryption::STRENGTH_256_BIT)
    encrypter.reset!
    assert_equal 18, encrypter.header_bytesize
    assert_equal 18, encrypter.header('ignored').bytesize
  end

  def test_gp_flags
    encrypter = Zip::AESEncrypter.new(@password, Zip::AESEncryption::STRENGTH_256_BIT)
    assert_equal 1, encrypter.gp_flags
  end

  def test_data_descriptor_and_crc_are_suppressed
    encrypter = Zip::AESEncrypter.new(@password, Zip::AESEncryption::STRENGTH_256_BIT)
    assert_equal '', encrypter.data_descriptor(12_345, 100, 100)
    assert_equal 0, encrypter.crc(12_345)
  end

  def test_reset_generates_a_fresh_salt_each_time
    encrypter = Zip::AESEncrypter.new(@password, Zip::AESEncryption::STRENGTH_256_BIT)

    encrypter.reset!
    first_header = encrypter.header('ignored')

    encrypter.reset!
    second_header = encrypter.header('ignored')

    refute_equal first_header, second_header
  end

  # `trailer` returns whatever ciphertext was still buffered (a final,
  # not-yet-block-aligned remainder) followed by the 10-byte authentication
  # code, since that's what `OutputStream` needs to be able to just append
  # it straight onto the output (see `Zip::OutputStream#finalize_current_entry`).
  # These tests split it back into its two parts.
  def split_trailer(trailer)
    auth_length = Zip::AESEncryption::AUTHENTICATION_CODE_LENGTH
    [trailer[0...-auth_length], trailer[-auth_length..]]
  end

  def test_encrypt_decrypt_round_trip
    plaintext = 'the quick brown fox jumps over the lazy dog' * 100

    STRENGTHS.each do |strength|
      header, ciphertext, auth_code = encrypt(plaintext, strength)

      decrypter = Zip::AESDecrypter.new(@password, strength)
      decrypter.reset!(header)
      decrypted = decrypter.decrypt(ciphertext) + decrypter.finalize
      decrypter.check_integrity!(StringIO.new(auth_code))

      assert_equal plaintext, decrypted
    end
  end

  # Chunk sizes are deliberately *not* multiples of the 16-byte block size,
  # and don't evenly divide the plaintext either - matching how `Deflater`
  # calls `encrypt` with whatever, arbitrarily sized buffer zlib happens to
  # have flushed. This is the scenario that originally broke on JRuby: the
  # cipher must only ever be run over whole blocks internally, buffering any
  # trailing partial block until it's completed by the next chunk (or
  # flushed by `trailer`), regardless of how the caller chunks its writes.
  def test_encrypt_decrypt_round_trip_in_chunks
    plaintext = SecureRandom.random_bytes(100_003)

    header, ciphertext, auth_code =
      encrypt(plaintext, Zip::AESEncryption::STRENGTH_256_BIT, 4097)

    decrypted = decrypt_in_chunks(header, ciphertext, auth_code,
                                  Zip::AESEncryption::STRENGTH_256_BIT, 32_768)

    assert_equal plaintext, decrypted
  end

  # Regression: decrypting a partial CTR block by itself used to reset the
  # counter for each call, so feeding the same ciphertext 1 or 7 bytes at a
  # time produced different (wrong) plaintext while the HMAC still matched.
  # The plaintext must be byte-identical to a whole-stream decrypt no matter
  # how the ciphertext is chunked, including sizes that cross 16-byte block
  # boundaries and an alternating pattern.
  def test_decrypted_output_is_independent_of_chunking
    plaintext = SecureRandom.random_bytes(10_000)

    STRENGTHS.each do |strength|
      header, ciphertext, auth_code = encrypt(plaintext, strength)
      reference = decrypt_whole(header, ciphertext, auth_code, strength)
      assert_equal plaintext, reference

      [1, 7, 16, 31, [1, 7, 31, 16, 3]].each do |chunk_size|
        decrypted = decrypt_in_chunks(header, ciphertext, auth_code,
                                      strength, chunk_size)
        assert_equal reference, decrypted,
                     "decryption differs for chunking #{chunk_size.inspect}"
      end
    end
  end

  def test_decrypt_chunking_covers_block_boundaries_and_final_partial_block
    # 47 bytes spans three 16-byte blocks with 15 bytes left over.
    plaintext = SecureRandom.random_bytes(47)
    header, ciphertext, auth_code =
      encrypt(plaintext, Zip::AESEncryption::STRENGTH_256_BIT)

    # Feeding 16 bytes at a time leaves the final 15-byte partial block to be
    # emitted by `finalize`.
    decrypter = Zip::AESDecrypter.new(@password, Zip::AESEncryption::STRENGTH_256_BIT)
    decrypter.reset!(header)
    decrypted = +''.b
    0.step(by: 16, to: ciphertext.bytesize - 1) do |offset|
      decrypted << decrypter.decrypt(ciphertext.byteslice(offset, 16))
    end
    assert_equal plaintext.bytesize - 15, decrypted.bytesize
    decrypted << decrypter.finalize
    decrypter.check_integrity!(StringIO.new(auth_code))
    assert_equal plaintext, decrypted
  end

  def test_finalize_with_no_ciphertext_returns_empty_string
    decrypter = Zip::AESDecrypter.new(@password, Zip::AESEncryption::STRENGTH_256_BIT)
    header, = encrypt('', Zip::AESEncryption::STRENGTH_256_BIT)
    decrypter.reset!(header)
    assert_equal ''.b, decrypter.finalize
  end

  def test_decrypt_with_wrong_password_raises
    encrypter = Zip::AESEncrypter.new(@password, Zip::AESEncryption::STRENGTH_256_BIT)
    encrypter.reset!
    header = encrypter.header('ignored')
    encrypter.encrypt('some data')

    decrypter = Zip::AESDecrypter.new('wrong_password', Zip::AESEncryption::STRENGTH_256_BIT)
    error = assert_raises(Zip::Error) { decrypter.reset!(header) }
    assert_equal 'Bad password', error.message
  end

  def test_tampered_ciphertext_fails_integrity_check
    encrypter = Zip::AESEncrypter.new(@password, Zip::AESEncryption::STRENGTH_256_BIT)
    encrypter.reset!
    header = encrypter.header('ignored')
    ciphertext = encrypter.encrypt('some secret data')
    leftover, auth_code = split_trailer(encrypter.trailer)
    ciphertext << leftover

    tampered = ciphertext.dup
    tampered[0] = (tampered.getbyte(0) ^ 0xFF).chr

    decrypter = Zip::AESDecrypter.new(@password, Zip::AESEncryption::STRENGTH_256_BIT)
    decrypter.reset!(header)
    decrypter.decrypt(tampered)
    decrypter.finalize
    error = assert_raises(Zip::Error) { decrypter.check_integrity!(StringIO.new(auth_code)) }
    assert_equal 'Integrity fault', error.message
  end

  def test_truncated_authentication_code_fails_integrity_check
    header, ciphertext, auth_code =
      encrypt('some secret data', Zip::AESEncryption::STRENGTH_256_BIT)

    decrypter = Zip::AESDecrypter.new(@password, Zip::AESEncryption::STRENGTH_256_BIT)
    decrypter.reset!(header)
    decrypter.decrypt(ciphertext)
    decrypter.finalize
    error = assert_raises(Zip::Error) do
      decrypter.check_integrity!(StringIO.new(auth_code[0...3]))
    end
    assert_equal 'Integrity fault', error.message
  end

  private

  # Produces a fixed (header, ciphertext, authentication code) triple for
  # `plaintext`, encrypting in `chunk_size` chunks to exercise the encrypter
  # buffering logic too.
  def encrypt(plaintext, strength, chunk_size = nil)
    encrypter = Zip::AESEncrypter.new(@password, strength)
    encrypter.reset!
    header = encrypter.header('ignored')

    ciphertext = +''.b
    if chunk_size
      plaintext.bytes.each_slice(chunk_size) do |chunk|
        ciphertext << encrypter.encrypt(chunk.pack('C*'))
      end
    else
      ciphertext << encrypter.encrypt(plaintext)
    end
    leftover, auth_code = split_trailer(encrypter.trailer)
    ciphertext << leftover

    [header, ciphertext, auth_code]
  end

  def decrypt_whole(header, ciphertext, auth_code, strength)
    decrypter = Zip::AESDecrypter.new(@password, strength)
    decrypter.reset!(header)
    decrypted = decrypter.decrypt(ciphertext) + decrypter.finalize
    decrypter.check_integrity!(StringIO.new(auth_code))
    decrypted
  end

  # Feeds `chunk_size` bytes (or the array repeated as alternating sizes) of
  # ciphertext at a time and reassembles the plaintext.
  def decrypt_in_chunks(header, ciphertext, auth_code, strength, chunk_size)
    sizes = chunk_size.is_a?(Array) ? chunk_size.cycle : nil
    decrypter = Zip::AESDecrypter.new(@password, strength)
    decrypter.reset!(header)
    decrypted = +''.b
    offset = 0
    while offset < ciphertext.bytesize
      length = sizes ? sizes.next : chunk_size
      decrypted << decrypter.decrypt(ciphertext.byteslice(offset, length).to_s)
      offset += length
    end
    decrypted << decrypter.finalize
    decrypter.check_integrity!(StringIO.new(auth_code))
    decrypted
  end
end
