# frozen_string_literal: true

require 'securerandom'

module Zip
  module AESEncryption # :nodoc:
    VERIFIER_LENGTH = 2
    BLOCK_SIZE = 16
    AUTHENTICATION_CODE_LENGTH = 10

    VERSION_AE_1 = 0x01
    VERSION_AE_2 = 0x02

    VERSIONS = [
      VERSION_AE_1,
      VERSION_AE_2
    ].freeze

    STRENGTH_128_BIT = 0x01
    STRENGTH_192_BIT = 0x02
    STRENGTH_256_BIT = 0x03

    STRENGTHS = [
      STRENGTH_128_BIT,
      STRENGTH_192_BIT,
      STRENGTH_256_BIT
    ].freeze

    BITS = {
      STRENGTH_128_BIT => 128,
      STRENGTH_192_BIT => 192,
      STRENGTH_256_BIT => 256
    }.freeze

    KEY_LENGTHS = {
      STRENGTH_128_BIT => 16,
      STRENGTH_192_BIT => 24,
      STRENGTH_256_BIT => 32
    }.freeze

    SALT_LENGTHS = {
      STRENGTH_128_BIT => 8,
      STRENGTH_192_BIT => 12,
      STRENGTH_256_BIT => 16
    }.freeze

    def initialize(password, strength)
      # Loaded here rather than at the top of the file so that `require 'zip'`
      # does not pull in openssl. Only AES-encrypted archives need it, and it
      # is the single largest cost of loading this library.
      require 'openssl'

      @password = password
      @strength = strength
      @bits = BITS[@strength]
      @key_length = KEY_LENGTHS[@strength]
      @salt_length = SALT_LENGTHS[@strength]
    end

    def header_bytesize
      @salt_length + VERIFIER_LENGTH
    end

    def gp_flags
      0x0001
    end

    private

    # Derive the encryption key, HMAC key and password-verification value
    # from the password and a salt, as specified by the WinZip AES format.
    def derive_keys(salt)
      raise Error, "Unsupported encryption AES-#{@bits}" unless STRENGTHS.include? @strength

      key_material = OpenSSL::KDF.pbkdf2_hmac(
        @password,
        salt:       salt,
        iterations: 1000,
        length:     (2 * @key_length) + VERIFIER_LENGTH,
        hash:       'sha1'
      )

      [
        key_material[0...@key_length],
        key_material[@key_length...(2 * @key_length)],
        key_material[-VERIFIER_LENGTH..]
      ]
    end
  end

  class AESEncrypter < Encrypter # :nodoc:
    include AESEncryption

    def header(_mtime)
      @salt + @pwd_verify
    end

    # `Deflater`/`PassThruCompressor` call this with whatever, arbitrarily
    # sized (and not necessarily block-aligned) buffer they happen to have
    # flushed, potentially many times per entry. Only whole 16-byte blocks
    # are actually run through the cipher here; any trailing partial block
    # is buffered in `@pending` until either more data completes it or
    # `trailer` forces the final flush. This keeps the CTR counter aligned
    # with the true byte offset in the plaintext stream regardless of how
    # callers happen to chunk their writes.
    def encrypt(data)
      @pending << data
      encrypted_data = encrypt_blocks
      @hmac.update(encrypted_data)
      encrypted_data
    end

    def data_descriptor(*)
      ''
    end

    def trailer
      encrypted_data = encrypt_blocks(final: true)
      @hmac.update(encrypted_data)
      encrypted_data + @hmac.digest[0...AUTHENTICATION_CODE_LENGTH]
    end

    def crc(_computed_crc)
      0
    end

    def reset!
      @salt = SecureRandom.random_bytes(@salt_length)
      enc_key, enc_hmac_key, @pwd_verify = derive_keys(@salt)

      @counter = 0
      @pending = +''.b
      @cipher = OpenSSL::Cipher::AES.new(@bits, :CTR)
      @cipher.encrypt
      @cipher.key = enc_key
      @hmac = OpenSSL::HMAC.new(enc_hmac_key, OpenSSL::Digest.new('SHA1'))
    end

    def prepare_entry(entry)
      entry.prep_aes_extra(AESEncryption::VERSION_AE_2, @strength)
    end

    private

    def encrypt_blocks(final: false)
      length = final ? @pending.bytesize : (@pending.bytesize / BLOCK_SIZE) * BLOCK_SIZE
      return '' if length.zero?

      data = @pending.slice!(0, length)
      encrypted_data = +''.b
      offset = 0

      while offset < data.bytesize
        @cipher.iv = [@counter + 1].pack('Vx12')
        encrypted_data << @cipher.update(data[offset, BLOCK_SIZE])
        @counter += 1
        offset += BLOCK_SIZE
      end

      # JRuby requires finalization of the cipher when the last block fed to
      # it is a partial one. This is a bug, as noted in
      # jruby/jruby-openssl#182 and jruby/jruby-openssl#183.
      encrypted_data << @cipher.final if final && defined?(JRUBY_VERSION)
      encrypted_data
    end
  end

  class AESDecrypter < Decrypter # :nodoc:
    include AESEncryption

    # The ciphertext may arrive in arbitrary chunks (1 byte, 7 bytes,
    # anything) that bear no relation to the 16-byte CTR block size. The
    # CTR counter tracks the *absolute* byte offset in the stream, so only
    # whole blocks are run through the cipher here and any trailing partial
    # block is buffered until more ciphertext arrives - mirroring how
    # `AESEncrypter#encrypt` does the same on the write side. Decrypting a
    # partial block on its own would wrongly re-use counter value 1 and
    # corrupt the plaintext.
    def decrypt(encrypted_data)
      @hmac.update(encrypted_data)
      @pending ||= +''.b
      @pending << encrypted_data

      decrypted_data = +''.b
      while @pending.bytesize >= BLOCK_SIZE
        block = @pending.slice!(0, BLOCK_SIZE)
        @cipher.iv = [@counter + 1].pack('Vx12')
        decrypted_data << @cipher.update(block)
        @counter += 1
      end

      decrypted_data
    end

    # Flushes the final, not-block-aligned ciphertext bytes. WinZip AES
    # leaves the last CTR block partial, so this must run once, after the
    # last ciphertext byte has been fed in and before the authentication
    # code is checked. Returns the tail of the plaintext.
    def finalize
      decrypted_data = +''.b
      unless @pending.nil? || @pending.empty?
        @cipher.iv = [@counter + 1].pack('Vx12')
        decrypted_data << @cipher.update(@pending)
        @pending.clear
      end

      # JRuby requires finalization of the cipher when the last block fed to
      # it is a partial one. This is a bug, as noted in
      # jruby/jruby-openssl#182 and jruby/jruby-openssl#183.
      decrypted_data << @cipher.final if defined?(JRUBY_VERSION)
      decrypted_data
    end

    def reset!(header)
      salt = header[0...@salt_length]
      pwd_verify = header[-VERIFIER_LENGTH..]
      enc_key, enc_hmac_key, enc_pwd_verify = derive_keys(salt)

      raise Error, 'Bad password' if enc_pwd_verify != pwd_verify

      @counter = 0
      @pending = +''.b
      @cipher = OpenSSL::Cipher::AES.new(@bits, :CTR)
      @cipher.decrypt
      @cipher.key = enc_key
      @hmac = OpenSSL::HMAC.new(enc_hmac_key, OpenSSL::Digest.new('SHA1'))
    end

    def check_integrity!(io)
      auth_code = read_exactly(io, AUTHENTICATION_CODE_LENGTH)
      if auth_code.bytesize != AUTHENTICATION_CODE_LENGTH ||
         @hmac.digest[0...AUTHENTICATION_CODE_LENGTH] != auth_code
        raise Error, 'Integrity fault'
      end
    end

    private

    # Reads exactly `length` bytes, tolerating short reads from the
    # underlying IO. Returns fewer bytes only if the stream is exhausted,
    # which (for the trailing authentication code) means truncation.
    def read_exactly(io, length)
      data = +''.b
      while data.bytesize < length
        chunk = io.read(length - data.bytesize)
        break if chunk.nil? || chunk.empty?

        data << chunk
      end
      data
    end
  end
end
