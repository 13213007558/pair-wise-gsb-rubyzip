# frozen_string_literal: true

require_relative 'generic'

module Zip
  # Common behaviour for the Info-ZIP "Unicode Path" (0x7075) and
  # "Unicode Comment" (0x6375) extra fields.
  #
  # Both fields share the same layout:
  #
  #   header ID       2 bytes  (0x7075 / 0x6375)
  #   data size       2 bytes
  #   version         1 byte   (only version 1 is defined)
  #   name CRC32      4 bytes  CRC32 of the value stored in the main header
  #   unicode value   N bytes  UTF-8, NUL terminated
  #
  # The CRC ties the unicode value to the non-unicode bytes in the main
  # header: if it does not match then the field is stale (the entry was
  # renamed after the field was generated) and must not be trusted.
  #
  # A field can be declared in the local header, the central directory or
  # both, and the two declarations are independent, so each is kept in its
  # own record.
  class ExtraField::Unicode < ExtraField::Generic # :nodoc:
    VERSION = 1

    # This field carries independent declarations in the local header and
    # the central directory.
    def self.local_aware?
      true
    end

    # One declaration of the field (local header or central directory).
    class Record
      attr_reader :version, :crc, :unicode_bytes, :raw

      def initialize
        @version = nil
        @crc = nil
        @unicode_bytes = +''.b
        @raw = nil # raw record body, kept verbatim for lossless rewrite
      end

      def present?
        !@raw.nil?
      end

      def version1?
        @version == VERSION
      end

      # Parse the record body (everything after the 4-byte extra header).
      def parse(content)
        @version       = content.getbyte(0)
        @crc           = content.bytesize >= 5 ? content[1, 4].unpack1('V') : nil
        @unicode_bytes =
          if content.bytesize > 5
            content[5..].to_s.sub(/\x00\z/, '').b
          else
            +''.b
          end
        @raw = content.dup.b
      end

      # Build a fresh version-1 record. `primary_bytes` is the value in the
      # main header the CRC is calculated over.
      def build(unicode_name, primary_bytes)
        @version       = VERSION
        @crc           = Zlib.crc32(primary_bytes.b)
        @unicode_bytes = unicode_name.to_s.encode('UTF-8').b
        @raw           = [VERSION, @crc].pack('CV') + @unicode_bytes + "\x00".b
      end

      def crc_matches?(primary_bytes)
        !@crc.nil? && @crc == Zlib.crc32(primary_bytes.b)
      end

      def valid_utf8?
        return false if @unicode_bytes.empty?

        @unicode_bytes.dup.force_encoding('UTF-8').valid_encoding?
      end

      # Is this record trustworthy for the given main-header value?
      def valid?(primary_bytes)
        version1? && crc_matches?(primary_bytes) && valid_utf8?
      end

      def unicode_name
        @unicode_bytes.dup.force_encoding('UTF-8')
      end
    end

    def initialize(binstr = nil, local: false)
      @local_record = nil
      @cdir_record  = nil
      merge(binstr, local: local) if binstr
    end

    def merge(binstr, local: false)
      return if binstr.nil? || binstr.empty?

      size, content = initial_parse(binstr)
      return unless size && content

      record(local).parse(content)
    end

    def local_record
      @local_record ||= Record.new
    end

    def cdir_record
      @cdir_record ||= Record.new
    end

    def record(local)
      local ? local_record : cdir_record
    end

    def present?(local: nil)
      if local.nil?
        @local_record&.present? || @cdir_record&.present?
      else
        record(local).present?
      end
    end

    # The trustworthy unicode value for this location, or nil if the
    # record is absent/invalid for `primary_bytes`.
    def valid_name(local:, primary_bytes:)
      rec = record(local)
      rec.present? && rec.valid?(primary_bytes) ? rec.unicode_name : nil
    end

    # Make sure a record exists to be serialised at this location,
    # mirroring the other declaration or regenerating a version-1 record.
    def prepare(local:, primary_bytes:, unicode_name:, unchanged:)
      rec   = record(local)
      other = record(!local)

      if rec.present? && unchanged
        rec
      elsif !rec.present? && other.present? && unchanged &&
            other.version1? && other.crc_matches?(primary_bytes)
        # Copy the still-valid declaration verbatim.
        rec.parse(other.raw)
      elsif unicode_name
        rec.build(unicode_name, primary_bytes)
      end
    end

    def ==(other)
      other.is_a?(self.class) &&
        to_local_bin == other.to_local_bin &&
        to_c_dir_bin == other.to_c_dir_bin
    end

    # These fields are only meaningful while they are consistent, so they
    # are safe to drop when extra fields are being suppressed.
    def suppress?
      true
    end

    def to_local_bin
      pack(@local_record)
    end

    def to_c_dir_bin
      pack(@cdir_record)
    end

    private

    def pack(rec)
      return +''.b unless rec&.present?

      body = rec.raw
      (self.class.const_get(:HEADER_ID) + [body.bytesize].pack('v') + body).b
    end
  end
end