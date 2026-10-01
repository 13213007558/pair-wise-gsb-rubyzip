# frozen_string_literal: true

require 'zlib'

module Zip
  # Info-ZIP Unicode extra fields (the "Unicode Path" field, 0x7075, and the
  # "Unicode Comment" field, 0x6375).
  #
  # These carry a UTF-8 copy of a field whose primary (header) bytes use a
  # legacy, local encoding with the language encoding flag (EFS) clear. A
  # record stores:
  #
  # - a one byte version (only +1+ is understood),
  # - the CRC32 of the primary field bytes as they appear in the *same*
  #   header the extra field was read from (the local header or the central
  #   directory entry),
  # - the UTF-8 field bytes.
  #
  # A record may only be used in place of the primary field when both the
  # version and the CRC match; anything else is retained verbatim so it can
  # be rewritten without loss, but it is never trusted.
  class ExtraField::Unicode < ExtraField::Generic # :nodoc:
    # The only version of the record layout that is understood.
    SUPPORTED_VERSION = 1

    # A single record as read from (or written to) one kind of header.
    class Record
      attr_reader :version, :crc, :value, :raw

      def initialize(binstr, primary_bytes)
        @raw = binstr.b.dup
        @primary_bytes = primary_bytes
        @version = nil
        @crc = nil
        @value = nil
        parse
      end

      # Pack a fresh, valid version 1 record into its on-disk form.
      def self.pack_record(header_id, value, primary_bytes)
        body = [SUPPORTED_VERSION, Zlib.crc32(primary_bytes || +'')].pack('CV')
        body << value.to_s.encode(Encoding::UTF_8).b
        header_id + [body.bytesize].pack('v') + body
      end

      # Can this record override the primary field? The version must be the
      # one we understand, the CRC must match the primary field bytes from the
      # same header, and the UTF-8 data must actually be valid UTF-8.
      def trusted?
        @version == SUPPORTED_VERSION && crc_valid? && @value&.valid_encoding?
      end

      # The complete on-disk representation of this record (id + size + data).
      def to_bin
        @raw
      end

      private

      def parse
        return if @raw.bytesize < 9 # id(2) + size(2) + version(1) + crc(4)

        @version, @crc, field_bytes = @raw.byteslice(4..).unpack('CVa*')
        @value = field_bytes.force_encoding(Encoding::UTF_8)
      end

      def crc_valid?
        !@primary_bytes.nil? && Zlib.crc32(@primary_bytes) == @crc
      end
    end

    def initialize(binstr = nil, local: false, primary_bytes: nil)
      @records = { local: nil, cdir: nil }
      @value = nil
      @value_set = false
      @generated = false
      @pending_primary = nil
      merge(binstr, local: local, primary_bytes: primary_bytes) if binstr
    end

    # The UTF-8 value of the field, but only when a trusted record backs it.
    # Never trust an unknown version, a stale CRC or invalid UTF-8 data.
    def unicode_value(local:)
      record = @records[local ? :local : :cdir]
      record&.trusted? ? record.value : nil
    end

    # Set the UTF-8 value to write. The CRC is calculated from the entry's
    # own primary field bytes when the field is serialized.
    def unicode_value=(value)
      @value = value.to_s.encode(Encoding::UTF_8)
      @value_set = true
      @generated = true
    end

    def merge(binstr, local: false, primary_bytes: nil)
      return if binstr.nil? || binstr.empty?

      size, = initial_parse(binstr)
      return unless size

      record = Record.new(binstr.b.dup, primary_bytes)
      @records[local ? :local : :cdir] = record
      @value ||= record.trusted? ? record.value : nil
    end

    # Called before the enclosing entry serializes this header.
    # +primary_bytes+ are the bytes about to be written to the main field in
    # the same header. +modified+ is true when the entry's field changed.
    def prepare_for_write(primary_bytes, local:, modified: false)
      @pending_primary = primary_bytes
      # A field the user created (or a field carried by a renamed entry) is
      # generated from the primary bytes, unless a UTF-8 value was given
      # explicitly (e.g. a legacy-encoded primary field).
      if @records.values.all?(&:nil?)
        @value ||= primary_bytes.to_s.dup.force_encoding(Encoding::UTF_8)
        @generated = true
      elsif modified && !@value_set
        @value = primary_bytes.to_s.dup.force_encoding(Encoding::UTF_8)
        @generated = true
      end
    end

    def to_local_bin
      pack(local: true)
    end

    def to_c_dir_bin
      pack(local: false)
    end

    # These fields must survive a lossless rewrite: they carry the only
    # UTF-8 representation of a legacy-named entry.
    def suppress?
      false
    end

    private

    def pack(local:)
      record = record_for(local)

      # An untouched, parsed record is echoed byte for byte. If this header
      # never declared the field, the other header's record verifies against
      # the same primary bytes, so it is safe to echo it as-is.
      return record.to_bin if record && !@generated && !@value_set

      primary = @pending_primary || +''
      value =
        if @generated || @value_set
          @value || primary.dup.force_encoding(Encoding::UTF_8)
        elsif record&.trusted?
          record.value
        else
          primary.dup.force_encoding(Encoding::UTF_8)
        end

      Record.pack_record(self.class.const_get(:HEADER_ID), value, primary)
    end

    def record_for(local)
      key = local ? :local : :cdir
      @records[key] || @records[local ? :cdir : :local]
    end
  end
end
