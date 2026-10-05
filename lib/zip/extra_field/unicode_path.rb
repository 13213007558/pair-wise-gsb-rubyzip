# frozen_string_literal: true

require_relative 'generic'

module Zip
  # Info-ZIP Unicode Path Extra Field (0x7075).
  #
  # Stores a UTF-8 version of the entry's name alongside a CRC32 of the
  # raw name bytes stored in the entry header. The Unicode name is only
  # considered authoritative when that CRC matches the header's name
  # bytes - otherwise some other tool has likely rewritten the name
  # without updating this field, and it must be ignored.
  class ExtraField::UnicodePath < ExtraField::Generic
    HEADER_ID = 'up'
    register_map

    VERSION = 1

    attr_reader :version, :name_crc32, :name

    def initialize(binstr = nil)
      @version    = VERSION
      @name_crc32 = nil
      @name       = nil
      @raw        = nil
      merge(binstr) if binstr
    end

    def merge(binstr)
      size, content = initial_parse(binstr)
      return unless size && content

      # Keep the unparsed content so that the field round-trips verbatim,
      # even if it turns out to be a version we don't understand.
      @raw = content
      return unless content.bytesize >= 5

      @version    = content.getbyte(0)
      @name_crc32 = content[1, 4].unpack1('V')
      @name       = content[5..] || +''
    end

    # Does the stored CRC32 match the given raw name bytes?
    def crc_valid_for?(raw_name)
      !@name_crc32.nil? && @name_crc32 == ::Zlib.crc32(raw_name)
    end

    # The Unicode name for +raw_name+ (the entry's raw header name bytes),
    # or nil if this field does not apply to that name: the CRC must match
    # and the stored name must be valid UTF-8.
    def name_for(raw_name)
      return nil unless @version == VERSION && @name && crc_valid_for?(raw_name)

      unicode_name = @name.dup.force_encoding(Encoding::UTF_8)
      unicode_name.valid_encoding? ? unicode_name : nil
    end

    def ==(other)
      other.kind_of?(UnicodePath) && to_c_dir_bin == other.to_c_dir_bin
    end

    def pack_for_local
      @raw || +''
    end

    def pack_for_c_dir
      @raw || +''
    end
  end
end
