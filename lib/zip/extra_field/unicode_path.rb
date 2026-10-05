# frozen_string_literal: true

module Zip
  # Info-ZIP Unicode Path Extra Field (0x7075). Carries a UTF-8 version of
  # the entry name, along with a CRC32 of the bytes stored in the standard
  # name field, so that readers can verify the two still correspond before
  # trusting the UTF-8 version.
  class ExtraField::UnicodePath < ExtraField::Generic
    VERSION = 1

    HEADER_ID = ['7075'].pack('H*')
    register_map

    attr_reader :version, :name_crc, :name

    def initialize(binstr = nil)
      @version  = nil
      @name_crc = nil
      @name     = nil
      merge(binstr) if binstr
    end

    def merge(binstr)
      return if binstr.empty?

      size, content = initial_parse(binstr)
      return if !size || size < 5

      @version, @name_crc = content.unpack('CV')
      @name = content[5..]
    end

    # The UTF-8 name from this field, if it can be trusted for +raw_name+
    # (the exact bytes from the standard name field): the field version must
    # be understood, the CRC must match those bytes, and the stored name
    # must be valid UTF-8. Returns nil otherwise.
    def name_for(raw_name)
      return unless @version == VERSION && @name && @name_crc == Zlib.crc32(raw_name)

      utf8_name = @name.dup.force_encoding(Encoding::UTF_8)
      utf8_name if utf8_name.valid_encoding?
    end

    def ==(other)
      other.instance_of?(self.class) &&
        other.version == @version &&
        other.name_crc == @name_crc &&
        other.name == @name
    end

    def pack_for_local
      pack_content
    end

    def pack_for_c_dir
      pack_content
    end

    private

    def pack_content
      return +'' unless @version

      [@version, @name_crc].pack('CV') << @name.to_s
    end
  end
end
