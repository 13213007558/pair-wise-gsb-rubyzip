# frozen_string_literal: true

require_relative 'unicode'

module Zip
  # Info-ZIP "Unicode Comment" extra field (0x6375): the UTF-8 version of an
  # entry comment whose primary comment bytes use a legacy encoding. The
  # specification only permits this field in the central directory.
  class ExtraField::UnicodeComment < ExtraField::Unicode # :nodoc:
    HEADER_ID = 'uc'
    register_map

    def to_local_bin
      +''
    end
  end
end
