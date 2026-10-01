# frozen_string_literal: true

require_relative 'unicode'

module Zip
  # Info-ZIP Unicode Comment extra field (0x6375). Holds the UTF-8 version of
  # an entry comment whose main-header bytes use a local encoding.
  class ExtraField::UnicodeComment < ExtraField::Unicode # :nodoc:
    HEADER_ID = [0x6375].pack('v')
    register_map
  end
end
