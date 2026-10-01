# frozen_string_literal: true

require_relative 'unicode'

module Zip
  # Info-ZIP Unicode Path extra field (0x7075). Holds the UTF-8 version of an
  # entry name whose main-header bytes use a local (e.g. CP437/GBK) encoding.
  class ExtraField::UnicodePath < ExtraField::Unicode # :nodoc:
    HEADER_ID = [0x7075].pack('v')
    register_map
  end
end
