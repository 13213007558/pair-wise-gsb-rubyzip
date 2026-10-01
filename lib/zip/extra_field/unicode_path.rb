# frozen_string_literal: true

require_relative 'unicode'

module Zip
  # Info-ZIP "Unicode Path" extra field (0x7075): the UTF-8 version of an
  # entry name whose primary name bytes use a legacy encoding.
  class ExtraField::UnicodePath < ExtraField::Unicode # :nodoc:
    HEADER_ID = 'up'
    register_map
  end
end
