# frozen_string_literal: true

module Zip
  class ExtraField < Hash # :nodoc:all
    ID_MAP = {}

    def initialize(binstr = nil, local: false)
      merge(binstr, local: local) if binstr
    end

    # Only the extra fields that keep separate local/central-directory
    # declarations take the `local` flag; the rest get the plain binary
    # record.
    def extra_field_type_exist(binstr, id, len, index, local)
      field_name = ID_MAP[id].name
      record = binstr[index, len + 4]
      if member?(field_name)
        merge_extra_field(self[field_name], record, local)
      else
        self[field_name] = build_extra_field(ID_MAP[id], record, local)
      end
    end

    def build_extra_field(klass, record, local)
      if local_aware?(klass)
        klass.new(record, local: local)
      else
        klass.new(record)
      end
    end

    def merge_extra_field(field, record, local)
      if local_aware?(field.class)
        field.merge(record, local: local)
      else
        field.merge(record)
      end
    end

    def local_aware?(klass)
      klass.respond_to?(:local_aware?) && klass.local_aware?
    end

    def extra_field_type_unknown(binstr, len, index, local)
      self[:unknown] ||= Unknown.new

      if !len || len + 4 > binstr[index..].bytesize
        self[:unknown].merge(binstr[index..], local: local)
        return
      end

      self[:unknown].merge(binstr[index, len + 4], local: local)
    end

    def merge(binstr, local: false)
      return if binstr.empty?

      i = 0
      while i < binstr.bytesize
        id  = binstr[i, 2]
        len = binstr[i + 2, 2].to_s.unpack1('v')
        if id && ID_MAP.member?(id)
          extra_field_type_exist(binstr, id, len, i, local)
        elsif id
          break unless extra_field_type_unknown(binstr, len, i, local)
        end
        i += len + 4
      end
    end

    def create(name)
      unless (field_class = ID_MAP.values.find { |k| k.name == name })
        raise Error, "Unknown extra field '#{name}'"
      end

      self[name] = field_class.new
    end

    # Place Unknown last, so "extra" data that is missing the proper
    # signature/size does not prevent known fields from being read back in.
    # The declared order of the known fields is preserved (Hash insertion
    # order), which matters for lossless rewrites.
    def ordered_values
      known, unknown = partition { |k, _| k != :unknown }
      known.map { |_, v| v }.concat(unknown.map { |_, v| v })
    end

    # Remove any extra fields that indicate they can be safely suppressed.
    def suppress_fields!(fields)
      reject! do |k, v|
        v.suppress? if fields == true || [*fields].include?(k)
      end
    end

    def to_local_bin
      ordered_values.map! { |v| v.to_local_bin.force_encoding('BINARY') }.join
    end

    alias to_s to_local_bin

    def to_c_dir_bin
      ordered_values.map! { |v| v.to_c_dir_bin.force_encoding('BINARY') }.join
    end

    def c_dir_size
      to_c_dir_bin.bytesize
    end

    def local_size
      to_local_bin.bytesize
    end

    alias length local_size
    alias size local_size
  end
end

require 'zip/extra_field/unknown'
require 'zip/extra_field/generic'
require 'zip/extra_field/universal_time'
require 'zip/extra_field/old_unix'
require 'zip/extra_field/unix'
require 'zip/extra_field/zip64'
require 'zip/extra_field/ntfs'
require 'zip/extra_field/aes'
require 'zip/extra_field/unicode_path'
require 'zip/extra_field/unicode_comment'

# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
