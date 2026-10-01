# frozen_string_literal: true

module Zip
  class ExtraField < Hash # :nodoc:all
    ID_MAP = {}

    def initialize(binstr = nil, local: false, name: nil, comment: nil)
      merge(binstr, local: local, name: name, comment: comment) if binstr
    end

    def extra_field_type_exist(binstr, id, len, index, local, name, comment)
      record = binstr[index, len + 4]
      field_name = ID_MAP[id].name
      if member?(field_name)
        merge_known_field(self[field_name], record, local, name, comment)
      else
        field = build_known_field(ID_MAP[id], record, local, name, comment)
        self[field_name] = field if field
      end
    end

    # The Unicode fields authenticate the primary bytes of the header they
    # appear in, so they need the raw name/comment bytes to check the CRC.
    def feed_unicode_field(field, record, local, name, comment)
      # The Unicode Comment field is only defined in the central directory.
      # Preserve a stray local-header copy verbatim rather than trusting it.
      if local && field.is_a?(::Zip::ExtraField::UnicodeComment)
        self[:unknown] ||= Unknown.new
        self[:unknown].merge(record, local: true)
        return
      end

      primary =
        if field.is_a?(::Zip::ExtraField::UnicodePath) then name
        else
          comment
        end
      field.merge(record, local: local, primary_bytes: primary&.b)
    end

    def merge_known_field(field, record, local, name, comment)
      if field.kind_of?(::Zip::ExtraField::Unicode)
        feed_unicode_field(field, record, local, name, comment)
      else
        field.merge(record)
      end
    end

    def build_known_field(klass, record, local, name, comment)
      # The Unicode Comment field is only defined in the central directory;
      # keep a stray copy as unknown data rather than trusting it.
      if local && klass == ::Zip::ExtraField::UnicodeComment
        self[:unknown] ||= Unknown.new
        self[:unknown].merge(record, local: true)
        return nil
      end

      if klass < ::Zip::ExtraField::Unicode
        klass.new(record, local: local,
                  primary_bytes: unicode_primary_for(klass, name, comment))
      else
        klass.new(record)
      end
    end

    def unicode_primary_for(klass, name, comment)
      primary = klass == ::Zip::ExtraField::UnicodePath ? name : comment
      primary&.b
    end

    def extra_field_type_unknown(binstr, len, index, local)
      self[:unknown] ||= Unknown.new

      if !len || len + 4 > binstr[index..].bytesize
        self[:unknown].merge(binstr[index..], local: local)
        return
      end

      self[:unknown].merge(binstr[index, len + 4], local: local)
    end

    def merge(binstr, local: false, name: nil, comment: nil)
      return if binstr.nil? || binstr.empty?

      i = 0
      while i < binstr.bytesize
        id  = binstr[i, 2]
        len = binstr[i + 2, 2].to_s.unpack1('v')
        if id && ID_MAP.member?(id)
          extra_field_type_exist(binstr, id, len, i, local, name, comment)
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
    def ordered_values
      result = []
      each { |k, v| k == :unknown ? result.push(v) : result.unshift(v) }
      result
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
require 'zip/extra_field/unicode'
require 'zip/extra_field/unicode_path'
require 'zip/extra_field/unicode_comment'
require 'zip/extra_field/universal_time'
require 'zip/extra_field/old_unix'
require 'zip/extra_field/unix'
require 'zip/extra_field/zip64'
require 'zip/extra_field/ntfs'
require 'zip/extra_field/aes'

# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
