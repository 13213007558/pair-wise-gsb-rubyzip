# frozen_string_literal: true

module Zip
  # Canonicalizes zip output so byte-for-byte reproducible archives can be
  # generated from identical input contents and compression settings.
  module Reproducible # :nodoc:
    FIXED_TIME = DOSTime.local(1980, 1, 1, 0, 0, 0).freeze
    FILE_PERMISSIONS = 0o644
    DIRECTORY_PERMISSIONS = 0o755
    SYMLINK_PERMISSIONS = 0o777
    VERSION_MADE_BY = Zip::VERSION_MADE_BY
    VERSION_NEEDED_TO_EXTRACT = 63
    ALLOWED_EXTRA_FIELDS = %i[aes zip64].freeze

    module_function

    def sorted_entries(entries)
      seen = {}
      entries.each do |entry|
        name = canonical_name(entry.name)
        if seen.key?(name)
          raise ArgumentError,
                "cannot create reproducible output with duplicate entry name #{name.inspect}"
        end

        seen[name] = entry
      end

      entries.sort_by { |entry| canonical_name(entry.name).b }
    end

    def normalize_entry(entry)
      validate_extra_fields(entry)

      entry.name = canonical_name(entry.name)
      entry.fstype = FSTYPE_UNIX
      entry.version_made_by = VERSION_MADE_BY
      entry.gp_flags = canonical_gp_flags(entry)
      entry.unix_perms = canonical_permissions(entry)
      entry.unix_uid = nil
      entry.unix_gid = nil
      entry.comment = canonical_text(entry.comment, 'entry comment')

      normalized_extra = Zip::ExtraField.new
      normalized_extra[:aes] = entry.extra[:aes] if entry.extra[:aes]
      entry.extra = normalized_extra
      entry.version_needed_to_extract = VERSION_NEEDED_TO_EXTRACT
      entry.time = FIXED_TIME
      entry.extra.delete(:universaltime)
      entry.local_header_size = nil
      entry
    end

    def validate_encrypter(encrypter)
      return if encrypter.nil? || encrypter.is_a?(NullEncrypter)

      raise ArgumentError,
            "cannot create reproducible output with #{encrypter.class}: " \
            'encryption introduces random header data'
    end

    def canonical_name(name)
      canonical_text(name, 'entry name').gsub('\\', '/')
    end

    def canonical_text(value, description)
      text = value.to_s
      text = text.dup.force_encoding(Encoding::UTF_8) unless text.encoding == Encoding::UTF_8
      return text if text.valid_encoding?

      raise ArgumentError, "#{description} is not valid UTF-8"
    end

    def canonical_permissions(entry)
      case entry.ftype
      when :directory then DIRECTORY_PERMISSIONS
      when :symlink then SYMLINK_PERMISSIONS
      else FILE_PERMISSIONS
      end
    end

    def canonical_gp_flags(entry)
      flags = Entry::EFS
      flags |= 0b0001 if entry.encrypted?

      if entry.compression_method == Entry::DEFLATED
        case entry.compression_level
        when 1 then flags |= Entry::COMPRESSION_LEVEL_SUPERFAST_GPFLAG
        when 2 then flags |= Entry::COMPRESSION_LEVEL_FAST_GPFLAG
        when 8, 9 then flags |= Entry::COMPRESSION_LEVEL_MAX_GPFLAG
        end
      end

      flags
    end

    def validate_extra_fields(entry)
      return unless entry.extra.member?(:unknown)

      raise ArgumentError,
            'unknown extra fields cannot be represented in reproducible output'
    end
  end
end
