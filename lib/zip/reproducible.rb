# frozen_string_literal: true

module Zip
  # Normalizes zip entries so that archives built from the same input
  # content are byte-for-byte identical, given the same Ruby/zlib versions
  # and compression settings. Enable it by passing +reproducible: true+
  # (or a Hash of options) to Zip::File or Zip::OutputStream.
  #
  # The normalization policy is:
  #
  # * _Entry order_: entries are written sorted by their (UTF-8) name,
  #   byte by byte. (Zip::File only; Zip::OutputStream is a stream, so
  #   there entries are normalized as they are written and ordering is
  #   the caller's responsibility.)
  # * _Timestamps_: every entry's modification time is fixed to the
  #   +:time+ option, defaulting to the +SOURCE_DATE_EPOCH+ environment
  #   variable when set, and to the DOS epoch (1980-01-01 00:00:00 UTC)
  #   otherwise. Access/creation times carried in extra fields are
  #   dropped with those fields.
  # * _Permissions and ownership_: files are stored with mode 0644 and
  #   directories with mode 0755 (configurable via +:file_permissions+
  #   and +:directory_permissions+); uid/gid ownership is discarded.
  # * _Extra fields_: only fields named in +:allowed_extra_fields+
  #   (default: +[:zip64]+, which is added automatically when sizes
  #   require it) are kept. Any other field gathered from source files
  #   or read from another archive is silently dropped. A field that
  #   was *explicitly* provided by the caller (via the +extra:+ argument)
  #   and is not on the allowed list cannot be normalized away without
  #   losing user data, so a Zip::NonReproducibleError is raised naming
  #   the field and the reason.
  # * _Entry names_: names are transcoded to UTF-8 when possible; a name
  #   that is not valid UTF-8 (and cannot be transcoded to it) raises
  #   Zip::NonReproducibleError, since its bytes cannot be interpreted
  #   deterministically. The language encoding (EFS) flag is set exactly
  #   when the name or comment contains non-ASCII characters.
  #
  # Encryption is inherently non-reproducible (it writes a random
  # salt/header), so combining an encrypter with this option raises
  # Zip::NonReproducibleError.
  module Reproducible
    # The default fixed timestamp: the DOS epoch, 1980-01-01 00:00:00 UTC.
    DEFAULT_TIME = ::Zip::DOSTime.utc(1980, 1, 1, 0, 0, 0).freeze

    # The fixed permission bits used for file entries by default.
    DEFAULT_FILE_PERMISSIONS = 0o644

    # The fixed permission bits used for directory entries by default.
    DEFAULT_DIRECTORY_PERMISSIONS = 0o755

    # The extra fields kept by default. Zip64 is required whenever entry
    # sizes or offsets exceed 32 bits, and is generated automatically.
    DEFAULT_ALLOWED_EXTRA_FIELDS = [:zip64].freeze

    # All extra field names that may be allow-listed.
    KNOWN_EXTRA_FIELDS =
      (::Zip::ExtraField::ID_MAP.values.map(&:name) + [:unknown]).freeze

    DEFAULT_OPTIONS = {
      time: nil, # nil resolves to SOURCE_DATE_EPOCH, then DEFAULT_TIME
      file_permissions: DEFAULT_FILE_PERMISSIONS,
      directory_permissions: DEFAULT_DIRECTORY_PERMISSIONS,
      allowed_extra_fields: DEFAULT_ALLOWED_EXTRA_FIELDS
    }.freeze

    class << self
      # Turns the +reproducible+ option value into a normalized options
      # Hash, or nil when reproducible output is disabled.
      def normalize_options(reproducible)
        return nil if reproducible.nil? || reproducible == false

        opts = reproducible.kind_of?(Hash) ? reproducible : {}
        unknown = opts.keys - DEFAULT_OPTIONS.keys
        unless unknown.empty?
          raise ArgumentError,
                "Unknown reproducible option(s): #{unknown.map(&:inspect).join(', ')}. " \
                "Known options: #{DEFAULT_OPTIONS.keys.map(&:inspect).join(', ')}."
        end

        merged = DEFAULT_OPTIONS.merge(opts)
        merged[:allowed_extra_fields] = validate_extra_fields(merged[:allowed_extra_fields])
        merged[:time] = resolve_time(merged[:time])
        merged
      end

      # Normalizes +entry+ in place according to +options+ (as returned by
      # normalize_options). Raises Zip::NonReproducibleError when the entry
      # carries explicitly provided metadata that cannot be normalized.
      def normalize_entry!(entry, options)
        normalize_name!(entry)
        normalize_efs_flag!(entry)
        entry.dos_time = options[:time]
        normalize_permissions!(entry, options)
        normalize_extra_fields!(entry, options)
        entry
      end

      private

      def validate_extra_fields(fields)
        [*fields].map do |field|
          key = field.to_sym
          unless KNOWN_EXTRA_FIELDS.include?(key)
            raise ArgumentError,
                  "Unknown extra field #{field.inspect} in :allowed_extra_fields. " \
                  "Known fields: #{KNOWN_EXTRA_FIELDS.map(&:inspect).join(', ')}."
          end
          key
        end
      end

      def resolve_time(time)
        time ||= source_date_epoch
        return DEFAULT_TIME if time.nil?

        unless time.respond_to?(:getutc)
          raise ArgumentError,
                "The reproducible :time option must be a Time, not #{time.class}."
        end

        # Normalize to UTC components so the stored DOS time does not
        # depend on the local timezone of the machine building the zip.
        utc = time.getutc
        ::Zip::DOSTime.utc(utc.year, utc.month, utc.day, utc.hour, utc.min, utc.sec)
      end

      def source_date_epoch
        value = ENV['SOURCE_DATE_EPOCH']
        return nil if value.nil? || value.empty?

        ::Time.at(Integer(value)).utc
      rescue ArgumentError, TypeError
        raise ArgumentError, "SOURCE_DATE_EPOCH is not a valid integer: #{value.inspect}."
      end

      def normalize_name!(entry)
        name = entry.name.dup
        name.force_encoding(::Encoding::UTF_8) if name.encoding == ::Encoding::ASCII_8BIT
        name = transcode_name!(entry, name)
        unless name.valid_encoding?
          raise ::Zip::NonReproducibleError,
                "cannot normalize the name of entry #{name.inspect}: it is not valid UTF-8. " \
                'Reproducible archives require entry names to be valid UTF-8; re-encode ' \
                'the name (or set Zip.force_entry_names_encoding when reading it).'
        end
        entry.name = name
      end

      def transcode_name!(entry, name)
        return name if [::Encoding::UTF_8, ::Encoding::US_ASCII].include?(name.encoding)

        name.encode(::Encoding::UTF_8)
      rescue ::EncodingError => e
        raise ::Zip::NonReproducibleError,
              "cannot normalize the name of entry #{entry.name.inspect}: #{e.message}"
      end

      def normalize_efs_flag!(entry)
        non_ascii = !entry.name.ascii_only? || !entry.comment.to_s.ascii_only?
        if non_ascii
          entry.gp_flags |= ::Zip::Entry::EFS
        else
          entry.gp_flags &= ~::Zip::Entry::EFS
        end
      end

      def normalize_permissions!(entry, options)
        entry.unix_perms =
          if entry.directory?
            options[:directory_permissions]
          else
            options[:file_permissions]
          end
        entry.unix_uid = nil
        entry.unix_gid = nil
      end

      def normalize_extra_fields!(entry, options)
        allowed = options[:allowed_extra_fields]
        dropped = entry.extra.keys - allowed
        return if dropped.empty?

        if entry.explicit_extra?
          raise ::Zip::NonReproducibleError,
                "cannot normalize entry '#{entry.name}': extra field(s) " \
                "#{dropped.map(&:inspect).join(', ')} were explicitly provided but are " \
                "not in :allowed_extra_fields (#{allowed.map(&:inspect).join(', ')}). " \
                'Remove them, or add them to the :allowed_extra_fields reproducible option.'
        end

        dropped.each { |key| entry.extra.delete(key) }
      end
    end
  end
end
