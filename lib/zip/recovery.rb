# frozen_string_literal: true

module Zip
  # Recovery scans a zip archive that has lost its central directory (for
  # example, because an upload was truncated) and reports which local
  # entries can be verified as complete. Nothing is recovered implicitly:
  # +scan+ only reports, and +recover+ writes a new archive containing just
  # the entries the caller has explicitly confirmed. The source archive is
  # only ever opened read-only.
  #
  # An entry is only considered recoverable when its exact data boundary is
  # known and its contents verify:
  #
  # * Deflated entries must inflate to a clean deflate stream end, and the
  #   CRC and sizes recorded in the local header (or in a following data
  #   descriptor) must match the inflated data.
  # * Stored entries must declare their sizes in the local header, and the
  #   CRC must match. A stored entry whose sizes live in a data descriptor
  #   has no determinable boundary, so it is reported as failed rather than
  #   guessed at.
  #
  # Example:
  #
  #   report = Zip::Recovery.scan('broken.zip')
  #   report.entries.each do |entry|
  #     puts "#{entry.name}: #{entry.status} (#{entry.evidence.join(', ')})"
  #   end
  #   confirmed = report.recoverable_entries.map(&:name)
  #   Zip::Recovery.recover('broken.zip', 'recovered.zip', confirm: confirmed)
  module Recovery
    # The result of scanning one local record (a would-be entry).
    class EntryReport
      # The entry name from the local header, or nil if none was found.
      attr_reader :name

      # The compression method declared by the local header.
      attr_reader :compression_method

      # Offset of the local header within the source archive.
      attr_reader :local_header_offset

      # Offset at which the entry's (compressed) data begins.
      attr_reader :data_offset

      # Offset just past the entry's data. Nil if the boundary is unknown.
      attr_reader :data_end_offset

      # Offset at which the next record would begin (past any data
      # descriptor). Nil if the boundary is unknown.
      attr_reader :end_offset

      # :recoverable or :failed.
      attr_reader :status

      # Human-readable evidence gathered while verifying the entry.
      attr_reader :evidence

      # Human-readable explanation of why the entry failed, or nil.
      attr_reader :failure

      def initialize # :nodoc:
        @evidence = []
        @status = :failed
      end

      # True if the entry was verified complete and can be recovered.
      def recoverable?
        @status == :recoverable
      end
    end

    # The result of scanning a whole archive. Enumerable over EntryReport.
    class Report
      include Enumerable

      # The EntryReport for each local record found, in file order.
      attr_reader :entries

      # A note about anything found after the last scannable entry (for
      # example leftover central directory structures or unparseable
      # trailing bytes), or nil.
      attr_reader :trailing_note

      def initialize # :nodoc:
        @entries = []
      end

      def each(&block) # :nodoc:
        entries.each(&block)
      end

      # All entries that verified complete and may be confirmed for
      # recovery.
      def recoverable_entries
        entries.select(&:recoverable?)
      end
    end

    LOCAL_HEADER_PACK = 'VvvvvvVVVvv' # :nodoc:
    DATA_DESCRIPTOR_SIGNATURE = 0x08074b50 # :nodoc:
    DESCRIPTOR_FLAG = 0x08 # :nodoc:
    ENCRYPTED_FLAG = 0x01 # :nodoc:
    ZIP64_EXTRA_ID = 0x0001 # :nodoc:
    ZIP64_PLACEHOLDER = 0xFFFFFFFF # :nodoc:

    class << self
      # Scans +source+ (a path or a readable IO) for verifiable local
      # entries and returns a Report. The source is only read, never
      # modified.
      def scan(source)
        Scanner.new(read_source(source)).scan
      end

      # Writes a new zip archive at +destination+ containing exactly the
      # scanned entries whose names are listed in +confirm+. Every
      # confirmed entry must have been verified complete by the scan;
      # attempting to confirm a failed or unknown entry raises Zip::Error
      # and nothing is written. The source archive is only read, never
      # modified, and +destination+ must be a different file.
      #
      # Returns the Report describing what was written.
      def recover(source, destination, confirm: nil)
        if confirm.nil?
          raise ArgumentError,
                'confirm: must name the entries approved for recovery; ' +
                  'nothing is recovered without explicit confirmation'
        end

        if source.is_a?(String) &&
           ::File.expand_path(source) == ::File.expand_path(destination.to_s)
          raise ::Zip::Error, 'destination must differ from the source archive'
        end

        data = read_source(source)
        report = Scanner.new(data, keep_data: true).scan
        confirmed = confirm.map { |name| name.to_s.b }

        confirmed.each do |name|
          entry = report.entries.find { |candidate| candidate.name&.b == name }
          raise ::Zip::Error, "cannot confirm '#{name}': no such entry was found" unless entry
          next if entry.recoverable?

          raise ::Zip::Error, "cannot confirm '#{entry.name}': #{entry.failure}"
        end

        ::Zip::OutputStream.open(destination) do |zos|
          report.entries.each do |entry|
            next unless entry.recoverable? && confirmed.include?(entry.name.b)

            zos.put_next_entry(entry.name, '', nil, entry.compression_method)
            zos << entry.verified_data
          end
        end

        report
      end

      private

      def read_source(source)
        if source.is_a?(String)
          ::File.open(source, 'rb', &:read)
        else
          source.read
        end
      end
    end

    # Walks the archive image sequentially, only ever parsing a local
    # header at the exact offset where one is expected. Bytes that merely
    # look like a zip signature inside entry data or trailing garbage are
    # never treated as entries.
    class Scanner # :nodoc:all
      def initialize(data, keep_data: false)
        @data = data.b
        @keep_data = keep_data
      end

      def scan
        report = Report.new
        offset = 0
        while offset < @data.bytesize
          entry, offset = scan_record(report, offset)
          report.entries << entry if entry
          break unless offset
        end
        report
      end

      private

      # Returns [entry_report_or_nil, next_offset_or_nil]. A nil next
      # offset means the boundary of the next record cannot be determined
      # and the scan stops.
      def scan_record(report, offset)
        remaining = @data.bytesize - offset
        if remaining < ::Zip::LOCAL_ENTRY_STATIC_HEADER_LENGTH
          report.trailing_note =
            "#{remaining} trailing byte(s) at offset #{offset} are too " +
              'short for a local header; ignored'
          return [nil, nil]
        end

        fields = @data.byteslice(offset, ::Zip::LOCAL_ENTRY_STATIC_HEADER_LENGTH)
                      .unpack(LOCAL_HEADER_PACK)
        signature = fields[0]

        if [::Zip::CENTRAL_DIRECTORY_ENTRY_SIGNATURE,
            ::Zip::CentralDirectory::END_OF_CD_SIG].include?(signature)
          report.trailing_note =
            "central directory structure found at offset #{offset}; scan stopped"
          return [nil, nil]
        end

        entry = EntryReport.new
        entry.local_header_offset = offset

        unless signature == ::Zip::LOCAL_ENTRY_SIGNATURE
          fail_entry(
            entry,
            format('no local file header signature at offset %<offset>d ' +
                   '(found 0x%<found>08x); cannot locate further entries ' +
                   'without guessing', offset: offset, found: signature)
          )
          return [entry, nil]
        end

        scan_local_entry(entry, fields, offset)
      end

      def scan_local_entry(entry, fields, offset)
        _, _version, gp_flags, method, _mod_time, _mod_date,
          crc, compressed_size, size, name_length, extra_length = fields

        header_end = offset + ::Zip::LOCAL_ENTRY_STATIC_HEADER_LENGTH +
                     name_length + extra_length
        if header_end > @data.bytesize
          fail_entry(entry, 'local header is truncated: name/extra fields ' +
                            'run past the end of the file')
          return [entry, nil]
        end

        entry.name = read_name(offset, name_length)
        entry.compression_method = method
        entry.data_offset = header_end

        if gp_flags & ENCRYPTED_FLAG != 0
          fail_entry(entry, 'entry is encrypted; its contents cannot be verified')
          return [entry, nil]
        end

        extra = @data.byteslice(header_end - extra_length, extra_length)
        size, compressed_size = zip64_sizes(extra, size, compressed_size, entry)
        return [entry, nil] if entry.failure

        scan_data(entry, gp_flags, method, crc, compressed_size, size)
      end

      def read_name(offset, name_length)
        name = @data.byteslice(offset + ::Zip::LOCAL_ENTRY_STATIC_HEADER_LENGTH,
                               name_length)
        if ::Zip.force_entry_names_encoding
          name.force_encoding(::Zip.force_entry_names_encoding)
        end
        name
      end

      def scan_data(entry, gp_flags, method, crc, compressed_size, size)
        case method
        when ::Zip::COMPRESSION_METHOD_DEFLATE
          scan_deflated(entry, gp_flags, crc, compressed_size, size)
        when ::Zip::COMPRESSION_METHOD_STORE
          scan_stored(entry, gp_flags, crc, compressed_size, size)
        else
          fail_entry(entry, "unsupported compression method #{method} " +
                            "(#{::Zip::COMPRESSION_METHODS[method]}); " +
                            'contents cannot be verified')
          [entry, nil]
        end
      end

      # Substitutes real sizes from a zip64 extra field when the local
      # header carries 0xFFFFFFFF placeholders. Returns [size,
      # compressed_size].
      def zip64_sizes(extra, size, compressed_size, entry)
        unless size == ZIP64_PLACEHOLDER || compressed_size == ZIP64_PLACEHOLDER
          return [size, compressed_size]
        end

        pos = 0
        while pos + 4 <= extra.bytesize
          id, length = extra.byteslice(pos, 4).unpack('vv')
          content = extra.byteslice(pos + 4, length) || +''.b
          if id == ZIP64_EXTRA_ID
            # Fields are present in this order, each only when the
            # corresponding header field holds the 0xFFFFFFFF placeholder.
            cursor = 0
            if size == ZIP64_PLACEHOLDER && cursor + 8 <= content.bytesize
              size = content.byteslice(cursor, 8).unpack1('Q<')
              cursor += 8
            end
            if compressed_size == ZIP64_PLACEHOLDER && cursor + 8 <= content.bytesize
              compressed_size = content.byteslice(cursor, 8).unpack1('Q<')
            end
            entry.evidence << 'zip64 extra field supplies the real sizes'
            return [size, compressed_size]
          end
          pos += 4 + length
        end

        if size == ZIP64_PLACEHOLDER || compressed_size == ZIP64_PLACEHOLDER
          fail_entry(entry, 'local header uses zip64 placeholder sizes but ' +
                            'no usable zip64 extra field is present')
        end
        [size, compressed_size]
      end

      def scan_deflated(entry, gp_flags, crc, compressed_size, size)
        inflater = ::Zlib::Inflate.new(-::Zlib::MAX_WBITS)
        begin
          inflated = inflater.inflate(@data.byteslice(entry.data_offset..) || +''.b)
          finished = inflater.finished?
          compressed = inflater.total_in
        rescue ::Zlib::Error => e
          fail_entry(entry, "deflate stream is corrupt: #{e.message}")
          return [entry, nil]
        end

        unless finished
          fail_entry(entry, 'deflate stream has no end marker within the ' +
                            'file; the entry is incomplete')
          return [entry, nil]
        end

        data_end = entry.data_offset + compressed
        entry.data_end_offset = data_end
        entry.verified_data = inflated if @keep_data
        entry.evidence << "deflate stream ended cleanly after #{compressed} " +
                          'compressed byte(s)'

        if gp_flags & DESCRIPTOR_FLAG != 0
          scan_descriptor(entry, inflated, compressed, data_end)
        else
          verify_deflated_against_header(entry, inflated, compressed,
                                         crc, compressed_size, size)
        end
      end

      def verify_deflated_against_header(entry, inflated, compressed,
                                         crc, compressed_size, size)
        if crc.zero? && compressed_size.zero? && size.zero? && !inflated.empty?
          fail_entry(entry, 'local header carries no CRC or sizes and no ' +
                            'data descriptor follows; nothing to verify against')
          return [entry, nil]
        end

        actual_crc = ::Zlib.crc32(inflated)
        unless check_crc(entry, crc, actual_crc, 'local header') &&
               check_size(entry, compressed_size, compressed, 'compressed size') &&
               check_size(entry, size, inflated.bytesize, 'size')
          return [entry, nil]
        end

        mark_recoverable(entry, entry.data_end_offset)
      end

      def scan_descriptor(entry, inflated, compressed, data_end)
        available = @data.bytesize - data_end
        rest = @data.byteslice(data_end, 24) || +''.b
        has_signature = rest.unpack1('V') == DATA_DESCRIPTOR_SIGNATURE
        sig_len = has_signature ? 4 : 0

        formats = []
        formats << ['standard', 12, 'VVV'] if available >= sig_len + 12
        formats << ['zip64', 20, 'VQ<Q<'] if available >= sig_len + 20

        actual_crc = ::Zlib.crc32(inflated)
        formats.each do |label, length, pack|
          desc_crc, desc_compressed, desc_size = rest.byteslice(sig_len, length).unpack(pack)
          next unless desc_crc == actual_crc &&
                      desc_compressed == compressed &&
                      desc_size == inflated.bytesize

          signature_note = has_signature ? ', with signature' : ''
          entry.evidence << "data descriptor (#{label}#{signature_note}) " +
                            "confirms CRC #{hex(actual_crc)}, compressed " +
                            "size #{compressed}, size #{inflated.bytesize}"
          return mark_recoverable(entry, data_end + sig_len + length)
        end

        fail_entry(entry, "data descriptor at offset #{data_end} is " +
                          'missing, truncated, or inconsistent with the ' +
                          'inflated data')
        [entry, nil]
      end

      def scan_stored(entry, gp_flags, crc, compressed_size, size)
        if gp_flags & DESCRIPTOR_FLAG != 0
          fail_entry(entry, 'stored entry declares its sizes in a data ' +
                            'descriptor, so its data boundary cannot be ' +
                            'determined without guessing')
          return [entry, nil]
        end

        if compressed_size != size
          fail_entry(entry, 'stored entry has inconsistent header sizes ' +
                            "(compressed #{compressed_size}, size #{size})")
          return [entry, nil]
        end

        data_end = entry.data_offset + compressed_size
        if data_end > @data.bytesize
          fail_entry(entry, "stored data is truncated: header declares " +
                            "#{compressed_size} byte(s) but only " +
                            "#{@data.bytesize - entry.data_offset} remain")
          return [entry, nil]
        end

        content = @data.byteslice(entry.data_offset, compressed_size)
        entry.data_end_offset = data_end
        entry.verified_data = content if @keep_data
        entry.evidence << "stored size #{compressed_size} from the local " +
                          'header gives an exact boundary'
        return [entry, nil] unless check_crc(entry, crc, ::Zlib.crc32(content),
                                             'local header')

        mark_recoverable(entry, data_end)
      end

      def check_crc(entry, expected, actual, source_name)
        return true if expected == actual

        fail_entry(entry, "CRC mismatch: #{source_name} records " +
                          "#{hex(expected)} but the data hashes to " +
                          "#{hex(actual)}")
        false
      end

      def check_size(entry, expected, actual, label)
        # A zero header field means "not recorded here".
        return true if expected.zero? || expected == actual

        fail_entry(entry, "#{label} mismatch: local header records " +
                          "#{expected} but the data measures #{actual}")
        false
      end

      def mark_recoverable(entry, end_offset)
        entry.status = :recoverable
        entry.end_offset = end_offset
        [entry, end_offset]
      end

      def fail_entry(entry, message)
        entry.failure = message
      end

      def hex(value)
        format('0x%08x', value)
      end
    end

    # Internal setters used by Scanner. Not part of the public API.
    class EntryReport
      attr_writer :compression_method, :local_header_offset, :data_offset, # :nodoc:
                  :data_end_offset, :end_offset, :status, :failure, :name

      attr_accessor :verified_data # :nodoc:
    end

    class Report
      attr_writer :trailing_note # :nodoc:
    end
  end
end
