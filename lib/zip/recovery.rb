# frozen_string_literal: true

module Zip
  # Zip::Recovery is an explicitly invoked tool for recovering entries from a
  # zip archive that has lost its central directory - for example because an
  # upload was interrupted before the archive finished writing. The local
  # entry data at the start of such an archive is often still intact.
  #
  # Recovery is a two-step, confirmation-gated process:
  #
  #   recovery = Zip::Recovery.new('broken.zip')
  #   report = recovery.scan
  #
  #   report.entries.each do |entry|
  #     puts "#{entry.name}: #{entry.status}"
  #     entry.confirm! if entry.verified?
  #   end
  #
  #   recovery.write('recovered.zip')
  #
  # +scan+ reads the source archive strictly read-only and walks the local
  # entry headers in order. An entry is only reported as +verified+ when its
  # data boundary can be determined exactly and its contents check out:
  #
  # * Deflated entries must inflate to a proper deflate stream end, and the
  #   resulting CRC and sizes must match the local header or, when general
  #   purpose bit 3 is set, the trailing data descriptor.
  # * Stored entries must have a size known from the local header and a
  #   matching CRC. Stored entries whose boundary cannot be determined (for
  #   example because their sizes were deferred to a data descriptor) are
  #   reported as failed with an explanation - their data is never guessed.
  #
  # Only entries that are both verified and explicitly confirmed via
  # EntryReport#confirm! are written to the new archive by #write. The source
  # archive is never modified.
  class Recovery
    # Data descriptor signature (also used as the split archive signature).
    DATA_DESCRIPTOR_SIGNATURE = 0x08074b50

    # Size of a data descriptor without the optional signature.
    DATA_DESCRIPTOR_STATIC_LENGTH = 12

    # End of central directory signature.
    END_OF_CENTRAL_DIRECTORY_SIGNATURE = 0x06054b50

    # Chunk size used when inflating or checksumming entry data.
    CHUNK_SIZE = 16_384

    class << self
      # Convenience equivalent of <tt>new(source_path).scan</tt>.
      def scan(source_path)
        new(source_path).scan
      end
    end

    # The path of the archive being recovered. It is only ever read, never
    # written to.
    attr_reader :source_path

    def initialize(source_path)
      @source_path = source_path
      @report = nil
    end

    # Scans the source archive and returns a Report describing every local
    # entry found. The archive is opened read-only and is never modified.
    def scan
      entries = []
      notes = []
      ::File.open(@source_path, 'rb') do |io|
        scan_entries(io, entries, notes)
      end
      @report = Report.new(@source_path, entries, notes)
    end

    # Writes every confirmed (and therefore verified) entry from the last
    # scan to a new zip archive at +output_path+, returning +output_path+.
    #
    # Raises Zip::RecoveryError if no scan has been performed, if no entries
    # have been confirmed, or if +output_path+ would overwrite the source
    # archive or an existing file.
    def write(output_path)
      raise ::Zip::RecoveryError, 'No scan performed yet; call #scan before #write.' unless @report

      confirmed = @report.confirmed_entries
      if confirmed.empty?
        raise ::Zip::RecoveryError,
              'No confirmed entries to recover. Confirm verified entries with ' +
              'Zip::Recovery::EntryReport#confirm! first.'
      end
      if ::File.expand_path(output_path) == ::File.expand_path(@source_path)
        raise ::Zip::RecoveryError, 'Refusing to overwrite the source archive.'
      end
      if ::File.exist?(output_path)
        raise ::Zip::RecoveryError, "Refusing to overwrite existing file '#{output_path}'."
      end

      ::File.open(@source_path, 'rb') do |src|
        ::Zip::OutputStream.open(output_path) do |zos|
          confirmed.each { |entry_report| write_entry(src, zos, output_path, entry_report) }
        end
      end
      output_path
    end

    private

    def scan_entries(io, entries, notes)
      loop do
        offset = io.tell
        signature_bytes = io.read(4)
        if signature_bytes.nil?
          notes << "Reached end of archive at offset #{offset}."
          break
        end
        if signature_bytes.bytesize < 4
          notes << "Archive ends with #{signature_bytes.bytesize} trailing byte(s) " +
                   "at offset #{offset}; too few bytes for another record."
          break
        end

        signature = signature_bytes.unpack1('V')
        case signature
        when ::Zip::LOCAL_ENTRY_SIGNATURE
          io.seek(offset)
          entry_report = scan_local_entry(io, offset)
          entries << entry_report
          break unless advance_past(io, entry_report, notes)
        when ::Zip::CENTRAL_DIRECTORY_ENTRY_SIGNATURE
          notes << "Central directory record found at offset #{offset}; " +
                   'the archive may not be damaged after all.'
          break
        when END_OF_CENTRAL_DIRECTORY_SIGNATURE
          notes << "End of central directory record found at offset #{offset}."
          break
        else
          notes << format('Unrecognised data (signature 0x%08x) at offset %d; scan stopped.',
                          signature, offset)
          break
        end
      end
    end

    def advance_past(io, entry_report, notes)
      if entry_report.entry_end_offset.nil?
        notes << "Scan stopped at #{entry_report.display_name}: its data boundary " +
                 'could not be determined, so subsequent entries cannot be located.'
        return false
      end

      io.seek(entry_report.entry_end_offset)
      true
    end

    def scan_local_entry(io, offset)
      entry = ::Zip::Entry.new(@source_path)
      begin
        entry.read_local_entry(io)
      rescue ::Zip::Error => e
        return EntryReport.new(
          local_header_offset: offset,
          failure_reason: "Local header could not be parsed: #{e.message}"
        )
      end

      report = EntryReport.new(
        name: entry.name,
        local_header_offset: offset,
        data_offset: entry.local_entry_offset,
        compression_method: entry.compression_method,
        time: entry.time
      )
      report.directory = entry.ftype == :directory
      report.evidence << format(
        'Local header parsed at offset %d (compression method %d [%s], gp flags 0x%04x).',
        offset, entry.compression_method,
        ::Zip::COMPRESSION_METHODS[entry.compression_method] || 'unknown', entry.gp_flags
      )
      verify_entry_data(io, entry, report)
      report
    end

    def verify_entry_data(io, entry, report)
      if entry.encrypted?
        report.fail!('Entry is encrypted; its contents cannot be verified or recovered.')
      elsif entry.zip64? && (entry.gp_flags & 8).positive?
        report.fail!('Entry uses Zip64 data descriptors, which recovery does not support.')
      else
        case entry.compression_method
        when ::Zip::COMPRESSION_METHOD_STORE
          verify_stored_entry(io, entry, report)
        when ::Zip::COMPRESSION_METHOD_DEFLATE
          verify_deflated_entry(io, entry, report)
        else
          report.fail!(
            "Compression method #{entry.compression_method} is not supported for recovery; " +
            'only stored and deflated entries can be verified.'
          )
        end
      end
    end

    def verify_stored_entry(io, entry, report)
      if (entry.gp_flags & 8).positive?
        report.fail!(
          'Stored entry defers its sizes to a data descriptor (gp flag bit 3): the data ' +
          'boundary cannot be determined reliably, so the entry is not recoverable.'
        )
        return
      end
      if entry.compressed_size != entry.size
        report.fail!(
          "Stored entry declares inconsistent sizes (compressed #{entry.compressed_size}, " +
          "uncompressed #{entry.size}); the local header cannot be trusted."
        )
        return
      end

      available = io.size - report.data_offset
      if entry.compressed_size > available
        report.fail!(
          "Stored entry is truncated: the header declares #{entry.compressed_size} data " +
          "byte(s) but only #{available} remain in the archive."
        )
        return
      end

      crc = crc_of_region(io, report.data_offset, entry.compressed_size)
      if crc == entry.crc
        report.evidence << format(
          'Stored data verified: %d byte(s) at offset %d, CRC 0x%08x matches the local header.',
          entry.compressed_size, report.data_offset, crc
        )
        report.mark_verified!(crc: crc, compressed_size: entry.compressed_size, size: entry.size)
      else
        report.fail!(format(
                       'CRC mismatch: the local header declares 0x%08x but the data hashes ' +
                       'to 0x%08x.', entry.crc, crc
                     ))
      end
    end

    def verify_deflated_entry(io, entry, report)
      result = inflate_region(io, report.data_offset)
      case result[:status]
      when :truncated
        report.fail!('Deflate stream is truncated: the archive ends before the ' +
                     'compressed data stream terminates.')
        return
      when :invalid
        report.fail!("Deflate stream is invalid: #{result[:error]}.")
        return
      end

      data_end = report.data_offset + result[:compressed_size]
      report.evidence << format(
        'Deflate stream ends at offset %d (%d compressed byte(s) inflate to %d byte(s)).',
        data_end, result[:compressed_size], result[:size]
      )

      if (entry.gp_flags & 8).positive?
        verify_data_descriptor(io, entry, report, result, data_end)
      else
        verify_against_header(entry, report, result, data_end)
      end
    end

    def verify_against_header(entry, report, result, data_end)
      problems = []
      if entry.crc != result[:crc]
        problems << format('CRC mismatch (header 0x%08x, computed 0x%08x)',
                           entry.crc, result[:crc])
      end
      if entry.compressed_size != result[:compressed_size]
        problems << format('compressed size mismatch (header %d, computed %d)',
                           entry.compressed_size, result[:compressed_size])
      end
      if entry.size != result[:size]
        problems << format('uncompressed size mismatch (header %d, computed %d)',
                           entry.size, result[:size])
      end

      if problems.empty?
        report.evidence << format(
          'CRC 0x%08x and sizes (%d compressed, %d uncompressed) match the local header.',
          result[:crc], result[:compressed_size], result[:size]
        )
        report.mark_verified!(crc: result[:crc], compressed_size: result[:compressed_size],
                              size: result[:size])
      else
        report.fail!("Data does not match the local header: #{problems.join('; ')}.")
        # The deflate stream end still fixes the boundary, so the scan can continue.
        report.data_end_offset = data_end
        report.entry_end_offset = data_end
      end
    end

    def verify_data_descriptor(io, _entry, report, result, data_end)
      descriptor = read_data_descriptor(io, data_end)
      if descriptor.nil?
        report.fail!('Data descriptor is missing or truncated after the end of the ' +
                     'deflate stream.')
        return
      end

      report.evidence << format('Data descriptor (%s) found at offset %d.',
                                descriptor[:signature] ? 'with signature' : 'without signature',
                                data_end)
      entry_end = data_end + descriptor[:length]
      problems = []
      if descriptor[:crc] != result[:crc]
        problems << format('CRC mismatch (descriptor 0x%08x, computed 0x%08x)',
                           descriptor[:crc], result[:crc])
      end
      if descriptor[:compressed_size] != result[:compressed_size]
        problems << format('compressed size mismatch (descriptor %d, computed %d)',
                           descriptor[:compressed_size], result[:compressed_size])
      end
      if descriptor[:size] != result[:size]
        problems << format('uncompressed size mismatch (descriptor %d, computed %d)',
                           descriptor[:size], result[:size])
      end

      if problems.empty?
        report.evidence << format(
          'CRC 0x%08x and sizes confirmed by the data descriptor (%d compressed, %d uncompressed).',
          result[:crc], result[:compressed_size], result[:size]
        )
        report.mark_verified!(crc: result[:crc], compressed_size: result[:compressed_size],
                              size: result[:size], entry_end_offset: entry_end)
      else
        report.fail!("Data does not match the data descriptor: #{problems.join('; ')}.")
        report.data_end_offset = data_end
        report.entry_end_offset = entry_end
      end
    end

    def read_data_descriptor(io, offset)
      io.seek(offset)
      buffer = io.read(DATA_DESCRIPTOR_STATIC_LENGTH + 4)
      return nil if buffer.nil? || buffer.bytesize < DATA_DESCRIPTOR_STATIC_LENGTH

      values = buffer.unpack('V4')
      if values[0] == DATA_DESCRIPTOR_SIGNATURE
        { signature: true, crc: values[1], compressed_size: values[2],
          size: values[3], length: DATA_DESCRIPTOR_STATIC_LENGTH + 4 }
      else
        { signature: false, crc: values[0], compressed_size: values[1],
          size: values[2], length: DATA_DESCRIPTOR_STATIC_LENGTH }
      end
    end

    def inflate_region(io, offset)
      io.seek(offset)
      inflater = ::Zlib::Inflate.new(-::Zlib::MAX_WBITS)
      crc = 0
      size = 0
      loop do
        break if inflater.finished?

        chunk = io.read(CHUNK_SIZE)
        return { status: :truncated } if chunk.nil? || chunk.empty?

        begin
          output = inflater.inflate(chunk)
        rescue ::Zlib::Error => e
          return { status: :invalid, error: e.message }
        end
        crc = ::Zlib.crc32(output, crc)
        size += output.bytesize
      end
      { status: :ok, compressed_size: inflater.total_in, size: size, crc: crc }
    ensure
      inflater&.close if inflater&.finished?
    end

    def crc_of_region(io, offset, length)
      io.seek(offset)
      crc = 0
      remaining = length
      while remaining.positive?
        chunk = io.read([remaining, CHUNK_SIZE].min)
        break unless chunk

        crc = ::Zlib.crc32(chunk, crc)
        remaining -= chunk.bytesize
      end
      crc
    end

    def write_entry(src, zos, output_path, entry_report)
      entry = ::Zip::Entry.new(
        output_path, entry_report.name,
        compression_method: entry_report.compression_method,
        time: entry_report.time
      )
      zos.put_next_entry(entry)
      zos << read_entry_data(src, entry_report) unless entry_report.directory?
    end

    def read_entry_data(src, entry_report)
      src.seek(entry_report.data_offset)
      compressed = src.read(entry_report.compressed_size)
      case entry_report.compression_method
      when ::Zip::COMPRESSION_METHOD_STORE
        compressed
      when ::Zip::COMPRESSION_METHOD_DEFLATE
        inflater = ::Zlib::Inflate.new(-::Zlib::MAX_WBITS)
        output = inflater.inflate(compressed)
        inflater.close
        output
      end
    end

    # The result of a Recovery#scan. Holds an EntryReport for every local
    # entry found in the source archive, plus scan-level notes (for example
    # why a scan stopped early).
    class Report
      # The path of the scanned archive.
      attr_reader :source_path

      # All EntryReport objects, in archive order.
      attr_reader :entries

      # Scan-level observations (array of strings).
      attr_reader :notes

      def initialize(source_path, entries, notes) # :nodoc:
        @source_path = source_path
        @entries = entries
        @notes = notes
      end

      # Entries whose contents were fully verified against their metadata.
      def verified_entries
        @entries.select(&:verified?)
      end

      # Entries that could not be verified. See EntryReport#failure_reason.
      def failed_entries
        @entries.select(&:failed?)
      end

      # Verified entries that have been explicitly confirmed for recovery.
      def confirmed_entries
        @entries.select(&:confirmed?)
      end
    end

    # The recovery report for a single local entry: its name, its byte
    # boundaries within the source archive, its recovery status and the
    # evidence that status is based on.
    class EntryReport
      # Status value for entries whose contents were fully verified.
      STATUS_VERIFIED = :verified

      # Status value for entries that could not be verified.
      STATUS_FAILED = :failed

      # The entry name, or nil if the local header could not be parsed.
      attr_reader :name

      # :verified or :failed (see STATUS_VERIFIED and STATUS_FAILED).
      attr_reader :status

      # The observations the status is based on (array of strings).
      attr_reader :evidence

      # Why the entry is not recoverable, or nil for verified entries.
      attr_reader :failure_reason

      # Byte offset of the local header in the source archive.
      attr_reader :local_header_offset

      # Byte offset of the entry data in the source archive.
      attr_reader :data_offset

      # Byte offset just past the entry data, or nil if it is unknown.
      attr_reader :data_end_offset

      # Byte offset just past the whole entry (including any data
      # descriptor), or nil if it is unknown.
      attr_reader :entry_end_offset

      # Verified sizes and CRC, or nil for failed entries.
      attr_reader :compressed_size, :size, :crc

      # The compression method declared by the local header.
      attr_reader :compression_method

      # The modification time declared by the local header.
      attr_reader :time

      attr_writer :data_end_offset, :entry_end_offset, :directory # :nodoc:

      def initialize(name: nil, local_header_offset: nil, data_offset: nil, # :nodoc:
                     compression_method: nil, time: nil, failure_reason: nil)
        @name = name
        @local_header_offset = local_header_offset
        @data_offset = data_offset
        @compression_method = compression_method
        @time = time
        @status = nil
        @evidence = []
        @failure_reason = nil
        @confirmed = false
        @directory = false
        fail!(failure_reason) if failure_reason
      end

      # True when the entry contents were fully verified.
      def verified?
        @status == STATUS_VERIFIED
      end

      # True when the entry could not be verified.
      def failed?
        @status == STATUS_FAILED
      end

      # True when the entry may be recovered (i.e. it is verified).
      def recoverable?
        verified?
      end

      # True once the entry has been explicitly confirmed for recovery.
      def confirmed?
        @confirmed
      end

      # True when the entry is a directory.
      def directory?
        @directory
      end

      # A human-readable identifier for the entry, usable in messages even
      # when the local header could not be parsed.
      def display_name
        @name ? "entry '#{@name}'" : "entry at offset #{@local_header_offset}"
      end

      # Explicitly confirms this entry for recovery. Only verified entries
      # can be confirmed; raises Zip::RecoveryError otherwise.
      def confirm!
        unless verified?
          raise ::Zip::RecoveryError,
                "Refusing to confirm #{display_name}: only verified entries can be confirmed."
        end

        @confirmed = true
        self
      end

      def fail!(reason) # :nodoc:
        @status = STATUS_FAILED
        @failure_reason = reason
      end

      def mark_verified!(crc:, compressed_size:, size:, entry_end_offset: nil) # :nodoc:
        @status = STATUS_VERIFIED
        @crc = crc
        @compressed_size = compressed_size
        @size = size
        @data_end_offset = @data_offset + compressed_size
        @entry_end_offset = entry_end_offset || @data_end_offset
      end
    end
  end
end
