# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'stringio'
require 'tempfile'

require_relative 'constants'

module Zip
  # Creates and applies binary deltas between two zip archives.
  #
  # A delta describes how to build a *target* archive from a *base* archive.
  # Entries that are unchanged can be copied byte-for-byte from the base,
  # including their compressed data. Entries with identical compressed
  # payloads and matching metadata but different names (renames) reuse the
  # base payload with a freshly written local header. Anything that cannot be
  # reused is embedded in the delta verbatim, and entries missing from the
  # target are omitted (deleted).
  #
  # A delta is bound to one exact base archive by a SHA-256 digest of the
  # whole base file and is itself protected by a SHA-256 digest. Applying a
  # delta verifies the base identity and every reuse precondition before any
  # output is written. The result is assembled in a temporary file, its
  # central directory offsets are regenerated, and it is renamed into place
  # only after it re-parses and validates, so a wrong base or corrupt delta
  # can never leave behind an archive that appears successful.
  #
  # The delta is self-describing. Extra fields that this library does not
  # understand are retained byte-for-byte from the target archive, in both
  # local headers and the central directory, and are structurally validated
  # when the delta is applied. Data descriptors and encryption headers are
  # part of the segment boundary checks.
  class ArchiveDelta
    # Magic signature at the start of every archive delta.
    MAGIC = 'RZDL'.b.freeze

    # Delta format version produced by this library.
    FORMAT_VERSION = 1

    # The complete local record (header, payload and any data descriptor) of
    # an unchanged entry is copied from the base archive.
    OP_SEGMENT = 1

    # A fresh local header is written and the compressed payload is copied
    # from the base archive. Used for renames.
    OP_PAYLOAD = 2

    # The complete local record is embedded in the delta.
    OP_BLOB = 3

    LOCAL_SIG        = 0x04034b50
    CDIR_SIG         = 0x02014b50
    EOCD_SIG         = 0x06054b50
    DATA_DESC_SIG    = 0x08074b50
    ZIP64_EXTRA_ID   = "\x01\x00".b.freeze
    DD_BIT           = 0b1000
    ENCRYPT_BIT      = 0b0001
    STATIC_EOCD_SIZE = 22

    LocalHeader = Struct.new( # :nodoc:
      :offset, :version_needed, :gp_flags, :method, :dos_time, :dos_date,
      :crc, :compressed_size, :size, :name, :extra, :header_length
    ) do
      def data_descriptor?
        (gp_flags & DD_BIT) == DD_BIT
      end

      def encrypted?
        (gp_flags & ENCRYPT_BIT) == ENCRYPT_BIT
      end
    end

    CentralRecord = Struct.new( # :nodoc:
      :version_made_by, :fstype, :version_needed, :gp_flags, :method,
      :dos_time, :dos_date, :crc, :compressed_size, :size, :name, :extra,
      :comment, :internal_attrs, :external_attrs, :local_header_offset,
      :raw
    )

    RawEntry = Struct.new( # :nodoc:
      :local, :cdir, :payload_offset, :data_descriptor, :segment_end
    ) do
      def segment_length
        segment_end - local.offset
      end
    end

    DataDescriptor = Struct.new(:crc, :compressed_size, :size, :signed) # :nodoc:

    DeltaEntry = Struct.new( # :nodoc:
      :op, :cdir_raw, :local_name, :local_extra, :local_version,
      :local_time, :local_date, :has_dd,
      :base_offset, :base_length, :payload_sha,
      :blob_offset, :blob_length
    )

    ParsedArchive = Struct.new(:raw, :entries, :cdir_offset, :comment) # :nodoc:

    class << self
      # Generate a delta that transforms +base_path+ into +target_path+.
      #
      # Returns the delta as a binary string. When +delta_path+ is given the
      # delta is written there and that path is returned instead.
      #
      # Raises DeltaError if either archive is malformed or cannot be
      # represented (for example because it spans disks or uses genuine
      # 64-bit ZIP64 offsets, which small-entry deltas do not need).
      def generate(base_path, target_path, delta_path: nil)
        delta = new.generate(base_path, target_path)
        if delta_path
          ::File.binwrite(delta_path, delta)
          delta_path
        else
          delta
        end
      end

      # Apply +delta+ to the archive at +base_path+ and write the result to
      # +output_path+.
      #
      # +delta+ is a binary delta string or a path to one. An existing
      # output file is kept unless +overwrite+ is true. All reuse
      # preconditions and digests are checked before writing begins. Raises
      # DeltaError on any failure, in which case no output is produced.
      def apply(base_path, delta, output_path, overwrite: false)
        new.apply(base_path, delta, output_path, overwrite: overwrite)
      end
    end

    # :nodoc:
    def generate(base_path, target_path)
      base = parse_archive(::File.binread(base_path))
      target = parse_archive(::File.binread(target_path))
      build_delta(base, target)
    end

    # :nodoc:
    def apply(base_path, delta, output_path, overwrite: false)
      base_raw = ::File.binread(base_path)
      delta_raw = delta.respond_to?(:read) ? delta.read : read_delta_input(delta)
      header, delta_entries, blob_section, body = parse_delta(delta_raw)
      base = parse_archive(base_raw)

      verify_digest(body, header[:delta_sha], 'delta')
      verify_digest(base_raw, header[:base_sha], 'base archive')

      if ::File.exist?(output_path) && !overwrite
        raise DeltaError, "Output already exists: #{output_path}"
      end

      planned = plan_entries(delta_entries, base, blob_section)
      assembled = assemble_output(header, planned)
      verify_output(assembled, header, delta_entries, planned, base)

      write_output_atomically(output_path, assembled)
      output_path
    end

    private

    def read_delta_input(delta)
      case delta
      when ::String
        binary_looks_like_delta?(delta) ? delta.b : ::File.binread(delta)
      else
        delta.read
      end
    end

    def binary_looks_like_delta?(string)
      string.start_with?(MAGIC)
    end

    # ---------- raw zip parsing ----------

    def parse_archive(raw)
      raise DeltaError, 'Archive is empty' if raw.nil? || raw.empty?

      cdir_offset, comment = parse_eocd(raw)
      entries = parse_central_directory(raw, cdir_offset)
      verify_archive_layout(raw, entries, cdir_offset)
      ParsedArchive.new(raw.b, entries, cdir_offset, comment.b)
    end

    def parse_eocd(raw)
      pos = raw.rindex([EOCD_SIG].pack('V'))
      raise DeltaError, 'End of central directory signature not found' unless pos
      if pos + STATIC_EOCD_SIZE > raw.bytesize
        raise DeltaError, 'Truncated end of central directory record'
      end

      _sig, disk, cdir_disk, count_disk, count, _cdir_size, cdir_offset,
        comment_length = raw.byteslice(pos, STATIC_EOCD_SIZE).unpack('VvvvvVVv')

      unless disk.zero? && cdir_disk.zero?
        raise DeltaError, 'Split/spanned archives are not supported by deltas'
      end

      if [count_disk, count].include?(0xFFFF) || cdir_offset == 0xFFFFFFFF
        raise DeltaError, 'Genuine ZIP64 archives are not supported by deltas'
      end

      comment = raw.byteslice(pos + STATIC_EOCD_SIZE, comment_length) || ''
      unless comment.bytesize == comment_length
        raise DeltaError, 'Truncated end of central directory comment'
      end

      [cdir_offset, comment]
    end

    def parse_central_directory(raw, cdir_offset)
      entries = []
      pos = cdir_offset
      while pos + 46 <= raw.bytesize
        sig = raw.byteslice(pos, 4).unpack1('V')
        break unless sig == CDIR_SIG

        record = parse_central_record(raw, pos)
        local = parse_local_header(raw, record.local_header_offset)
        payload_offset = record.local_header_offset + local.header_length
        # With a data descriptor the local header sizes are zero by design,
        # so the central directory is authoritative for the payload length.
        compressed_size = local.data_descriptor? ? record.compressed_size : local.compressed_size
        descriptor = local.data_descriptor? ?
                       parse_data_descriptor(raw, record, payload_offset + compressed_size) : nil
        segment_end = payload_offset + compressed_size +
                      (descriptor ? (descriptor.signed ? 16 : 12) : 0)

        local.compressed_size = compressed_size if local.data_descriptor?
        local.crc = record.crc if local.data_descriptor? && local.crc.zero?
        local.size = record.size if local.data_descriptor? && local.size.zero?
        entries << RawEntry.new(local, record, payload_offset, descriptor, segment_end)
        pos += 46 + record.name.bytesize + record.extra.bytesize + record.comment.bytesize
      end
      raise DeltaError, 'Central directory contains no entries or is corrupt' if entries.empty?

      entries
    end

    def parse_central_record(raw, pos)
      fields = raw.byteslice(pos, 46).unpack('VCCvvvvvVVVvvvvvVV')
      (sig, version_made_by, fstype, version_needed, gp_flags, method,
       dos_time, dos_date, crc, compressed_size, size, name_length,
       extra_length, comment_length, disk_number, internal_attrs,
       external_attrs, local_offset) = fields

      raise DeltaError, 'Bad central directory signature' unless sig == CDIR_SIG
      raise DeltaError, 'Split archives are not supported by deltas' unless disk_number.zero?

      name = raw.byteslice(pos + 46, name_length)
      extra = raw.byteslice(pos + 46 + name_length, extra_length)
      comment = raw.byteslice(pos + 46 + name_length + extra_length, comment_length)
      unless name && name.bytesize == name_length &&
             extra && extra.bytesize == extra_length &&
             comment && comment.bytesize == comment_length
        raise DeltaError, 'Truncated central directory entry'
      end

      if size == 0xFFFFFFFF || compressed_size == 0xFFFFFFFF || local_offset == 0xFFFFFFFF
        size, compressed_size, local_offset =
          resolve_zip64_fields(extra, size, compressed_size, local_offset)
      end
      raise DeltaError, 'Genuine ZIP64 archives are not supported by deltas' if
        size >= 0xFFFFFFFF || compressed_size >= 0xFFFFFFFF || local_offset >= 0xFFFFFFFF

      CentralRecord.new(
        version_made_by, fstype, version_needed, gp_flags, method,
        dos_time, dos_date, crc, compressed_size, size, name.b, extra.b,
        comment.b, internal_attrs, external_attrs, local_offset,
        raw.byteslice(pos, 46 + name_length + extra_length + comment_length).b
      )
    end

    def resolve_zip64_fields(extra, size, compressed_size, local_offset)
      parsed_size, parsed_compressed, parsed_offset = size, compressed_size, local_offset
      each_extra_field(extra) do |id, data|
        next unless id == ZIP64_EXTRA_ID

        cursor = 0
        if size == 0xFFFFFFFF
          parsed_size = read_zip64_uint(data, cursor)
          cursor += 8
        end
        if compressed_size == 0xFFFFFFFF
          parsed_compressed = read_zip64_uint(data, cursor)
          cursor += 8
        end
        if local_offset == 0xFFFFFFFF
          parsed_offset = read_zip64_uint(data, cursor)
        end
      end
      [parsed_size, parsed_compressed, parsed_offset]
    end

    def read_zip64_uint(data, cursor)
      slice = data.byteslice(cursor, 8)
      raise DeltaError, 'Truncated ZIP64 extra field' unless slice && slice.bytesize == 8

      slice.unpack1('Q<')
    end

    def each_extra_field(extra)
      pos = 0
      while pos + 4 <= extra.bytesize
        id = extra.byteslice(pos, 2)
        length = extra.byteslice(pos + 2, 2).unpack1('v')
        data = extra.byteslice(pos + 4, length)
        raise DeltaError, 'Truncated extra field' unless data && data.bytesize == length

        yield(id, data)
        pos += 4 + length
      end
      raise DeltaError, 'Trailing bytes in extra field block' unless pos == extra.bytesize
    end

    def parse_local_header(raw, offset)
      header = raw.byteslice(offset, 30)
      unless header && header.bytesize == 30
        raise DeltaError, "Missing local header at offset #{offset}"
      end

      sig, version_needed, _fstype, gp_flags, method, dos_time, dos_date,
        crc, compressed_size, size, name_length, extra_length =
        header.unpack('VCCvvvvVVVvv')
      raise DeltaError, "Bad local header signature at offset #{offset}" unless sig == LOCAL_SIG

      name = raw.byteslice(offset + 30, name_length)
      extra = raw.byteslice(offset + 30 + name_length, extra_length)
      raise DeltaError, 'Truncated local header' unless name && name.bytesize == name_length &&
                                                         extra && extra.bytesize == extra_length

      if size == 0xFFFFFFFF || compressed_size == 0xFFFFFFFF
        size, compressed_size, = resolve_zip64_fields(extra, size, compressed_size, 0)
      end

      LocalHeader.new(
        offset, version_needed, gp_flags, method, dos_time, dos_date, crc,
        compressed_size, size, name.b, extra.b, 30 + name_length + extra_length
      )
    end

    def parse_data_descriptor(raw, record, pos)
      signed = raw.byteslice(pos, 4)&.unpack1('V') == DATA_DESC_SIG
      start = signed ? pos + 4 : pos
      bytes = raw.byteslice(start, 12)
      unless bytes && bytes.bytesize == 12
        raise DeltaError, "Truncated data descriptor for '#{record.name}'"
      end

      crc, compressed_size, size = bytes.unpack('VVV')
      unless crc == record.crc && compressed_size == record.compressed_size && size == record.size
        raise DeltaError, "Data descriptor mismatch for '#{record.name}'"
      end

      DataDescriptor.new(crc, compressed_size, size, signed)
    end

    def verify_archive_layout(raw, entries, _cdir_offset = nil)
      sorted = entries.sort_by { |e| e.local.offset }
      sorted.each_cons(2) do |entry, next_entry|
        next unless entry.segment_end > next_entry.local.offset

        raise DeltaError, "Overlapping entry segments at '#{entry.cdir.name}'"
      end

      entries.each do |entry|
        if entry.segment_end > raw.bytesize
          raise DeltaError, "Entry segment runs past end of archive: '#{entry.cdir.name}'"
        end

        verify_local_matches_central(entry)
      end
    end

    def verify_local_matches_central(entry)
      local = entry.local
      cdir = entry.cdir
      checks = {
        name:            local.name == cdir.name,
        method:          local.method == cdir.method,
        gp_flags:        (local.gp_flags & ~DD_BIT) == (cdir.gp_flags & ~DD_BIT),
        dd_flag:         local.data_descriptor? == ((cdir.gp_flags & DD_BIT) == DD_BIT),
        crc:             local.crc == cdir.crc || local.data_descriptor?,
        size:            local.size == cdir.size || local.data_descriptor?,
        compressed_size: local.compressed_size == cdir.compressed_size || local.data_descriptor?,
        time:            local.dos_time == cdir.dos_time && local.dos_date == cdir.dos_date
      }
      bad = checks.reject { |_, ok| ok }.keys
      unless bad.empty?
        raise DeltaError,
              "Local header/central directory mismatch (#{bad.join(', ')}) for '#{cdir.name}'"
      end
    end

    # ---------- delta generation ----------

    def build_delta(base, target)
      used_base = {}
      blobs = +''.b
      delta_entries = target.entries.map do |target_entry|
        classify_entry(target_entry, base, target, used_base, blobs)
      end

      encode_delta(base, target, delta_entries, blobs)
    end

    def classify_entry(target_entry, base, target, used_base, blobs)
      same_offset_base = unused_base(base, used_base) do |base_entry|
        base_entry.local.offset == target_entry.local.offset
      end

      if same_offset_base && exact_segment_match?(target_entry, same_offset_base, target, base)
        used_base[same_offset_base.object_id] = true
        return segment_entry(target_entry, same_offset_base, target)
      end

      payload_base = unused_base(base, used_base) do |base_entry|
        payload_reusable?(target_entry, base_entry, target, base)
      end
      if payload_base
        used_base[payload_base.object_id] = true
        return payload_entry(target_entry, payload_base, target, base)
      end

      blob_entry(target_entry, target, blobs)
    end

    def unused_base(base, used_base)
      base.entries.find do |base_entry|
        !used_base[base_entry.object_id] && yield(base_entry)
      end
    end

    def exact_segment_match?(target_entry, base_entry, target, base)
      target_entry.local.name == base_entry.local.name &&
        record_bytes(target_entry, target) == record_bytes(base_entry, base)
    end

    def record_bytes(entry, archive)
      archive.raw.byteslice(entry.local.offset, entry.segment_length)
    end

    def payload_bytes(entry, archive)
      archive.raw.byteslice(entry.payload_offset, entry.local.compressed_size)
    end

    # Reuse of the compressed payload is only allowed when every boundary
    # relevant attribute matches: method, CRC, sizes, encryption flag, data
    # descriptor flag and general purpose flags. A matching name alone is
    # never enough.
    def payload_reusable?(target_entry, base_entry, target, base)
      t = target_entry.local
      b = base_entry.local
      t.method == b.method &&
        t.crc == b.crc &&
        t.size == b.size &&
        t.compressed_size == b.compressed_size &&
        t.encrypted? == b.encrypted? &&
        t.data_descriptor? == b.data_descriptor? &&
        t.gp_flags == b.gp_flags &&
        payload_bytes(target_entry, target) == payload_bytes(base_entry, base)
    end

    def common_delta_fields(entry)
      {
        cdir_raw:      entry.cdir.raw.dup,
        local_name:    entry.local.name.dup,
        local_extra:   entry.local.extra.dup,
        local_version: entry.local.version_needed,
        local_time:    entry.local.dos_time,
        local_date:    entry.local.dos_date,
        has_dd:        entry.local.data_descriptor?
      }
    end

    def segment_entry(target_entry, base_entry, target)
      fields = common_delta_fields(target_entry)
      entry = DeltaEntry.new(
        OP_SEGMENT, fields[:cdir_raw], fields[:local_name], fields[:local_extra],
        fields[:local_version], fields[:local_time], fields[:local_date],
        fields[:has_dd], base_entry.local.offset, base_entry.segment_length,
        +''.b, nil, nil
      )
      entry.payload_sha = Digest::SHA256.digest(payload_bytes(target_entry, target))
      entry
    end

    def payload_entry(target_entry, base_entry, target, _base)
      fields = common_delta_fields(target_entry)
      entry = DeltaEntry.new(
        OP_PAYLOAD, fields[:cdir_raw], fields[:local_name], fields[:local_extra],
        fields[:local_version], fields[:local_time], fields[:local_date],
        fields[:has_dd], base_entry.payload_offset,
        base_entry.local.compressed_size, +''.b, nil, nil
      )
      entry.payload_sha = Digest::SHA256.digest(payload_bytes(target_entry, target))
      entry
    end

    def blob_entry(target_entry, target, blobs)
      record = record_bytes(target_entry, target)
      fields = common_delta_fields(target_entry)
      entry = DeltaEntry.new(
        OP_BLOB, fields[:cdir_raw], fields[:local_name], fields[:local_extra],
        fields[:local_version], fields[:local_time], fields[:local_date],
        fields[:has_dd], 0, 0,
        Digest::SHA256.digest(payload_bytes(target_entry, target)),
        blobs.bytesize, record.bytesize
      )
      blobs << record
      entry
    end

    def encode_delta(base, target, delta_entries, blobs)
      body = +''.b
      body << [FORMAT_VERSION].pack('v')
      body << [target.entries.size].pack('Q<')
      body << [target.comment.bytesize].pack('Q<')
      body << target.comment
      delta_entries.each { |entry| encode_entry(body, entry) }
      body << [blobs.bytesize].pack('Q<')
      body << blobs

      header = MAGIC.dup
      header << Digest::SHA256.digest(base.raw)
      header << Digest::SHA256.digest(body) # body is complete at this point.
      header << body
      header << [body.bytesize].pack('Q<')
      header << [0x0404_4C5A].pack('V') # "ZLDD" tail marker.
      header
    end

    def encode_entry(body, entry)
      body << [entry.op].pack('C')
      write_blob_ref(body, entry.cdir_raw)
      write_blob_ref(body, entry.local_name)
      write_blob_ref(body, entry.local_extra)
      body << [entry.local_version, entry.local_time, entry.local_date,
               entry.has_dd ? 1 : 0,
               entry.base_offset || 0, entry.base_length || 0,
               entry.blob_offset || 0, entry.blob_length || 0].pack('vvvC Q<Q< Q<Q<')
      body << entry.payload_sha.to_s.ljust(32, "\0".b)
    end

    def write_blob_ref(body, bytes)
      body << [bytes.bytesize].pack('Q<')
      body << bytes
    end

    # ---------- delta parsing ----------

    def parse_delta(raw)
      raise DeltaError, 'Delta is empty' if raw.nil? || raw.empty?
      raise DeltaError, 'Bad delta magic' unless raw.start_with?(MAGIC)
      raise DeltaError, 'Delta is truncated' if raw.bytesize < 4 + 32 + 32 + 18 + 39 + 32 + 8 + 12

      base_sha = raw.byteslice(4, 32)
      delta_sha = raw.byteslice(36, 32)
      body_start = 68
      body_length_field = raw.byteslice(-12, 8)
      tail = raw.byteslice(-4, 4)
      raise DeltaError, 'Bad delta tail marker' unless tail == [0x0404_4C5A].pack('V')

      body_length = body_length_field.unpack1('Q<')
      expected_total = body_start + body_length + 8 + 4
      raise DeltaError, 'Delta length mismatch' unless expected_total == raw.bytesize

      body = raw.byteslice(body_start, body_length)
      cursor = 0
      version = read_uint(body, cursor, 2, 'v'); cursor += 2
      raise DeltaError, "Unsupported delta version: #{version}" unless version == FORMAT_VERSION

      entry_count = read_uint(body, cursor, 8, 'Q<'); cursor += 8
      comment_length = read_uint(body, cursor, 8, 'Q<'); cursor += 8
      comment = read_bytes(body, cursor, comment_length); cursor += comment_length

      entries = []
      entry_count.times do
        entry, cursor = parse_delta_entry(body, cursor)
        entries << entry
      end

      blob_length = read_uint(body, cursor, 8, 'Q<'); cursor += 8
      blob_section = read_bytes(body, cursor, blob_length); cursor += blob_length
      raise DeltaError, 'Trailing bytes in delta body' unless cursor == body.bytesize

      [
        { base_sha: base_sha.b, delta_sha: delta_sha.b, comment: comment.b },
        entries,
        blob_section.b,
        body
      ]
    end

    def parse_delta_entry(body, cursor)
      op = read_uint(body, cursor, 1, 'C'); cursor += 1
      cdir_raw, cursor = read_length_prefixed(body, cursor)
      local_name, cursor = read_length_prefixed(body, cursor)
      local_extra, cursor = read_length_prefixed(body, cursor)
      nums = read_bytes(body, cursor, 39); cursor += 39
      local_version, local_time, local_date, has_dd,
        base_offset, base_length, blob_offset, blob_length =
        nums.unpack('vvvC Q<Q< Q<Q<')
      payload_sha = read_bytes(body, cursor, 32); cursor += 32

      unless [OP_SEGMENT, OP_PAYLOAD, OP_BLOB].include?(op)
        raise DeltaError, "Unknown delta operation: #{op}"
      end

      [
        DeltaEntry.new(
        op, cdir_raw, local_name, local_extra, local_version,
        local_time, local_date, has_dd == 1,
        base_offset, base_length, payload_sha,
        blob_offset, blob_length
        ), cursor
      ]
    end

    def read_length_prefixed(body, cursor)
      length = read_uint(body, cursor, 8, 'Q<')
      bytes = read_bytes(body, cursor + 8, length)
      [bytes, cursor + 8 + length]
    end

    def read_uint(body, cursor, length, directive)
      bytes = body.byteslice(cursor, length)
      raise DeltaError, 'Unexpected end of delta' unless bytes && bytes.bytesize == length

      bytes.unpack1(directive)
    end

    def read_bytes(body, cursor, length)
      bytes = body.byteslice(cursor, length)
      raise DeltaError, 'Unexpected end of delta' unless bytes && bytes.bytesize == length

      bytes.b
    end

    def verify_digest(raw, expected, label)
      actual = Digest::SHA256.digest(raw)
      return if actual == expected

      raise DeltaError, "SHA-256 mismatch for #{label}"
    end

    # ---------- planning and assembly ----------

    PlannedEntry = Struct.new( # :nodoc:
      :delta_entry, :local_header_bytes, :payload,
      :data_descriptor_bytes, :base_entry
    )

    def plan_entries(delta_entries, base, blob_section)
      delta_entries.map do |entry|
        plan_entry(entry, base, blob_section)
      end
    end

    def plan_entry(entry, base, blob_section)
      case entry.op
      when OP_SEGMENT
        plan_segment(entry, base)
      else
        target_local = build_target_local_header(entry)
        payload, descriptor, base_entry =
          case entry.op
          when OP_PAYLOAD
            plan_payload(entry, base)
          when OP_BLOB
            plan_blob(entry, blob_section)
          end
        PlannedEntry.new(entry, target_local, payload, descriptor, base_entry)
      end
    end

    def plan_segment(entry, base)
      base_entry = base.entries.find { |e| e.local.offset == entry.base_offset }
      unless base_entry
        raise DeltaError,
              "Base entry missing for reused segment at offset #{entry.base_offset}"
      end
      unless base_entry.segment_length == entry.base_length
        raise DeltaError, 'Base segment length mismatch'
      end

      record = base.raw.byteslice(entry.base_offset, entry.base_length)
      header_length = 30 + entry.local_name.bytesize + entry.local_extra.bytesize
      local_header = record.byteslice(0, header_length)
      verify_segment_header(local_header, entry)

      payload_offset = local_header.bytesize
      payload = record.byteslice(payload_offset, base_entry.local.compressed_size)
      raise DeltaError, 'Reused payload digest mismatch' unless
        Digest::SHA256.digest(payload) == entry.payload_sha

      descriptor = record.byteslice(payload_offset + payload.bytesize,
                                   record.bytesize - payload_offset - payload.bytesize)
      raise DeltaError, 'Segment data descriptor mismatch' unless
        descriptor.empty? == !entry.has_dd

      PlannedEntry.new(entry, local_header, payload, descriptor, base_entry)
    end

    def verify_segment_header(header, entry)
      raise DeltaError, 'Segment local header too short' unless header.bytesize >= 30
      raise DeltaError, 'Segment local header has bad signature' unless
        header.byteslice(0, 4).unpack1('V') == LOCAL_SIG
      values = header.unpack('VCCvvvvVVVvv')
      _sig, version, _fstype, gp_flags, method, time, date, _crc,
        _cs, _size, name_length, extra_length = values
      checks = {
        version: version == entry.local_version,
        gp_flags: gp_flags == expected_gp_flags(entry),
        method: method == entry_wire_method_from_cdir(entry),
        time: time == entry.local_time && date == entry.local_date,
        name_length: name_length == entry.local_name.bytesize,
        extra_length: extra_length == entry.local_extra.bytesize,
        dd_flag: ((gp_flags & DD_BIT) == DD_BIT) == entry.has_dd
      }
      checks[:name] = header.byteslice(30, name_length) == entry.local_name
      checks[:extra] = header.byteslice(30 + name_length, extra_length) == entry.local_extra
      bad = checks.reject { |_, ok| ok }.keys
      raise DeltaError, "Segment header mismatch: #{bad.join(', ')}" unless bad.empty?
    end

    def expected_gp_flags(entry)
      (cdir_value(entry, :gp_flags) & ~DD_BIT) | (entry.has_dd ? DD_BIT : 0)
    end

    def plan_payload(entry, base)
      base_entry = base.entries.find { |e| e.payload_offset == entry.base_offset }
      raise DeltaError, "Base payload missing at offset #{entry.base_offset}" unless base_entry
      unless base_entry.local.compressed_size == entry.base_length
        raise DeltaError, 'Base payload length mismatch'
      end

      payload = base.raw.byteslice(entry.base_offset, entry.base_length)
      raise DeltaError, 'Reused payload digest mismatch' unless
        Digest::SHA256.digest(payload) == entry.payload_sha
      raise DeltaError, 'Payload reuse metadata mismatch' unless
        reusable_with?(entry, base_entry.local)

      [payload, descriptor_for(entry), base_entry]
    end

    def reusable_with?(entry, base_local)
      target = cdir_static_fields(entry)
      target[:method] == base_local.method && target[:crc] == base_local.crc &&
        target[:size] == base_local.size &&
        target[:compressed_size] == base_local.compressed_size &&
        (target[:gp_flags] & ENCRYPT_BIT) == (base_local.gp_flags & ENCRYPT_BIT) &&
        (target[:gp_flags] & DD_BIT) == (base_local.gp_flags & DD_BIT)
    end

    def descriptor_for(entry)
      return +''.b unless entry.has_dd

      fields = cdir_static_fields(entry)
      crc = fields[:crc]
      compressed_size = fields[:compressed_size]
      size = fields[:size]
      [DATA_DESC_SIG, crc, compressed_size, size].pack('VVVV').b
    end

    def plan_blob(entry, blob_section)
      record = blob_section.byteslice(entry.blob_offset, entry.blob_length)
      unless record && record.bytesize == entry.blob_length
        raise DeltaError, 'Blob data missing or truncated'
      end

      target_header = build_target_local_header(entry)
      header_length = target_header.bytesize
      raise DeltaError, 'Blob local header does not match delta metadata' unless
        record.byteslice(0, header_length) == target_header

      fields = cdir_static_fields(entry)
      compressed_size = fields[:compressed_size]
      payload = record.byteslice(header_length, compressed_size)
      descriptor = record.byteslice(header_length + compressed_size,
                                    record.bytesize - header_length - compressed_size)
      raise DeltaError, 'Blob descriptor flag mismatch' unless
        descriptor.empty? != entry.has_dd
      raise DeltaError, 'Blob descriptor length invalid' unless descriptor.empty? ||
        descriptor.bytesize == (descriptor.byteslice(0, 4).unpack1('V') == DATA_DESC_SIG ? 16 : 12)
      verify_descriptor_values(descriptor, fields)
      raise DeltaError, 'Blob payload digest mismatch' unless
        Digest::SHA256.digest(payload) == entry.payload_sha

      [payload, descriptor, nil]
    end

    def verify_descriptor_values(descriptor, fields)
      return if descriptor.empty?

      signed = descriptor.byteslice(0, 4).unpack1('V') == DATA_DESC_SIG
      values = descriptor.byteslice(signed ? 4 : 0, 12).unpack('VVV')
      return if values == [fields[:crc], fields[:compressed_size], fields[:size]]

      raise DeltaError, 'Blob data descriptor values mismatch'
    end

    def build_target_local_header(entry)
      name_length = entry.local_name.bytesize
      extra_length = entry.local_extra.bytesize
      sizes = target_header_sizes(entry)
      [
        LOCAL_SIG, entry.local_version, 0, # host system unused on local header
        expected_gp_flags(entry), entry_wire_method_from_cdir(entry),
        entry.local_time, entry.local_date,
        entry.has_dd ? 0 : cdir_value(entry, :crc),
        entry.has_dd ? sizes[:dd_compressed_size] : sizes[:compressed_size],
        entry.has_dd ? sizes[:dd_size] : sizes[:size],
        name_length, extra_length
      ].pack('VCCvvvvVVVvv') + entry.local_name + entry.local_extra
    end

    def target_header_sizes(entry)
      size, compressed = cdir_sizes(entry)
      has_zip64 = false
      each_extra_field(entry.local_extra) { |id, _| has_zip64 ||= id == ZIP64_EXTRA_ID }
      raise DeltaError, 'Entry sizes need genuine ZIP64 support' if
        size >= 0xFFFFFFFF || compressed >= 0xFFFFFFFF

      if has_zip64
        {
          size: 0xFFFFFFFF, compressed_size: 0xFFFFFFFF,
          dd_size: 0xFFFFFFFF, dd_compressed_size: 0xFFFFFFFF
        }
      else
        {
          size: size, compressed_size: compressed,
          dd_size: 0, dd_compressed_size: 0
        }
      end
    end

    def cdir_sizes(entry)
      fields = cdir_static_fields(entry)
      [fields[:size], fields[:compressed_size]]
    end

    def cdir_value(entry, key)
      cdir_static_fields(entry)[key]
    end

    def cdir_static_fields(entry)
      @cdir_fields_cache ||= {}
      @cdir_fields_cache[entry.cdir_raw.object_id] ||= begin
        values = entry.cdir_raw.unpack('VCCvvvvvVVVvvvvvVV')
        size = values[10]
        compressed_size = values[9]
        gp_flags = values[4]
        name_length = values[11]
        extra_length = values[12]
        extra = entry.cdir_raw.byteslice(46 + name_length, extra_length)
        if size == 0xFFFFFFFF || compressed_size == 0xFFFFFFFF
          size, compressed_size, = resolve_zip64_fields(extra, size, compressed_size, 0)
        end
        {
          crc: values[8], compressed_size: compressed_size, size: size,
          gp_flags: gp_flags, method: values[5]
        }
      end
    end

    def entry_wire_method_from_cdir(entry)
      cdir_value(entry, :method)
    end

    # ---------- output assembly ----------

    def assemble_output(header, planned)
      out = +''.b
      offsets = {}

      planned.each do |planned_entry|
        entry = planned_entry.delta_entry
        offsets[entry.object_id] = out.bytesize
        out << planned_entry.local_header_bytes
        out << planned_entry.payload
        out << planned_entry.data_descriptor_bytes
      end

      cdir_offset = out.bytesize
      planned.each do |planned_entry|
        entry = planned_entry.delta_entry
        out << patched_central_record(entry.cdir_raw, offsets[entry.object_id])
      end

      cdir_size = out.bytesize - cdir_offset
      raise DeltaError, 'Output archive needs genuine ZIP64 support' if
        cdir_offset > 0xFFFFFFFF || cdir_size > 0xFFFFFFFF || planned.size > 0xFFFF
      out << [
        EOCD_SIG, 0, 0, planned.size, planned.size,
        cdir_size, cdir_offset, header[:comment].bytesize
      ].pack('VvvvvVVv')
      out << header[:comment]
      out
    end

    def patched_central_record(raw, offset)
      raise DeltaError, 'Output offset exceeds 32-bit ZIP limit' if offset > 0xFFFFFFFF

      values = raw.unpack('VCCvvvvvVVVvvvvvVV')
      values[17] = offset
      values.pack('VCCvvvvvVVVvvvvvVV') +
        raw.byteslice(46, raw.bytesize - 46)
    end

    def verify_output(assembled, header, delta_entries, planned, base)
      reparsed = parse_archive(assembled)
      unless reparsed.entries.size == delta_entries.size
        raise DeltaError, 'Output entry count mismatch'
      end
      raise DeltaError, 'Output comment mismatch' unless reparsed.comment == header[:comment]

      reparsed.entries.each_with_index do |entry, index|
        delta_entry = delta_entries[index]
        raise DeltaError, 'Output entry order/name mismatch' unless
          entry.local.name == delta_entry.local_name
        raise DeltaError, 'Output central directory raw mismatch' unless
          normalize_cdir_record(entry.cdir.raw) == normalize_cdir_record(delta_entry.cdir_raw)
        payload = assembled.byteslice(entry.payload_offset, entry.local.compressed_size)
        raise DeltaError, 'Output payload digest mismatch' unless
          Digest::SHA256.digest(payload) == delta_entry.payload_sha
        if [OP_SEGMENT, OP_PAYLOAD].include?(delta_entry.op)
          raise DeltaError, 'Reused payload is not present in base archive' unless
            payload_present_in_base?(payload, base)
        end

        next unless delta_entry.op == OP_BLOB

        planned_entry = planned[index]
        raise DeltaError, 'Output local record does not match delta blob' unless
          assembled.byteslice(entry.local.offset, entry.segment_length) ==
            planned_entry.local_header_bytes + planned_entry.payload +
              planned_entry.data_descriptor_bytes
      end
    end

    def payload_present_in_base?(payload, base)
      base.entries.any? do |base_entry|
        base_entry.local.compressed_size == payload.bytesize &&
          base.raw.byteslice(base_entry.payload_offset, payload.bytesize) == payload
      end
    end

    def normalize_cdir_record(raw)
      values = raw.unpack('VCCvvvvvVVVvvvvvVV')
      values[17] = 0
      values.pack('VCCvvvvvVVVvvvvvVV') + raw.byteslice(46, raw.bytesize - 46)
    end

    def write_output_atomically(output_path, assembled)
      dir = ::File.dirname(::File.expand_path(output_path))
      ::FileUtils.mkdir_p(dir)
      ::Tempfile.create(['zip-delta', '.zip'], dir) do |tmp|
        tmp.binmode
        tmp.write(assembled)
        tmp.flush
        begin
          ::File.chmod(0o600, tmp.path)
        rescue SystemCallError
          nil
        end
        ::File.rename(tmp.path, output_path)
      end
    end
  end
end
