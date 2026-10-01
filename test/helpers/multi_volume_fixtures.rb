# frozen_string_literal: true

# Helpers for building small multi-volume (split/spanned) zip archives in
# memory, for the multi-volume reading tests. A regular zip is built with
# rubyzip itself, taken apart, and reassembled so that it can be cut into
# disks at arbitrary byte offsets; cutting rewrites the central directory
# and end records with the disk-relative offsets and disk numbers that a
# real multi-volume archiver would have written.
module MultiVolumeFixtures
  EOCD_SIGNATURE = 0x06054b50
  EOCD_STATIC_SIZE = 22
  ZIP64_EOCD_SIGNATURE = 0x06064b50
  ZIP64_EOCD_STATIC_SIZE = 56
  ZIP64_LOCATOR_SIGNATURE = 0x07064b50
  ZIP64_LOCATOR_SIZE = 20
  CDIR_ENTRY_STATIC_HEADER_LENGTH = 46
  LOCAL_ENTRY_STATIC_HEADER_LENGTH = 30
  ZIP64_EXTRA_ID = 0x0001

  # Builds a fixture archive. +entries+ is a list of
  # [name, content] or [name, content, :stored] triples.
  def self.build(entries, zip64: false)
    Archive.new(entries, zip64: zip64)
  end

  # An array of disk contents (binary strings) that knows where the
  # archive was cut, so tests can map global archive offsets onto disks.
  class Disks < Array
    def initialize(disks, cuts)
      super()
      replace(disks)
      @cuts = cuts
    end

    # Maps a global archive offset to a [disk_number, offset_within_disk]
    # pair.
    def locate(global)
      disk = @cuts.index { |cut| global < cut } || @cuts.size
      [disk, global - (disk.zero? ? 0 : @cuts[disk - 1])]
    end

    # Replaces the bytes at a global archive offset, in place.
    def patch(global, packed)
      disk, rel = locate(global)
      self[disk][rel, packed.bytesize] = packed
    end
  end

  # A zip archive built for splitting: holds the uncut archive bytes and
  # the position of every record, so that #cut can split the bytes into
  # disks and rewrite the disk-relative offsets and disk numbers that a
  # multi-volume archive's central directory and end records must carry.
  class Archive
    attr_reader :entry_count, :cdir_offset, :eocd_offset,
                :zip64_eocd_offset, :zip64_locator_offset

    def initialize(entries, zip64: false)
      @zip64 = zip64
      parse_source(build_single_disk_zip(entries))
      layout_archive
    end

    def zip64?
      @zip64
    end

    # The uncut archive bytes, as one binary string.
    def bytes
      @bytes
    end

    def size
      @bytes.bytesize
    end

    def local_header_offset(name)
      cdir_entry(name)[:local_offset]
    end

    def data_offset(name)
      offset = local_header_offset(name)
      name_length = @bytes[offset + 26, 2].unpack1('v')
      extra_length = @bytes[offset + 28, 2].unpack1('v')
      offset + LOCAL_ENTRY_STATIC_HEADER_LENGTH + name_length + extra_length
    end

    def cdir_entry_offset(name)
      @cdir_entry_positions[@cdir_entries.index { |entry| entry[:name] == name }]
    end

    # Splits the archive at the given (ascending) global byte offsets and
    # returns a Disks array with all disk numbers and disk-relative offsets
    # rewritten accordingly.
    def cut(*offsets)
      validate_cuts(offsets)
      disks = Disks.new(slice_at(offsets), offsets)
      patch_cdir_entries(disks)
      patch_end_records(disks)
      disks
    end

    private

    def build_single_disk_zip(entries)
      buffer = ::Zip::OutputStream.write_buffer(suppress_extra_fields: true) do |zos|
        entries.each do |name, content, *rest|
          method = rest.first == :stored ? ::Zip::Entry::STORED : ::Zip::Entry::DEFLATED
          zos.put_next_entry(name, '', nil, method)
          zos.write(content)
        end
      end
      buffer.string
    end

    def parse_source(source)
      eocd_at = source.rindex([EOCD_SIGNATURE].pack('V'))
      @entry_count = source[eocd_at + 10, 2].unpack1('v')
      cdir_size = source[eocd_at + 12, 4].unpack1('V')
      @cdir_offset = source[eocd_at + 16, 4].unpack1('V')
      @local_part = source[0...@cdir_offset]

      @cdir_entries = []
      pos = @cdir_offset
      @entry_count.times do
        fields = source[pos, CDIR_ENTRY_STATIC_HEADER_LENGTH].unpack('VCCvvvvvVVVvvvvvVV')
        name = source[pos + 46, fields[11]]
        extra = source[pos + 46 + fields[11], fields[12]]
        comment = source[pos + 46 + fields[11] + fields[12], fields[13]]
        @cdir_entries << {
          fields: fields, name: name, extra: extra, comment: comment,
          local_offset: fields[17]
        }
        pos += CDIR_ENTRY_STATIC_HEADER_LENGTH + fields[11] + fields[12] + fields[13]
      end
      raise 'fixture sanity check failed' unless pos == @cdir_offset + cdir_size
    end

    # Lays out the final archive bytes: the untouched local part, a rebuilt
    # central directory and the end records. Disk numbers and disk-relative
    # offsets are left as zero placeholders; #cut patches them once the
    # disk boundaries are known.
    def layout_archive
      cdir = +''.b
      @cdir_entry_positions = []
      @cdir_entries.each do |entry|
        @cdir_entry_positions << @cdir_offset + cdir.bytesize
        fields = entry[:fields].dup
        extra = entry[:extra]
        if @zip64
          fields[3] = [fields[3], 45].max # version needed to extract
          fields[14] = 0xFFFF             # disk number start
          fields[17] = 0xFFFFFFFF         # relative local header offset
          entry[:zip64_extra_at] =
            @cdir_offset + cdir.bytesize + CDIR_ENTRY_STATIC_HEADER_LENGTH +
            fields[11] + extra.bytesize + 4
          extra += [ZIP64_EXTRA_ID, 12, 0, 0].pack('vvQ<V')
          fields[12] += 16
        end
        cdir << fields.pack('VCCvvvvvVVVvvvvvVV')
        cdir << entry[:name] << extra << entry[:comment]
      end
      @cdir_size = cdir.bytesize
      @bytes = @local_part + cdir + build_tail(@cdir_offset + @cdir_size)
    end

    def build_tail(tail_at)
      if @zip64
        @zip64_eocd_offset = tail_at
        @zip64_locator_offset = tail_at + ZIP64_EOCD_STATIC_SIZE
        @eocd_offset = @zip64_locator_offset + ZIP64_LOCATOR_SIZE
        [ZIP64_EOCD_SIGNATURE, 44, 45, 45, 0, 0, 0, 0, @cdir_size, 0].pack('VQ<vvVVQ<Q<Q<Q<') <<
          [ZIP64_LOCATOR_SIGNATURE, 0, 0, 0].pack('VVQ<V') <<
          [EOCD_SIGNATURE, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0]
          .pack('VvvvvVVv')
      else
        @eocd_offset = tail_at
        [EOCD_SIGNATURE, 0, 0, 0, 0, @cdir_size, 0, 0].pack('VvvvvVVv')
      end
    end

    def validate_cuts(offsets)
      raise ArgumentError, 'cut offsets must be ascending' unless offsets.each_cons(2).all? { |a, b| a < b }
      return if offsets.empty? || (offsets.first.positive? && offsets.last < size)

      raise ArgumentError, 'cut offsets must lie inside the archive'
    end

    def slice_at(offsets)
      disks = []
      previous = 0
      offsets.each do |offset|
        disks << @bytes[previous...offset]
        previous = offset
      end
      disks << @bytes[previous..]
      disks
    end

    def patch_cdir_entries(disks)
      @cdir_entries.each_with_index do |entry, index|
        disk, rel = disks.locate(entry[:local_offset])
        if @zip64
          disks.patch(entry[:zip64_extra_at], [rel].pack('Q<'))
          disks.patch(entry[:zip64_extra_at] + 8, [disk].pack('V'))
        else
          disks.patch(@cdir_entry_positions[index] + 34, [disk].pack('v'))
          disks.patch(@cdir_entry_positions[index] + 42, [rel].pack('V'))
        end
      end
    end

    def patch_end_records(disks)
      cdir_disk, cdir_rel = disks.locate(@cdir_offset)
      entries_on_last_disk = @cdir_entry_positions.count do |pos|
        disks.locate(pos).first == disks.size - 1
      end

      if @zip64
        disks.patch(@zip64_eocd_offset + 16, [disks.size - 1].pack('V'))
        disks.patch(@zip64_eocd_offset + 20, [cdir_disk].pack('V'))
        disks.patch(@zip64_eocd_offset + 24, [entries_on_last_disk].pack('Q<'))
        disks.patch(@zip64_eocd_offset + 32, [@entry_count].pack('Q<'))
        disks.patch(@zip64_eocd_offset + 48, [cdir_rel].pack('Q<'))
        zip64_disk, zip64_rel = disks.locate(@zip64_eocd_offset)
        disks.patch(@zip64_locator_offset + 4, [zip64_disk].pack('V'))
        disks.patch(@zip64_locator_offset + 8, [zip64_rel].pack('Q<'))
        disks.patch(@zip64_locator_offset + 16, [disks.size].pack('V'))
      else
        disks.patch(@eocd_offset + 4, [disks.size - 1].pack('v'))
        disks.patch(@eocd_offset + 6, [cdir_disk].pack('v'))
        disks.patch(@eocd_offset + 8, [entries_on_last_disk].pack('v'))
        disks.patch(@eocd_offset + 10, [@entry_count].pack('v'))
        disks.patch(@eocd_offset + 16, [cdir_rel].pack('V'))
      end
    end

    def cdir_entry(name)
      entry = @cdir_entries.find { |candidate| candidate[:name] == name }
      raise "no such entry in fixture: #{name}" unless entry

      entry
    end
  end
end
