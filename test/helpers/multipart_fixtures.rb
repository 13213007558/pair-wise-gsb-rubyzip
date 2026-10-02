# frozen_string_literal: true

require 'stringio'

# Builders for the small, artificial split (multi-volume) archives used
# by the multipart tests. Everything is built in memory; nothing touches
# the filesystem. Each fixture is derived from the same tiny reference
# archive so that what is read back can be compared with the unsplit
# version.
module MultipartFixtures
  EOCD_SIG         = [0x06054b50].pack('V')
  ZIP64_EOCD_SIZE  = 56
  LOCATOR_SIZE     = 20
  EOCD_STATIC_SIZE = 22
  CDIR_STATIC_SIZE = 46
  SPLIT_SIG        = [::Zip::SPLIT_FILE_SIGNATURE].pack('V')

  ENTRY_CONTENTS = {
    'stored.txt'     => 'Store me! ' * 40,
    'deflated.txt'   => 'deflate me, deflate me! ' * 200,
    'dir/nested.bin' => Random.new(42).bytes(3_000)
  }.freeze
  DIRECTORY_NAME  = 'dir/'
  ARCHIVE_COMMENT = 'multipart fixture comment'

  module_function

  # The reference archive: a single, unsplit zip in a String.
  def build_unsplit_archive
    ::Zip::OutputStream.write_buffer(StringIO.new) do |zos|
      zos.put_next_entry('stored.txt', '', ::Zip::ExtraField.new, ::Zip::Entry::STORED)
      zos << ENTRY_CONTENTS['stored.txt']
      zos.put_next_entry('deflated.txt')
      zos << ENTRY_CONTENTS['deflated.txt']
      zos.put_next_entry(DIRECTORY_NAME)
      zos.put_next_entry('dir/nested.bin')
      zos << ENTRY_CONTENTS['dir/nested.bin']
      zos.comment = ARCHIVE_COMMENT
    end.string
  end

  # { entry name => contents } for every entry in an open Zip::File;
  # directory entries map to nil.
  def read_all_entries(zip_file)
    zip_file.entries.each_with_object({}) do |entry, hash|
      hash[entry.name] = entry.directory? ? nil : zip_file.read(entry)
    end
  end

  # The spans (flat offsets) of the structures that the fixtures split
  # across volume boundaries: the first entry's local header, the second
  # entry's compressed data, the central directory and the EOCD record.
  def structure_spans(data)
    info = eocd_info(data)
    zf = ::Zip::File.open_buffer(StringIO.new(data))

    lh0 = zf.find_entry('stored.txt').local_header_offset
    nlen, xlen = data[lh0 + 26, 4].unpack('vv')

    entry = zf.find_entry('deflated.txt')
    elen, xextra = data[entry.local_header_offset + 26, 4].unpack('vv')
    data_start = entry.local_header_offset + 30 + elen + xextra

    {
      local_header:      lh0...(lh0 + 30 + nlen + xlen),
      compressed_data:   data_start...(data_start + entry.compressed_size),
      central_directory: info[:cdir_offset]...(info[:cdir_offset] + info[:cdir_size]),
      eocd:              info[:eocd_offset]...(info[:eocd_offset] + EOCD_STATIC_SIZE + info[:comment_length])
    }
  end

  # One split boundary inside each structure returned by
  # structure_spans, so that every structure crosses a volume boundary
  # exactly once.
  def structure_boundaries(data)
    structure_spans(data).values.map { |span| span.begin + (span.size / 2) }.sort
  end

  # Splits the archive naively: the volumes are plain byte ranges of the
  # original archive, so every offset stays global and every disk number
  # in the archive remains 0.
  def build_naive_volumes(data, boundaries)
    split_at(data, boundaries)
  end

  # Splits the archive APPNOTE-style: the first volume starts with the
  # split-file signature, and the disk numbers and offsets in the
  # central directory entries and the EOCD are rewritten to be relative
  # to the disk on which each structure starts.
  def build_appnote_volumes(data, boundaries)
    delta = SPLIT_SIG.bytesize
    flat = SPLIT_SIG + data
    volumes = split_at(flat, boundaries.map { |b| b + delta })
    bases = cumulative_bases(volumes)
    info = eocd_info(data)

    entry_disks = patch_cdir_entries!(volumes, bases, flat, info[:cdir_offset] + delta, info[:entries], delta)

    flat_eocd = info[:eocd_offset] + delta
    flat_cdir = info[:cdir_offset] + delta
    cdir_disk = disk_of(bases, flat_cdir)
    poke(volumes, bases, flat_eocd + 4, [volumes.size - 1].pack('v'))           # number of this disk
    poke(volumes, bases, flat_eocd + 6, [cdir_disk].pack('v'))                  # disk with start of cdir
    poke(volumes, bases, flat_eocd + 8, [entry_disks.count(volumes.size - 1)].pack('v'))
    poke(volumes, bases, flat_eocd + 16, [flat_cdir - bases[cdir_disk]].pack('V'))
    volumes
  end

  # Replaces the EOCD with a zip64 EOCD record, a zip64 locator and a
  # 0xFFFF-marked EOCD, then splits APPNOTE-style (without the split
  # signature) so that the central directory starts on a later disk and
  # both the zip64 EOCD record and the EOCD cross a volume boundary.
  def build_zip64_volumes(data)
    info = eocd_info(data)
    comment = data[info[:eocd_offset] + EOCD_STATIC_SIZE, info[:comment_length]]

    z64_off = info[:eocd_offset]
    loc_off = z64_off + ZIP64_EOCD_SIZE
    new_eocd_off = loc_off + LOCATOR_SIZE

    flat =
      data[0...info[:eocd_offset]] +
      [0x06064b50, 44, 45, 45, 0, 0, info[:entries], info[:entries],
       info[:cdir_size], info[:cdir_offset]].pack('VQ<vvVVQ<Q<Q<Q<') +
      [0x07064b50, 0, 0, 1].pack('VVQ<V') +
      [0x06054b50, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
       info[:comment_length]].pack('VvvvvVVv') +
      comment

    boundaries = [
      info[:cdir_offset] - 100, # so the central directory starts on disk 1
      info[:cdir_offset] + 50,  # inside the central directory
      z64_off + 30,             # inside the zip64 EOCD record
      new_eocd_off + 10         # inside the EOCD record
    ]
    volumes = split_at(flat, boundaries)
    bases = cumulative_bases(volumes)

    patch_cdir_entries!(volumes, bases, flat, info[:cdir_offset], info[:entries], 0)

    cdir_disk = disk_of(bases, info[:cdir_offset])
    poke(volumes, bases, z64_off + 16, [volumes.size - 1].pack('V'))  # number of this disk
    poke(volumes, bases, z64_off + 20, [cdir_disk].pack('V'))         # disk with start of cdir
    poke(volumes, bases, z64_off + 48, [info[:cdir_offset] - bases[cdir_disk]].pack('Q<'))

    z64_disk = disk_of(bases, z64_off)
    poke(volumes, bases, loc_off + 4, [z64_disk].pack('V'))
    poke(volumes, bases, loc_off + 8, [z64_off - bases[z64_disk]].pack('Q<'))
    poke(volumes, bases, loc_off + 16, [volumes.size].pack('V'))
    volumes
  end

  def eocd_info(data)
    eocd_off = data.rindex(EOCD_SIG)
    _, this_disk, cdir_disk, _, entries, cdir_size, cdir_off, comment_len =
      data[eocd_off, EOCD_STATIC_SIZE].unpack('VvvvvVVv')
    {
      eocd_offset: eocd_off, this_disk: this_disk, cdir_disk: cdir_disk,
      entries: entries, cdir_size: cdir_size, cdir_offset: cdir_off,
      comment_length: comment_len
    }
  end

  def split_at(flat, boundaries)
    volumes = []
    pos = 0
    boundaries.each { |b| volumes << flat[pos...b]; pos = b }
    volumes << flat[pos..]
    volumes
  end

  def cumulative_bases(volumes)
    bases = []
    total = 0
    volumes.each { |v| bases << total; total += v.bytesize }
    bases
  end

  def disk_of(bases, pos)
    disk = bases.size - 1
    disk -= 1 while disk.positive? && bases[disk] > pos
    disk
  end

  # Writes +bytes+ into the volumes at a flat offset, crossing a volume
  # boundary if the field itself straddles one.
  def poke(volumes, bases, flat_pos, bytes)
    bytes.each_byte do |byte|
      disk = disk_of(bases, flat_pos)
      volumes[disk].setbyte(flat_pos - bases[disk], byte)
      flat_pos += 1
    end
  end

  # Rewrites the disk-number and local-header-offset fields of every
  # central directory entry so they are relative to the disk on which
  # the entry's local header starts. +delta+ is the shift between the
  # offsets stored in +flat+ and flat coordinates (the size of the split
  # signature, if one was prepended). Returns the disk of each entry's
  # central directory record.
  def patch_cdir_entries!(volumes, bases, flat, cdir_offset, entry_count, delta)
    entry_disks = []
    pos = cdir_offset
    entry_count.times do
      nlen, xlen, clen = flat[pos + 28, 6].unpack('vvv')
      rel = flat[pos + 42, 4].unpack1('V') + delta
      disk = disk_of(bases, rel)
      poke(volumes, bases, pos + 34, [disk].pack('v'))
      poke(volumes, bases, pos + 42, [rel - bases[disk]].pack('V'))
      entry_disks << disk_of(bases, pos)
      pos += CDIR_STATIC_SIZE + nlen + xlen + clen
    end
    entry_disks
  end
end
