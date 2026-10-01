# frozen_string_literal: true

require 'stringio'
require 'zlib'

# Builds very small multi-volume ZIP archives out of hand-packed records,
# so that cuts can be placed in the middle of local headers, compressed
# data, central directory records and end-of-central-directory records.
#
# Every offset written into the archive is relative to the start of the
# disk the record ends up on, exactly as the ZIP specification requires
# for a multi-volume archive.
module MultiVolumeFixtures
  CDIR_SIGNATURE          = 0x02014b50
  LOCAL_SIGNATURE         = 0x04034b50
  EOCD_SIGNATURE          = 0x06054b50
  ZIP64_EOCD_SIGNATURE    = 0x06064b50
  ZIP64_LOCATOR_SIGNATURE = 0x07064b50
  SPANNING_SIGNATURE      = 0x08074b50

  # @param entries [Array<Hash>] +:name+, +:data+, +:method+ (0/8).
  # @param zip64_entry [String, nil] name of an entry whose start disk is
  #   recorded through a Zip64 extra field (base header set to 0xFFFF).
  # @param zip64_eocd [Boolean] emit a Zip64 EOCD plus locator.
  #
  # @return [Array(String, Hash)] the archive bytes and a layout Hash with
  #   the local-header offsets and central-directory position.
  def self.build_zip(entries, zip64_entry: nil, zip64_eocd: false)
    locals = +''.b
    central_directory = +''.b
    local_offsets = []

    entries.each do |entry|
      name = entry[:name].b
      data = entry[:data].b
      compressed =
        if entry[:method] == 8
          deflater = Zlib::Deflate.new(Zlib::DEFAULT_COMPRESSION, -Zlib::MAX_WBITS)
          result = deflater.deflate(data, Zlib::FINISH)
          deflater.close
          result
        else
          data
        end
      crc = Zlib.crc32(data)

      local_offsets << locals.bytesize
      locals << [
        LOCAL_SIGNATURE, 20, 0, entry[:method], 0, 0x4021, 0x21,
        compressed.bytesize, data.bytesize, name.bytesize, 0
      ].pack('VvvvvvVVVvv')
      locals << name
      locals << compressed

      extra = +''.b
      disk_base = 0
      if zip64_entry == entry[:name]
        # Record the start disk through a Zip64 extra field. The wide size
        # and relative-header-offset fields must accompany it, with their
        # base-header values set to the FF placeholders.
        extra = [
          0x0001, 28,
          data.bytesize, compressed.bytesize, local_offsets.last, 0
        ].pack('vvQ<Q<Q<V')
        disk_base = 0xFFFF
      end

      cdir_record = [
        CDIR_SIGNATURE, 52, 3, 45, 0, entry[:method], 0x4021, 0x21, crc,
        if zip64_entry == entry[:name] then 0xFFFFFFFF else compressed.bytesize end,
        if zip64_entry == entry[:name] then 0xFFFFFFFF else data.bytesize end,
        name.bytesize, extra.bytesize, 0,
        disk_base, 0, 0,
        zip64_entry == entry[:name] ? 0xFFFFFFFF : local_offsets.last
      ].pack('VCCvvvvvVVVvvvvvVV')
      central_directory << cdir_record
      central_directory << name
      central_directory << extra
    end

    cdir_offset = locals.bytesize
    cdir_size = central_directory.bytesize

    tail = if zip64_eocd
             zip64_eocd = [
               ZIP64_EOCD_SIGNATURE, 44, 52, 45, 0, 0,
               entries.size, entries.size, cdir_size, cdir_offset
             ].pack('VQ<vvVVQ<Q<Q<Q<')
             locator = [
               ZIP64_LOCATOR_SIGNATURE, 0,
               locals.bytesize + cdir_size + zip64_eocd.bytesize, 1
             ].pack('VVQ<V')
             plain_eocd = [
               EOCD_SIGNATURE, 0, 0, entries.size, entries.size,
               [cdir_size, 0xFFFFFFFF].min,
               [cdir_offset, 0xFFFFFFFF].min, 0
             ].pack('VvvvvVVv')
             zip64_eocd + locator + plain_eocd
           else
             [
               EOCD_SIGNATURE, 0, 0, entries.size, entries.size,
               cdir_size, cdir_offset, 0
             ].pack('VvvvvVVv')
           end

    bytes = locals + central_directory + tail
    [bytes, { local_offsets: local_offsets,
              cdir_offset: cdir_offset,
              cdir_size: cdir_size,
              entry_sizes: entries.map { |e| e[:data].bytesize } }]
  end

  # Splits an archive produced by {build_zip} on the given global byte
  # positions and rewrites every disk-relative offset (EOCD fields, Zip64
  # fields, central directory entry offsets and Zip64 disk numbers) so the
  # result is a valid multi-volume image.
  def self.split_archive(bytes, layout, cuts,
                        zip64_eocd: false, zip64_entry: false)
    bytes = bytes.b.dup
    bounds = [0] + cuts + [bytes.bytesize]
    disk_of = ->(pos) { bounds[0...-1].rindex { |bound| bound <= pos } }
    local_of = ->(pos) { pos - bounds[disk_of.call(pos)] }

    cdir_disk = disk_of.call(layout[:cdir_offset])

    pos = layout[:cdir_offset]
    layout[:local_offsets].each do
      name_length = bytes[pos + 28, 2].unpack1('v')
      extra_length = bytes[pos + 30, 2].unpack1('v')
      comment_length = bytes[pos + 32, 2].unpack1('v')
      base_local_offset = bytes[pos + 42, 4].unpack1('V')
      extra_start = pos + 46 + name_length

      if zip64_entry && bytes[pos + 34, 2].unpack1('v') == 0xFFFF &&
         base_local_offset == 0xFFFFFFFF
        # Zip64 extra payload: original size (8), compressed size (8),
        # relative header offset (8), disk start number (4).
        global_local_offset = bytes[extra_start + 20, 8].unpack1('Q<')
        local_disk = disk_of.call(global_local_offset)
        bytes[extra_start + 20, 8] =
          [local_of.call(global_local_offset)].pack('Q<')
        bytes[extra_start + 28, 4] = [local_disk].pack('V')
      else
        global_local_offset = base_local_offset
        local_disk = disk_of.call(global_local_offset)
        bytes[pos + 34, 2] = [local_disk].pack('v')
        bytes[pos + 42, 4] = [local_of.call(global_local_offset)].pack('V')
      end

      pos += 46 + name_length + extra_length + comment_length
    end

    eocd = bytes.rindex([EOCD_SIGNATURE].pack('V'))
    last_disk = bounds.size - 2
    bytes[eocd + 4, 2] = [last_disk].pack('v')
    bytes[eocd + 6, 2] = [cdir_disk].pack('v')
    bytes[eocd + 16, 4] = [local_of.call(layout[:cdir_offset])].pack('V')

    if zip64_eocd
      zip64_position = bytes.rindex([ZIP64_EOCD_SIGNATURE].pack('V'))
      locator_position = bytes.rindex([ZIP64_LOCATOR_SIGNATURE].pack('V'))
      bytes[zip64_position + 16, 2] = [last_disk].pack('v')
      bytes[zip64_position + 18, 2] = [cdir_disk].pack('v')
      bytes[zip64_position + 48, 8] =
        [local_of.call(layout[:cdir_offset])].pack('Q<')
      bytes[locator_position + 4, 4] =
        [disk_of.call(zip64_position)].pack('V')
      bytes[locator_position + 8, 8] =
        [local_of.call(zip64_position)].pack('Q<')
      bytes[locator_position + 16, 4] = [last_disk + 1].pack('V')
    end

    bounds.each_cons(2).map { |from, to| bytes[from...to] }
  end

  # Prepends the traditional spanning signature to the first disk. Disk-
  # local offsets still start at 0 and point at the first local header,
  # which follows the signature.
  def self.add_spanning_signature(disks)
    result = disks.map(&:dup)
    result[0] = [SPANNING_SIGNATURE].pack('V') + result[0]
    result
  end

  # Tracks which disk numbers have been opened and never closes anything.
  class TrackingOpener
    attr_reader :opened

    def initialize(disks)
      @disks = disks
      @opened = []
      @ios = {}
    end

    def call(disk_number)
      @opened << disk_number
      @ios[disk_number] ||= StringIO.new(@disks[disk_number])
    end

    def closed?(disk_number)
      @ios[disk_number]&.closed?
    end
  end
end
