# frozen_string_literal: true

# Builds tiny hand-made split (multi-volume) zip fixtures for the
# multi-volume reading tests. Takes the bytes of a normal zip archive and
# a list of split points, patches the disk number fields the way a real
# splitting tool would (the EOCD record, the Zip64 EOCD record and
# locator, and each central directory entry's disk number start), and
# returns the volumes as an Array of binary Strings.
module SplitFixture
  EOCD_SIG          = 0x06054b50
  ZIP64_EOCD_SIG    = 0x06064b50
  ZIP64_EOCD_LOC_SIG = 0x07064b50
  CDIR_ENTRY_SIG    = 0x02014b50

  module_function

  # Splits `bytes` at each of `split_points` (absolute offsets, each
  # strictly inside the archive) into volumes, patching the disk number
  # fields first. Returns an Array of Strings, volumes[0] being disk 0.
  def split(bytes, split_points)
    points = split_points.sort
    if points.empty? || points.any? { |point| point <= 0 || point >= bytes.bytesize }
      raise ArgumentError, 'split points must lie strictly inside the archive'
    end

    bytes = bytes.dup.b
    patch_disk_numbers(bytes, points)

    volumes = []
    prev = 0
    (points + [bytes.bytesize]).each do |point|
      volumes << bytes[prev...point]
      prev = point
    end
    volumes
  end

  # The number of the disk on which `offset` falls, given the split points.
  def disk_for(offset, split_points)
    split_points.count { |point| point <= offset }
  end

  # Turns the bytes of a normal zip archive (without a comment) into the
  # bytes of an equivalent archive that uses Zip64 end records: a Zip64
  # EOCD record and locator are inserted before the EOCD record, and the
  # EOCD record's count/size/offset fields are replaced with Zip64
  # markers, forcing readers down the Zip64 path.
  def make_zip64(bytes)
    eocd_offset = bytes.rindex([EOCD_SIG].pack('V'))
    raise ArgumentError, 'EOCD not found' unless eocd_offset

    _, _, _, _, count, cdir_size, cdir_offset, = bytes[eocd_offset, 22].unpack('VvvvvVVv')
    body = bytes[0...eocd_offset]
    zip64_eocd_offset = body.bytesize
    zip64_eocd = [ZIP64_EOCD_SIG, 44, 63, 45, 0, 0, count, count,
                  cdir_size, cdir_offset].pack('VQ<vvVVQ<Q<Q<Q<')
    locator = [ZIP64_EOCD_LOC_SIG, 0, zip64_eocd_offset, 1].pack('VVQ<V')
    eocd = [EOCD_SIG, 0, 0, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0].pack('VvvvvVVv')
    body + zip64_eocd + locator + eocd
  end

  def patch_disk_numbers(bytes, points)
    eocd_offset = bytes.rindex([EOCD_SIG].pack('V'))
    raise ArgumentError, 'EOCD not found' unless eocd_offset

    _, this_disk, cdir_disk, _, count, cdir_size, cdir_offset, =
      bytes[eocd_offset, 22].unpack('VvvvvVVv')

    if count == 0xFFFF || cdir_size == 0xFFFFFFFF || cdir_offset == 0xFFFFFFFF
      count, cdir_size, cdir_offset = patch_zip64_disk_numbers(bytes, eocd_offset, points)
    end

    # EOCD: number of this disk @4, disk with start of cdir @6. Keep any
    # Zip64 markers already there.
    bytes[eocd_offset + 4, 2] = [points.size].pack('v') unless this_disk == 0xFFFF
    unless cdir_disk == 0xFFFF
      bytes[eocd_offset + 6, 2] = [disk_for(cdir_offset, points)].pack('v')
    end

    patch_cdir_entries(bytes, points, cdir_offset, count)
  end

  def patch_zip64_disk_numbers(bytes, eocd_offset, points)
    locator_offset = bytes.rindex([ZIP64_EOCD_LOC_SIG].pack('V'), eocd_offset)
    zip64_offset = bytes.rindex([ZIP64_EOCD_SIG].pack('V'), locator_offset)
    raise ArgumentError, 'Zip64 records not found' unless locator_offset && zip64_offset

    count, cdir_size, cdir_offset = bytes[zip64_offset + 32, 24].unpack('Q<Q<Q<')

    # Zip64 EOCD: number of this disk @16, disk with start of cdir @20.
    bytes[zip64_offset + 16, 4] = [points.size].pack('V')
    bytes[zip64_offset + 20, 4] = [disk_for(cdir_offset, points)].pack('V')
    # Zip64 locator: disk with the Zip64 EOCD @4, total number of disks @16.
    bytes[locator_offset + 4, 4] = [disk_for(zip64_offset, points)].pack('V')
    bytes[locator_offset + 16, 4] = [points.size + 1].pack('V')

    [count, cdir_size, cdir_offset]
  end

  def patch_cdir_entries(bytes, points, cdir_offset, count)
    offset = cdir_offset
    count.times do
      unless bytes[offset, 4].unpack1('V') == CDIR_ENTRY_SIG
        raise ArgumentError, 'central directory entry signature not found'
      end

      name_len, extra_len, comment_len = bytes[offset + 28, 6].unpack('vvv')
      local_header_offset = bytes[offset + 42, 4].unpack1('V')
      # Our fixtures never need Zip64 offsets in the central directory.
      # Keep any Zip64 disk number start marker (0xFFFF): the real value
      # then lives in the entry's Zip64 extra field.
      unless bytes[offset + 34, 2].unpack1('v') == 0xFFFF
        bytes[offset + 34, 2] = [disk_for(local_header_offset, points)].pack('v')
      end
      offset += 46 + name_len + extra_len + comment_len
    end
  end
end
