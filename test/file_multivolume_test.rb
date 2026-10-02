# frozen_string_literal: true

require 'tmpdir'

require_relative 'test_helper'
require_relative 'helpers/split_fixture'

class FileMultivolumeTest < Minitest::Test
  ENTRY_CONTENTS = {
    'alpha.txt'     => 'Hello, multi-volume world! ' * 40,
    'stored.bin'    => Random.new(1234).bytes(300),
    'dir/gamma.txt' => ('a'..'z').to_a.join * 15
  }.freeze

  # Builds the bytes of a small zip archive with one deflated entry, one
  # stored entry, one entry in a subdirectory, and an archive comment.
  def build_zip_bytes(comment: 'a multi-volume test archive')
    io = ::Zip::OutputStream.write_buffer(StringIO.new) do |zos|
      ENTRY_CONTENTS.each do |name, content|
        method = name.end_with?('.bin') ? ::Zip::Entry::STORED : ::Zip::Entry::DEFLATED
        zos.put_next_entry(name, '', ::Zip::ExtraField.new, method)
        zos.write(content)
      end
      zos.comment = comment
    end
    io.string
  end

  def read_archive(zf)
    {
      comment: zf.comment,
      entries: zf.entries.to_h { |entry| [entry.name, zf.read(entry)] }
    }
  end

  def volumes_to_ios(volumes)
    volumes.each_with_index.to_h { |data, disk| [disk, StringIO.new(data)] }
  end

  # Splits `bytes` at `split_points`, opens the result as a multi-volume
  # archive and asserts that its comment and every entry's contents are
  # identical to those of the un-split archive. Returns the volume IOs.
  def assert_split_roundtrip(bytes, split_points)
    expected = read_archive(::Zip::File.open_buffer(bytes))
    ios = volumes_to_ios(SplitFixture.split(bytes, split_points))
    actual = read_archive(::Zip::File.open_multivolume(ios))
    assert_equal(expected, actual)
    ios
  end

  def eocd_offset(bytes)
    bytes.rindex([SplitFixture::EOCD_SIG].pack('V'))
  end

  def cdir_info(bytes)
    fields = bytes[eocd_offset(bytes), 22].unpack('VvvvvVVv')
    { count: fields[4], size: fields[5], offset: fields[6], comment_length: fields[7] }
  end

  # [offset, length] of each entry's local header.
  def local_header_spans(bytes)
    ::Zip::File.open_buffer(bytes).entries.map do |entry|
      name_length, extra_length = bytes[entry.local_header_offset + 26, 4].unpack('vv')
      [entry.local_header_offset, 30 + name_length + extra_length]
    end
  end

  # [offset, length] of each entry's compressed data.
  def compressed_data_spans(bytes)
    ::Zip::File.open_buffer(bytes).entries.map do |entry|
      name_length, extra_length = bytes[entry.local_header_offset + 26, 4].unpack('vv')
      [entry.local_header_offset + 30 + name_length + extra_length, entry.compressed_size]
    end
  end

  # [offset, length] of each central directory entry.
  def cdir_entry_spans(bytes)
    info = cdir_info(bytes)
    spans = []
    offset = info[:offset]
    info[:count].times do
      name_length, extra_length, comment_length = bytes[offset + 28, 6].unpack('vvv')
      spans << [offset, 46 + name_length + extra_length + comment_length]
      offset += spans.last[1]
    end
    spans
  end

  def middle_of(span)
    span[0] + span[1] / 2
  end

  def test_single_volume_archive
    bytes = build_zip_bytes
    ios = { 0 => StringIO.new(bytes) }
    expected = read_archive(::Zip::File.open_buffer(bytes))
    assert_equal(expected, read_archive(::Zip::File.open_multivolume(ios)))
  end

  def test_archive_split_in_two
    bytes = build_zip_bytes
    assert_split_roundtrip(bytes, [bytes.bytesize / 2])
  end

  def test_archive_split_in_three
    bytes = build_zip_bytes
    assert_split_roundtrip(bytes, [bytes.bytesize / 3, 2 * bytes.bytesize / 3])
  end

  def test_local_header_spanning_volumes
    bytes = build_zip_bytes
    local_header_spans(bytes).each do |span|
      assert_split_roundtrip(bytes, [middle_of(span)])
    end
  end

  def test_compressed_data_spanning_volumes
    bytes = build_zip_bytes
    compressed_data_spans(bytes).each do |span|
      assert_split_roundtrip(bytes, [middle_of(span)])
    end
  end

  def test_cdir_entry_spanning_volumes
    bytes = build_zip_bytes
    cdir_entry_spans(bytes).each do |span|
      assert_split_roundtrip(bytes, [middle_of(span)])
    end
  end

  def test_eocd_spanning_volumes
    bytes = build_zip_bytes
    offset = eocd_offset(bytes)
    length = 22 + cdir_info(bytes)[:comment_length]
    assert_split_roundtrip(bytes, [offset + length / 2])
  end

  def test_many_tiny_volumes
    bytes = build_zip_bytes
    assert_split_roundtrip(bytes, (7...bytes.bytesize).step(7).to_a)
  end

  def test_zip64_eocd_spanning_volumes
    bytes = SplitFixture.make_zip64(build_zip_bytes(comment: ''))
    zip64_offset = bytes.rindex([SplitFixture::ZIP64_EOCD_SIG].pack('V'))
    assert_split_roundtrip(bytes, [zip64_offset + 10])
  end

  def test_zip64_locator_spanning_volumes
    bytes = SplitFixture.make_zip64(build_zip_bytes(comment: ''))
    locator_offset = bytes.rindex([SplitFixture::ZIP64_EOCD_LOC_SIG].pack('V'))
    assert_split_roundtrip(bytes, [locator_offset + 10])
  end

  def test_zip64_archive_eocd_spanning_volumes
    bytes = SplitFixture.make_zip64(build_zip_bytes(comment: ''))
    assert_split_roundtrip(bytes, [eocd_offset(bytes) + 11])
  end

  def test_entry_disk_number_start
    bytes = build_zip_bytes
    split_points = [bytes.bytesize / 3, 2 * bytes.bytesize / 3]
    mvio = ::Zip::MultiVolumeIO.new(volumes_to_ios(SplitFixture.split(bytes, split_points)))
    zf = ::Zip::File.open_multivolume(mvio)
    zf.entries.each do |entry|
      assert_equal(
        mvio.disk_number_for_offset(entry.local_header_offset),
        entry.disk_number_start,
        "wrong disk number start for #{entry.name}"
      )
    end
    assert(zf.entries.map(&:disk_number_start).max.positive?)
  end

  def test_entry_disk_number_start_from_zip64_extra
    bytes = build_zip64_disk_start_fixture
    # Split so that the second entry's local header starts on disk 1.
    split_point = local_header_spans(bytes)[1][0]
    ios = volumes_to_ios(SplitFixture.split(bytes, [split_point]))
    zf = ::Zip::File.open_multivolume(ios)
    assert_equal([0, 1], zf.entries.map(&:disk_number_start))
    assert_equal('first', zf.read('one.txt'))
    assert_equal('second', zf.read('two.txt'))
  end

  def test_missing_middle_volume
    bytes = build_zip_bytes
    split_points = [bytes.bytesize / 3, 2 * bytes.bytesize / 3]
    ios = volumes_to_ios(SplitFixture.split(bytes, split_points))
    ios.delete(1)
    error = assert_raises(::Zip::MissingVolumeError) do
      ::Zip::File.open_multivolume(ios)
    end
    assert_equal(1, error.disk_number)
  end

  def test_missing_last_volume
    bytes = build_zip_bytes
    split_points = [bytes.bytesize / 3, 2 * bytes.bytesize / 3]
    ios = volumes_to_ios(SplitFixture.split(bytes, split_points))
    ios.delete(2)
    # With the last volume gone the EOCD itself is unreadable; there is no
    # gap in the provided sequence, so this is a plain read error, not a
    # MissingVolumeError.
    error = assert_raises(::Zip::Error) { ::Zip::File.open_multivolume(ios) }
    refute_kind_of(::Zip::MissingVolumeError, error)
  end

  def test_skipped_volume_with_last_volume_present
    bytes = build_zip_bytes
    split_points = [bytes.bytesize / 3, 2 * bytes.bytesize / 3]
    volumes = SplitFixture.split(bytes, split_points)
    # The caller provides disks 0 and 2, but mislabels the last volume as
    # disk 1. The EOCD (which says the archive spans 3 disks) is readable,
    # so the missing volume is reported directly.
    ios = { 0 => StringIO.new(volumes[0]), 1 => StringIO.new(volumes[2]) }
    error = assert_raises(::Zip::MissingVolumeError) do
      ::Zip::File.open_multivolume(ios)
    end
    assert_equal(2, error.disk_number)
  end

  def test_out_of_range_cdir_offset
    bytes = build_zip_bytes(comment: '')
    split_points = [bytes.bytesize / 2]
    volumes = SplitFixture.split(bytes, split_points)
    # Corrupt the EOCD's central directory offset so that it points way
    # beyond the end of the archive.
    eocd = volumes[1].rindex([SplitFixture::EOCD_SIG].pack('V'))
    volumes[1][eocd + 16, 4] = [10_000_000].pack('V')
    ios = volumes_to_ios(volumes)
    assert_raises(::Zip::VolumeOffsetError) { ::Zip::File.open_multivolume(ios) }
  end

  def test_open_multivolume_with_no_volumes
    assert_raises(::Zip::MissingVolumeError) { ::Zip::File.open_multivolume({}) }
  end

  def test_volumes_are_not_closed
    bytes = build_zip_bytes
    ios = volumes_to_ios(SplitFixture.split(bytes, [bytes.bytesize / 2]))
    ::Zip::File.open_multivolume(ios) do |zf|
      zf.each { |entry| zf.read(entry) }
    end
    ios.each_value { |io| refute(io.closed?) }
  end

  def test_open_multivolume_accepts_a_multi_volume_io
    bytes = build_zip_bytes
    mvio = ::Zip::MultiVolumeIO.new(volumes_to_ios(SplitFixture.split(bytes, [bytes.bytesize / 2])))
    expected = read_archive(::Zip::File.open_buffer(bytes))
    assert_equal(expected, read_archive(::Zip::File.open_multivolume(mvio)))
  end

  def test_volumes_from_real_files
    bytes = build_zip_bytes
    volumes = SplitFixture.split(bytes, [bytes.bytesize / 3, 2 * bytes.bytesize / 3])
    Dir.mktmpdir do |dir|
      names = %w[archive.z01 archive.z02 archive.zip]
      ios = volumes.each_with_index.to_h do |data, disk|
        path = ::File.join(dir, names[disk])
        ::File.binwrite(path, data)
        [disk, ::File.open(path, 'rb')]
      end
      expected = read_archive(::Zip::File.open_buffer(bytes))
      assert_equal(expected, read_archive(::Zip::File.open_multivolume(ios)))
      ios.each_value { |io| refute(io.closed?) }
      ios.each_value(&:close)
    end
  end

  def test_input_stream_over_multi_volume_io
    bytes = build_zip_bytes
    mvio = ::Zip::MultiVolumeIO.new(
      volumes_to_ios(SplitFixture.split(bytes, [bytes.bytesize / 2]))
    )
    contents = {}
    ::Zip::InputStream.open(mvio) do |zis|
      while (entry = zis.get_next_entry)
        contents[entry.name] = zis.read
      end
    end
    assert_equal(ENTRY_CONTENTS, contents)
  end

  def test_multivolume_archives_are_read_only
    bytes = build_zip_bytes
    ios = volumes_to_ios(SplitFixture.split(bytes, [bytes.bytesize / 2]))
    zf = ::Zip::File.open_multivolume(ios)
    zf.rename('alpha.txt', 'renamed.txt')
    error = assert_raises(::Zip::Error) { zf.close }
    assert_match(/read-only/, error.message)
  end

  def test_extract_to_filesystem
    bytes = build_zip_bytes
    ios = volumes_to_ios(SplitFixture.split(bytes, [bytes.bytesize / 3, 2 * bytes.bytesize / 3]))
    Dir.mktmpdir do |dir|
      ::Zip::File.open_multivolume(ios) do |zf|
        zf.extract_all(dir)
      end
      ENTRY_CONTENTS.each do |name, content|
        assert_equal(content, ::File.binread(::File.join(dir, name)))
      end
    end
  end

  private

  # Hand-builds a two-entry archive in which the second central directory
  # entry carries its disk number start in a Zip64 extra field (the base
  # field holding the 0xFFFF marker), as archives with more than 0xFFFF
  # disks do. The second entry's local header is placed on disk 1 by
  # splitting just before it.
  def build_zip64_disk_start_fixture
    one = build_stored_local_entry('one.txt', 'first')
    two = build_stored_local_entry('two.txt', 'second')
    cdir_offset = one.bytesize + two.bytesize

    cdir1 = build_stored_cdir_entry('one.txt', 'first', 0, 0)
    # Disk number start is 0xFFFF on the wire; the real value (1) is in
    # the Zip64 extra field.
    zip64_extra = [0x0001, 4, 1].pack('vvV')
    cdir2 = build_stored_cdir_entry('two.txt', 'second', one.bytesize, 0xFFFF, zip64_extra)
    cdir_size = cdir1.bytesize + cdir2.bytesize

    eocd = [SplitFixture::EOCD_SIG, 0, 0, 2, 2, cdir_size, cdir_offset, 0].pack('VvvvvVVv')
    one + two + cdir1 + cdir2 + eocd
  end

  # DOS date for 2024-01-01, so the hand-built entries have valid times.
  DOS_DATE = 22_561

  def build_stored_local_entry(name, content)
    [
      ::Zip::LOCAL_ENTRY_SIGNATURE, 20, 0, ::Zip::Entry::STORED, 0, DOS_DATE,
      Zlib.crc32(content), content.bytesize, content.bytesize,
      name.bytesize, 0
    ].pack('VvvvvvVVVvv') + name + content
  end

  def build_stored_cdir_entry(name, content, offset, disk_start, extra = '')
    [
      SplitFixture::CDIR_ENTRY_SIG, 63, 3, 20, 0, ::Zip::Entry::STORED, 0, DOS_DATE,
      Zlib.crc32(content), content.bytesize, content.bytesize,
      name.bytesize, extra.bytesize, 0, disk_start, 0, 0, offset
    ].pack('VCCvvvvvVVVvvvvvVV') + name + extra
  end
end
