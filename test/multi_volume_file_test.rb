# frozen_string_literal: true

require_relative 'test_helper'
require_relative 'helpers/multi_volume_fixtures'
require 'tmpdir'

class ZipMultiVolumeFileTest < Minitest::Test
  # An archive in which a local header, an entry's (compressed) data and
  # the central directory each cross a disk boundary.
  def build_spanning_archive
    archive = MultiVolumeFixtures.build([
      ['alpha.txt', 'a' * 100],
      ['beta.txt', (0...500).map { |i| (i % 256).chr }.join],
      ['gamma.txt', 'gamma']
    ])
    cuts = [
      archive.local_header_offset('alpha.txt') + 15, # inside alpha's local header
      archive.data_offset('beta.txt') + 40,          # inside beta's data
      archive.cdir_offset + 20                       # inside the central directory
    ]
    [archive, archive.cut(*cuts)]
  end

  # An archive in which disk 1 holds only the tail of skip_me.txt's data,
  # so that reading wanted.txt never needs to touch it.
  def build_lazy_archive
    archive = MultiVolumeFixtures.build([
      ['skip_me.txt', 'x' * 300, :stored],
      ['wanted.txt', 'wanted content']
    ])
    cuts = [
      archive.data_offset('skip_me.txt') + 30,   # inside skip_me's data
      archive.local_header_offset('wanted.txt'), # wanted's records start on disk 2
      archive.cdir_offset                        # central directory starts on disk 3
    ]
    [archive, archive.cut(*cuts)]
  end

  def build_zip64_archive
    archive = MultiVolumeFixtures.build([
      ['z1.txt', 'zip64 one ' * 10],
      ['z2.txt', 'zip64 two']
    ], zip64: true)
    cuts = [
      archive.data_offset('z1.txt') + 10, # inside z1's data
      archive.cdir_offset + 30            # inside the central directory
    ]
    [archive, archive.cut(*cuts)]
  end

  def disks_hash(disks)
    disks.map.with_index { |data, disk| [disk, StringIO.new(data)] }.to_h
  end

  def open_spanning(&block)
    archive, disks = build_spanning_archive
    zf = ::Zip::MultiVolumeFile.open(disks_hash(disks), &block)
    [archive, disks, zf]
  end

  def test_read_entries_spanning_disk_boundaries
    _, _, zf = open_spanning
    assert_equal('a' * 100, zf.read('alpha.txt'))
    assert_equal((0...500).map { |i| (i % 256).chr }.join, zf.read('beta.txt'))
    assert_equal('gamma', zf.read('gamma.txt'))
  end

  def test_entries_carry_disk_numbers_and_disk_relative_offsets
    archive, disks, zf = open_spanning
    zf.each do |entry|
      disk, rel = disks.locate(archive.local_header_offset(entry.name))
      assert_equal(disk, entry.disk_number_start, "wrong disk for #{entry.name}")
      assert_equal(rel, entry.local_header_offset, "wrong offset for #{entry.name}")
    end
    assert_equal([0, 1, 2], zf.entries.map(&:disk_number_start))
  end

  def test_entry_listing
    _, _, zf = open_spanning
    assert_equal(3, zf.size)
    assert_equal(%w[alpha.txt beta.txt gamma.txt], zf.entries.map(&:name))
    assert_equal(500, zf.find_entry('beta.txt').size)
  end

  def test_get_input_stream_reads_entry_in_chunks
    _, _, zf = open_spanning
    content = +''
    zf.get_input_stream('beta.txt') do |stream|
      content << stream.read(7) until stream.eof?
    end
    assert_equal((0...500).map { |i| (i % 256).chr }.join, content)
  end

  def test_extract_entry
    _, _, zf = open_spanning
    Dir.mktmpdir do |dir|
      zf.extract('beta.txt', 'out.txt', destination_directory: dir)
      assert_equal((0...500).map { |i| (i % 256).chr }.join, File.binread(File.join(dir, 'out.txt')))
    end
  end

  def test_eocd_spanning_a_disk_boundary
    archive = MultiVolumeFixtures.build([['one.txt', '1' * 50], ['two.txt', '2' * 50]])
    disks = archive.cut(30, archive.eocd_offset + 10)
    ::Zip::MultiVolumeFile.open(disks_hash(disks)) do |zf|
      assert_equal('1' * 50, zf.read('one.txt'))
      assert_equal('2' * 50, zf.read('two.txt'))
    end
  end

  def test_only_the_needed_disks_are_opened
    _, disks = build_lazy_archive
    opened = []
    io = ::Zip::MultiVolumeIo.new(disks.size) do |disk|
      opened << disk
      StringIO.new(disks[disk])
    end
    zf = ::Zip::MultiVolumeFile.new(io)
    assert_equal('wanted content', zf.read('wanted.txt'))
    assert_equal([0, 2, 3], opened.uniq.sort)
    refute_includes(opened, 1)
  end

  def test_missing_disk_is_only_noticed_when_needed
    _, disks = build_lazy_archive
    io = ::Zip::MultiVolumeIo.new(disks.size) do |disk|
      disk == 1 ? nil : StringIO.new(disks[disk])
    end
    zf = ::Zip::MultiVolumeFile.new(io)
    assert_equal('wanted content', zf.read('wanted.txt'))
    error = assert_raises(::Zip::MissingDiskError) { zf.read('skip_me.txt') }
    assert_equal(1, error.disk_number)
    assert_match(/disk 1/, error.message)
  end

  def test_sequential_input_stream_iteration_across_disks
    _, disks = build_spanning_archive
    stream = ::Zip::InputStream.new(::Zip::MultiVolumeIo.new(disks_hash(disks)))
    names = []
    while (entry = stream.get_next_entry)
      names << entry.name
      names << stream.read.bytesize
    end
    assert_equal(['alpha.txt', 100, 'beta.txt', 500, 'gamma.txt', 5], names)
  end

  def test_single_disk_archive
    archive, = build_spanning_archive
    disk = archive.cut[0]
    ::Zip::MultiVolumeFile.open(0 => StringIO.new(disk)) do |zf|
      assert_equal('gamma', zf.read('gamma.txt'))
    end
  end

  def test_zip64_disk_numbers_and_offsets
    archive, disks = build_zip64_archive
    ::Zip::MultiVolumeFile.open(disks_hash(disks)) do |zf|
      assert_equal('zip64 one ' * 10, zf.read('z1.txt'))
      assert_equal('zip64 two', zf.read('z2.txt'))
      zf.each do |entry|
        assert(entry.zip64?)
        disk, rel = disks.locate(archive.local_header_offset(entry.name))
        assert_equal(disk, entry.disk_number_start)
        assert_equal(rel, entry.local_header_offset)
      end
    end
  end

  def test_zip64_eocd_read_from_an_earlier_disk
    archive, disks = build_zip64_archive
    # A maximum-length archive comment pushes the Zip64 EOCD out of the
    # trailing window, so it has to be fetched through the locator.
    disks[-1] << ('C' * 65_535)
    disks.patch(archive.eocd_offset + 20, [65_535].pack('v'))
    ::Zip::MultiVolumeFile.open(disks_hash(disks)) do |zf|
      assert_equal('C' * 65_535, zf.comment)
      assert_equal('zip64 two', zf.read('z2.txt'))
    end
  end

  def test_missing_last_disk
    _, disks = build_spanning_archive
    error = assert_raises(::Zip::MultiVolumeError) do
      ::Zip::MultiVolumeFile.new(disks_hash(disks[0..2]))
    end
    assert_equal(2, error.disk_number)
    assert_match(/disk 2/, error.message)
  end

  def test_disk_count_mismatch
    _, disks = build_spanning_archive
    # The caller skipped disk 2 and supplied the real last disk in its place.
    ios = { 0 => StringIO.new(disks[0]), 1 => StringIO.new(disks[1]), 2 => StringIO.new(disks[3]) }
    error = assert_raises(::Zip::MultiVolumeError) { ::Zip::MultiVolumeFile.new(ios) }
    assert_equal(3, error.disk_number)
    assert_match(/ends on disk 3/, error.message)
    assert_match(/3 disk\(s\) were provided/, error.message)
  end

  def test_extra_disk_provided
    _, disks = build_spanning_archive
    error = assert_raises(::Zip::MultiVolumeError) do
      ::Zip::MultiVolumeFile.new(disks_hash(disks + ['junk']))
    end
    assert_equal(3, error.disk_number)
    assert_match(/5 disk\(s\) were provided/, error.message)
  end

  def test_zip64_total_disks_mismatch
    archive, disks = build_zip64_archive
    disks.patch(archive.zip64_locator_offset + 16, [99].pack('V'))
    error = assert_raises(::Zip::MultiVolumeError) do
      ::Zip::MultiVolumeFile.new(disks_hash(disks))
    end
    assert_match(/99 disk\(s\)/, error.message)
  end

  def test_entry_on_unprovided_disk
    archive, disks = build_spanning_archive
    disks.patch(archive.cdir_entry_offset('beta.txt') + 34, [9].pack('v'))
    error = assert_raises(::Zip::MissingDiskError) do
      ::Zip::MultiVolumeFile.new(disks_hash(disks))
    end
    assert_equal(9, error.disk_number)
  end

  def test_truncated_central_directory_record
    archive, disks = build_spanning_archive
    # Point the central directory at the very end of the last disk, so that
    # the first central directory record is cut off mid-record.
    disks.patch(archive.eocd_offset + 6, [3].pack('v'))
    disks.patch(archive.eocd_offset + 16, [disks[3].bytesize - 10].pack('V'))
    error = assert_raises(::Zip::MultiVolumeError) do
      ::Zip::MultiVolumeFile.new(disks_hash(disks))
    end
    assert_equal(3, error.disk_number)
    assert_equal(disks[3].bytesize, error.disk_offset)
    assert_match(/truncated/, error.message)
  end

  def test_truncated_local_header
    archive, disks = build_spanning_archive
    # Point gamma's local header at the very end of the last disk.
    disks.patch(archive.cdir_entry_offset('gamma.txt') + 34, [3].pack('v'))
    disks.patch(archive.cdir_entry_offset('gamma.txt') + 42, [disks[3].bytesize - 5].pack('V'))
    error = assert_raises(::Zip::MultiVolumeError) do
      ::Zip::MultiVolumeFile.new(disks_hash(disks))
    end
    assert_equal(3, error.disk_number)
    assert_equal(disks[3].bytesize, error.disk_offset)
  end

  def test_disk_ios_are_not_closed
    _, disks = build_lazy_archive
    ios = disks_hash(disks)
    zf = ::Zip::MultiVolumeFile.new(ios)
    assert_equal('wanted content', zf.read('wanted.txt'))
    zf.close
    refute(ios.values.any?(&:closed?))

    stream = zf.get_input_stream('wanted.txt')
    stream.close
    refute(ios.values.any?(&:closed?))
  end

  def test_read_only
    _, disks = build_lazy_archive
    zf = ::Zip::MultiVolumeFile.new(disks_hash(disks))
    assert_raises(::Zip::Error) { zf.add('new.txt', __FILE__) }
    assert_raises(::Zip::Error) { zf.remove('wanted.txt') }
    assert_raises(::Zip::Error) { zf.rename('wanted.txt', 'w.txt') }
    assert_raises(::Zip::Error) { zf.mkdir('dir') }
    assert_raises(::Zip::Error) { zf.get_output_stream('out.txt') }
    assert_raises(::Zip::Error) { zf.comment = 'nope' }
    zf.close # closing a read-only archive is a no-op and must not raise
  end
end
