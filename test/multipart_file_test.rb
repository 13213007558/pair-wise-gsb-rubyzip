# frozen_string_literal: true

require_relative 'test_helper'
require_relative 'helpers/multipart_fixtures'
require 'tmpdir'

class ZipMultipartFileTest < Minitest::Test
  include MultipartFixtures

  def setup
    @data = build_unsplit_archive
    zf = ::Zip::File.open_buffer(StringIO.new(@data))
    @expected = MultipartFixtures.read_all_entries(zf)
    @boundaries = structure_boundaries(@data)
  end

  def open_multipart(volumes, &block)
    ios = volumes.map { |v| StringIO.new(v) }
    ::Zip::File.open_multipart(ios, &block)
  end

  def test_each_structure_crosses_a_volume_boundary_once
    spans = structure_spans(@data).values
    @boundaries.each_with_index do |boundary, i|
      assert(spans[i].cover?(boundary),
             "boundary #{boundary} should be inside #{spans[i]}")
    end
    # Four boundaries, five volumes, and no two boundaries in the same
    # structure.
    assert_equal(4, @boundaries.size)
  end

  def test_naive_split_matches_unsplit
    volumes = build_naive_volumes(@data, @boundaries)
    assert_equal(5, volumes.size)

    open_multipart(volumes) do |zf|
      assert_equal(MultipartFixtures::ARCHIVE_COMMENT, zf.comment)
      assert_equal(@expected, MultipartFixtures.read_all_entries(zf))
    end
  end

  def test_appnote_split_matches_unsplit
    volumes = build_appnote_volumes(@data, @boundaries)
    assert_equal(5, volumes.size)
    # The first volume of a real split archive starts with the split
    # file signature.
    assert_equal(MultipartFixtures::SPLIT_SIG, volumes.first[0, 4])

    open_multipart(volumes) do |zf|
      assert_equal(MultipartFixtures::ARCHIVE_COMMENT, zf.comment)
      assert_equal(@expected, MultipartFixtures.read_all_entries(zf))
      # Entries later in the archive start on later disks.
      disks = zf.entries.map(&:disk_number_start)
      assert(disks.max.positive?, "expected some entries to start on later disks: #{disks}")
    end
  end

  def test_zip64_split_matches_unsplit
    volumes = build_zip64_volumes(@data)
    assert_equal(5, volumes.size)

    open_multipart(volumes) do |zf|
      assert_equal(MultipartFixtures::ARCHIVE_COMMENT, zf.comment)
      assert_equal(@expected, MultipartFixtures.read_all_entries(zf))
    end
  end

  def test_extract_all_matches_unsplit
    volumes = build_appnote_volumes(@data, @boundaries)
    Dir.mktmpdir do |dir|
      split_dir = File.join(dir, 'split')
      unsplit_dir = File.join(dir, 'unsplit')
      open_multipart(volumes) { |zf| zf.extract_all(split_dir) }
      ::Zip::File.open_buffer(StringIO.new(@data)) { |zf| zf.extract_all(unsplit_dir) }

      MultipartFixtures::ENTRY_CONTENTS.each_key do |name|
        assert_equal(
          ::File.binread(File.join(unsplit_dir, name)),
          ::File.binread(File.join(split_dir, name)),
          "extracted #{name} differs"
        )
      end
      assert(::File.directory?(File.join(split_dir, MultipartFixtures::DIRECTORY_NAME)))
    end
  end

  def test_volumes_can_be_supplied_as_a_hash_of_disk_numbers
    volumes = build_naive_volumes(@data, @boundaries)
    ios = volumes.each_with_index.to_h { |v, i| [i, StringIO.new(v)] }
    ::Zip::File.open_multipart(ios) do |zf|
      assert_equal(@expected, MultipartFixtures.read_all_entries(zf))
    end
  end

  def test_volumes_can_be_supplied_as_a_multipart_reader
    volumes = build_naive_volumes(@data, @boundaries)
    reader = ::Zip::MultipartReader.new(volumes.map { |v| StringIO.new(v) })
    ::Zip::File.open_multipart(reader) do |zf|
      assert_equal(@expected, MultipartFixtures.read_all_entries(zf))
    end
  end

  def test_caller_keeps_ownership_of_the_volume_ios
    volumes = build_appnote_volumes(@data, @boundaries)
    ios = volumes.map { |v| StringIO.new(v) }
    ::Zip::File.open_multipart(ios) do |zf|
      MultipartFixtures.read_all_entries(zf)
    end
    assert(ios.none?(&:closed?), 'volume IOs must not be closed by rubyzip')
  end

  def test_missing_volume_in_the_sequence
    volumes = build_naive_volumes(@data, @boundaries)
    ios = volumes.map { |v| StringIO.new(v) }
    error = assert_raises(::Zip::MissingVolumeError) do
      ::Zip::File.open_multipart({ 0 => ios[0], 1 => ios[1], 3 => ios[3], 4 => ios[4] }) {}
    end
    assert_equal(2, error.disk_number)
  end

  def test_missing_volume_referenced_by_the_eocd
    volumes = build_naive_volumes(@data, @boundaries)
    bases = cumulative_bases(volumes)
    # The EOCD claims to be on disk 9, which was not provided.
    poke(volumes, bases, eocd_info(@data)[:eocd_offset] + 4, [9].pack('v'))
    error = assert_raises(::Zip::MissingVolumeError) do
      open_multipart(volumes) {}
    end
    assert_equal(9, error.disk_number)
  end

  def test_missing_volume_referenced_by_an_entry
    volumes = build_appnote_volumes(@data, @boundaries)
    bases = cumulative_bases(volumes)
    info = eocd_info(@data)
    # The first central directory entry claims to start on disk 9.
    poke(volumes, bases, info[:cdir_offset] + 4 + 34, [9].pack('v'))
    error = assert_raises(::Zip::MissingVolumeError) do
      open_multipart(volumes) {}
    end
    assert_equal(9, error.disk_number)
  end

  def test_missing_volume_referenced_by_the_zip64_locator
    volumes = build_zip64_volumes(@data)
    bases = cumulative_bases(volumes)
    # The locator claims the archive has more disks than were provided.
    info = eocd_info(@data)
    loc_off = info[:eocd_offset] + MultipartFixtures::ZIP64_EOCD_SIZE
    poke(volumes, bases, loc_off + 16, [9].pack('V'))
    error = assert_raises(::Zip::MissingVolumeError) do
      open_multipart(volumes) {}
    end
    assert_equal(8, error.disk_number)
  end

  def test_duplicate_volume
    volumes = build_naive_volumes(@data, @boundaries)
    ios = volumes.map { |v| StringIO.new(v) }
    assert_raises(::Zip::DuplicateVolumeError) do
      ::Zip::File.open_multipart([[0, ios[0]], [1, ios[1]], [2, ios[2]],
                                  [3, ios[3]], [4, ios[4]], [0, ios[0]]])
    end
  end

  def test_out_of_range_central_directory_offset
    volumes = build_naive_volumes(@data, @boundaries)
    bases = cumulative_bases(volumes)
    # The EOCD points the central directory far beyond the end of the
    # concatenated archive.
    poke(volumes, bases, eocd_info(@data)[:eocd_offset] + 16, [1_000_000].pack('V'))
    assert_raises(::Zip::VolumeOffsetError) do
      open_multipart(volumes) {}
    end
  end

  def test_a_single_volume_of_a_split_archive_raises_split_archive_error
    # Split so that the EOCD record sits entirely in the last volume.
    volumes = build_appnote_volumes(@data, [100, 200, 300])
    # Handing the last volume (which holds the EOCD) to the regular
    # single-file interface must not silently misread the archive.
    assert_raises(::Zip::SplitArchiveError) do
      ::Zip::File.open_buffer(StringIO.new(volumes.last))
    end
  end

  def test_multipart_archives_are_read_only
    ios = build_naive_volumes(@data, @boundaries).map { |v| StringIO.new(v) }
    zf = ::Zip::File.open_multipart(ios)
    zf.mkdir('new_dir')
    assert_raises(::Zip::Error) { zf.commit }
    assert_raises(::Zip::Error) { zf.close }
  end

  def test_count_entries
    volumes = build_naive_volumes(@data, @boundaries)
    reader = ::Zip::MultipartReader.new(volumes.map { |v| StringIO.new(v) })
    assert_equal(@expected.size, ::Zip::File.count_entries(reader))
  end
end
