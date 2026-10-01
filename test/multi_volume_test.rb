# frozen_string_literal: true

require_relative 'test_helper'
require_relative 'helpers/multi_volume_fixtures'

class ZipMultiVolumeTest < Minitest::Test
  Fixtures = MultiVolumeFixtures

  def setup
    @entries = [
      { name: 'a.txt', data: 'A' * 30, method: 0 },
      { name: 'b.bin', data: 'B' * 120, method: 8 }
    ]
    @zip, @layout = Fixtures.build_zip(@entries)
  end

  # A single disk is just an ordinary archive: the new entry point must read
  # it the same as Zip::File.open_buffer.
  def test_reads_a_single_disk_like_an_ordinary_archive
    disks = Fixtures.split_archive(@zip, @layout, [])
    zip = Zip::File.open_volume_set(disks.map { |d| StringIO.new(d) })

    assert_equal %w[a.txt b.bin], zip.entries.map(&:name)
    assert_equal 'A' * 30, zip.read('a.txt')
    assert_equal 'B' * 120, zip.read('b.bin')
  ensure
    zip&.close
  end

  def test_local_header_is_split_across_disks
    # b's local header starts at 65; cut 12 bytes into it.
    cut = @layout[:local_offsets][1] + 12
    disks = Fixtures.split_archive(@zip, @layout, [cut])

    Zip::File.open_volume_set(disks.map { |d| StringIO.new(d) }) do |zip|
      assert_equal 'A' * 30, zip.read('a.txt')
      assert_equal 'B' * 120, zip.read('b.bin')
    end
  end

  def test_compressed_data_is_split_across_disks
    # Cut 38 bytes into b's local record (30-byte static header + name),
    # so the deflate stream itself crosses the boundary.
    cut = @layout[:local_offsets][1] + 38
    disks = Fixtures.split_archive(@zip, @layout, [cut])

    Zip::File.open_volume_set(disks.map { |d| StringIO.new(d) }) do |zip|
      assert_equal 'B' * 120, zip.read('b.bin')
    end
  end

  def test_stored_data_split_exactly_on_a_boundary
    stored, stored_layout = Fixtures.build_zip(
      [
        { name: 'a.txt', data: 'A' * 30, method: 0 },
        { name: 'b.txt', data: 'B' * 60, method: 0 }
      ]
    )
    # b's data ends exactly at this cut point (35-byte header + 60 bytes).
    cut = stored_layout[:local_offsets][1] + 35 + 60
    disks = Fixtures.split_archive(stored, stored_layout, [cut])

    Zip::File.open_volume_set(disks.map { |d| StringIO.new(d) }) do |zip|
      assert_equal 'B' * 60, zip.read('b.txt')
      assert_equal 'A' * 30, zip.read('a.txt')
    end
  end

  def test_central_directory_record_is_split_across_disks
    # Cut 20 bytes into the first central directory record.
    disks = Fixtures.split_archive(
      @zip, @layout, [@layout[:cdir_offset] + 20]
    )

    Zip::File.open_volume_set(disks.map { |d| StringIO.new(d) }) do |zip|
      assert_equal 'A' * 30, zip.read('a.txt')
      assert_equal 'B' * 120, zip.read('b.bin')
    end
  end

  def test_eocd_itself_spans_the_last_boundary
    disks = Fixtures.split_archive(@zip, @layout, [@zip.bytesize - 10])

    Zip::File.open_volume_set(disks.map { |d| StringIO.new(d) }) do |zip|
      assert_equal 'A' * 30, zip.read('a.txt')
    end
  end

  def test_four_disks_with_records_on_every_disk
    cuts = [25, 80, @layout[:cdir_offset] + 30]
    disks = Fixtures.split_archive(@zip, @layout, cuts)

    Zip::File.open_volume_set(disks.map { |d| StringIO.new(d) }) do |zip|
      assert_equal 'A' * 30, zip.read('a.txt')
      assert_equal 'B' * 120, zip.read('b.bin')
      entry = zip.find_entry('b.bin')
      assert_equal 1, entry.disk_number_start
      assert_equal @layout[:local_offsets][1] - cuts[0],
                   entry.local_header_offset
    end
  end

  def test_reading_one_entry_only_opens_the_disks_it_needs
    # The central directory lives entirely on the final disk. a is on disk
    # 0; b's header/data span disks 1 and 2.
    big_zip, big_layout = Fixtures.build_zip(
      [
        { name: 'a.txt', data: 'A' * 30, method: 0 },
        { name: 'b.bin', data: 'B' * 400, method: 0 }
      ]
    )
    cuts = [65, 200, 300]
    disks = Fixtures.split_archive(big_zip, big_layout, cuts)
    tracker = Fixtures::TrackingOpener.new(disks)
    set = Zip::VolumeSet.open(disks.size, tracker)
    zip = Zip::File.new(set.reader(set.disk_count - 1),
                        buffer: true, volume_set: set)

    # Reading the central directory only opens the last disk.
    assert_equal [3], tracker.opened

    assert_equal 'A' * 30, zip.read('a.txt')
    assert_equal [3, 0], tracker.opened

    assert_equal 'B' * 400, zip.read('b.bin')
    assert_equal [3, 0, 1, 2], tracker.opened
  ensure
    set&.close
  end

  def test_spanning_signature_on_first_disk_is_skipped
    cuts = [@layout[:local_offsets][1] - 5]
    disks = Fixtures.add_spanning_signature(
      Fixtures.split_archive(@zip, @layout, cuts)
    )

    Zip::File.open_volume_set(disks.map { |d| StringIO.new(d) }) do |zip|
      assert_equal 'A' * 30, zip.read('a.txt')
      assert_equal 'B' * 120, zip.read('b.bin')
    end
  end

  def test_zip64_eocd_and_zip64_disk_number
    zip64_bytes, zip64_layout = Fixtures.build_zip(
      @entries, zip64_entry: 'b.bin', zip64_eocd: true
    )
    cuts = [25, 80, zip64_layout[:cdir_offset] + 20]
    disks = Fixtures.split_archive(
      zip64_bytes, zip64_layout, cuts,
      zip64_eocd: true, zip64_entry: true
    )

    Zip::File.open_volume_set(disks.map { |d| StringIO.new(d) }) do |zip|
      entry = zip.find_entry('b.bin')
      assert_equal 1, entry.disk_number_start
      assert_equal 'B' * 120, zip.read('b.bin')
      assert_equal 'A' * 30, zip.read('a.txt')
    end
  end

  def test_missing_last_disk_raises_with_disk_number
    disks = Fixtures.split_archive(@zip, @layout, [65])
    set = Zip::VolumeSet.open(2, ->(disk) { disk == 1 ? nil : StringIO.new(disks[0]) })

    error = assert_raises(Zip::MissingVolumeError) do
      Zip::File.new(set.reader(1), buffer: true, volume_set: set)
    end
    assert_equal 1, error.disk_number
  end

  def test_missing_member_disk_raises_with_disk_number_and_offset
    disks = Fixtures.split_archive(
      @zip, @layout, [@layout[:local_offsets][1] + 20]
    )
    # The central directory is read from the last disk; disk 0 (where b's
    # header starts) is only opened when b is read. Make that opener fail.
    set = Zip::VolumeSet.open(
      2,
      ->(disk) { raise 'boom' if disk.zero?

                 StringIO.new(disks[disk]) }
    )
    zip = Zip::File.new(set.reader(1), buffer: true, volume_set: set)

    error = assert_raises(Zip::MissingVolumeError) { zip.read('b.bin') }
    assert_equal 0, error.disk_number
    assert_match(/boom/, error.message)
  ensure
    set&.close
  end

  def test_wrong_number_of_disks_raises_volume_order_error
    disks = Fixtures.split_archive(@zip, @layout, [65])
    # Claim three disks; the EOCD on the last provided disk says two.
    set = Zip::VolumeSet.open(
      3, ->(disk) { StringIO.new(disks.fetch(disk, disks.last)) }
    )

    assert_raises(Zip::VolumeOrderError) do
      Zip::File.new(set.reader(2), buffer: true, volume_set: set)
    end
  ensure
    set&.close
  end

  def test_entry_pointing_at_a_missing_disk_reports_it
    disks = Fixtures.split_archive(@zip, @layout, [65]).map(&:dup)
    eocd = disks[1].rindex([Fixtures::EOCD_SIGNATURE].pack('V'))
    cdir_offset = disks[1][eocd + 16, 4].unpack1('V')
    # Rewrite a's start-disk field to a non-existent disk number.
    disks[1][cdir_offset + 34, 2] = [9].pack('v')

    Zip::File.open_volume_set(disks.map { |d| StringIO.new(d) }) do |zip|
      error = assert_raises(Zip::MissingVolumeError) { zip.read('a.txt') }
      assert_equal 9, error.disk_number
    end
  end

  def test_record_truncated_at_final_disk_boundary
    # Four disks: a on disk 0; b's header on disk 1 and its data spanning
    # disks 1 and 2; the central directory and EOCD on disk 3. Truncate
    # disk 2 in the middle of b's data: the record is cut off at a volume
    # boundary while the central directory remains readable. The error
    # locates disk 2 and an offset within it.
    stored, stored_layout = Fixtures.build_zip(
      [
        { name: 'a.txt', data: 'A' * 30, method: 0 },
        { name: 'b.txt', data: 'B' * 400, method: 0 }
      ]
    )
    # b's data spans disks 1 and 2 while the central directory is on disk
    # 3. Removing disk 2 cuts the record at a volume boundary: reading b
    # must fail and locate disk 2 (the disk the continuation was expected
    # on).
    disks = Fixtures.split_archive(stored, stored_layout, [65, 300, 450])

    set = Zip::VolumeSet.open(4, ->(disk) {
      raise Zip::MissingVolumeError.new(disk_number: disk) if disk == 2

      StringIO.new(disks[disk])
    })
    error = assert_raises(Zip::MissingVolumeError) do
      zip = Zip::File.new(set.reader(3), buffer: true, volume_set: set)
      zip.read('b.txt')
    end
    assert_equal 2, error.disk_number
  ensure
    set&.close
  end

  def test_local_header_truncated_at_disk_boundary
    # Four disks, with the central directory entirely on the last one. b's
    # local header starts at 65 on disk 1 and would continue on disk 2;
    # shorten disk 2 so it cannot contain the rest of the 35-byte header.
    big_zip, big_layout = Fixtures.build_zip(
      [
        { name: 'a.txt', data: 'A' * 30, method: 0 },
        { name: 'b.bin', data: 'B' * 400, method: 0 }
      ]
    )
    disks = Fixtures.split_archive(big_zip, big_layout, [65, 80, 200])

    # Disk 2, which b's local header continues on, is empty; the fixed
    # 30-byte local header therefore cannot be completed. Disk 3 holds the
    # central directory.
    set = Zip::VolumeSet.open(
      4,
      ->(disk) { StringIO.new(disk == 2 ? +'' : disks[disk]) }
    )
    error = assert_raises(Zip::VolumeTruncationError) do
      zip = Zip::File.new(set.reader(3), buffer: true, volume_set: set)
      zip.read('b.bin')
    end
    assert_equal 2, error.disk_number
    assert error.offset
  ensure
    set&.close
  end

  def test_provided_ios_are_not_closed
    disks = Fixtures.split_archive(@zip, @layout, [65])
    ios = disks.map { |d| StringIO.new(d) }

    Zip::File.open_volume_set(ios) do |zip|
      assert_equal 'A' * 30, zip.read('a.txt')
    end
    refute ios.any?(&:closed?)
  end

  def test_opener_ios_are_closed_when_auto_closing
    disks = Fixtures.split_archive(@zip, @layout, [65])
    opened = []

    Zip::File.open_volume_set(
      nil, disk_count: 2,
      opener: ->(disk) { io = StringIO.new(disks[disk]); opened << io; io }
    ) do |zip|
      assert_equal 'A' * 30, zip.read('a.txt')
    end
    assert opened.any?
    assert opened.all?(&:closed?)
  end

  def test_auto_close_false_keeps_opener_ios_open
    disks = Fixtures.split_archive(@zip, @layout, [65])
    opened = []

    Zip::File.open_volume_set(
      nil, disk_count: 2, auto_close: false,
      opener: ->(disk) { io = StringIO.new(disks[disk]); opened << io; io }
    ) do |zip|
      assert_equal 'A' * 30, zip.read('a.txt')
    end
    refute opened.any?(&:closed?)
    opened.each(&:close)
  end

  def test_volume_set_exposes_reader_for_manual_use
    disks = Fixtures.split_archive(@zip, @layout, [65])
    set = Zip::VolumeSet.from_ios(disks.map { |d| StringIO.new(d) })
    reader = set.reader(1, 0)
    reader.seek([0, 0], IO::SEEK_SET)
    assert_equal [Fixtures::LOCAL_SIGNATURE].pack('V'), reader.read(4)
  end
end
