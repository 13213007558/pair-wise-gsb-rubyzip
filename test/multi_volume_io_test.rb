# frozen_string_literal: true

require_relative 'test_helper'

class ZipMultiVolumeIoTest < Minitest::Test
  DISKS = [('a' * 10).b, ('b' * 10).b, ('c' * 5).b].freeze

  # An IO that claims to be larger than the data it actually returns.
  class LyingIo < StringIO
    def size
      100
    end
  end

  def build_io
    ios = DISKS.map { |data| StringIO.new(data) }
    [::Zip::MultiVolumeIo.new(0 => ios[0], 1 => ios[1], 2 => ios[2]), ios]
  end

  def test_read_across_disk_boundaries
    io, = build_io
    assert_equal('aaaaaaaaaabbbbb', io.read(15))
    assert_equal('bbbbbccccc', io.read(10))
  end

  def test_read_to_end
    io, = build_io
    io.seek_disk(1, 5)
    assert_equal('bbbbbccccc', io.read)
  end

  def test_read_at_end_returns_nil
    io, = build_io
    io.seek_disk(2, 5)
    assert_nil(io.read(10))
    assert_equal('', io.read)
    assert_equal('', io.read(0))
  end

  def test_read_into_outbuf
    io, = build_io
    outbuf = +'junk'
    assert_same(outbuf, io.read(5, outbuf))
    assert_equal('aaaaa', outbuf)
  end

  def test_tell_returns_disk_relative_position
    io, = build_io
    io.seek_disk(1, 4)
    position = io.tell
    assert_equal(1, position.disk_number)
    assert_equal(4, position.offset)
    assert_equal('disk 1, offset 4', position.to_s)
  end

  def test_seek_with_integer_uses_logical_offsets
    io, = build_io
    io.seek(12)
    assert_equal(::Zip::MultiVolumeIo::Position.new(1, 2), io.tell)
  end

  def test_seek_cur_crosses_disks_in_both_directions
    io, = build_io
    io.seek_disk(0, 8)
    io.seek(5, IO::SEEK_CUR)
    assert_equal(::Zip::MultiVolumeIo::Position.new(1, 3), io.tell)
    io.seek(-13, IO::SEEK_CUR)
    assert_equal(::Zip::MultiVolumeIo::Position.new(0, 0), io.tell)
  end

  def test_seek_end
    io, = build_io
    io.seek(-5, IO::SEEK_END)
    assert_equal(::Zip::MultiVolumeIo::Position.new(2, 0), io.tell)
    io.seek(-15, IO::SEEK_END)
    assert_equal(::Zip::MultiVolumeIo::Position.new(1, 0), io.tell)
  end

  def test_seek_before_start_raises_einval
    io, = build_io
    assert_raises(Errno::EINVAL) { io.seek(-100, IO::SEEK_END) }
  end

  def test_seek_disk_rolls_past_disk_end
    io, = build_io
    io.seek_disk(0, 24)
    assert_equal(::Zip::MultiVolumeIo::Position.new(2, 4), io.tell)
  end

  def test_position_arithmetic_normalises_on_seek
    io, = build_io
    position = ::Zip::MultiVolumeIo::Position.new(1, 8) + 5
    assert_equal(::Zip::MultiVolumeIo::Position.new(1, 13), position)
    io.seek(position)
    assert_equal(::Zip::MultiVolumeIo::Position.new(2, 3), io.tell)
  end

  def test_position_zero
    assert(::Zip::MultiVolumeIo::Position.new(0, 0).zero?)
    refute(::Zip::MultiVolumeIo::Position.new(0, 1).zero?)
  end

  def test_missing_disk_raises_missing_disk_error
    io, = build_io
    error = assert_raises(::Zip::MissingDiskError) { io.seek_disk(5, 0) }
    assert_equal(5, error.disk_number)
    assert_match(/disk 5/, error.message)
  end

  def test_opener_returning_nil_raises_missing_disk_error
    io = ::Zip::MultiVolumeIo.new(2) { |disk| disk.zero? ? StringIO.new('aa') : nil }
    # Rolling over onto the missing disk 1 fails fast.
    error = assert_raises(::Zip::MissingDiskError) { io.seek_disk(0, 2) }
    assert_equal(1, error.disk_number)
  end

  def test_opener_is_called_lazily_and_only_once_per_disk
    opened = []
    io = ::Zip::MultiVolumeIo.new(3) do |disk|
      opened << disk
      StringIO.new(DISKS[disk])
    end
    io.read(5)
    assert_equal([0], opened)
    io.read(10)
    assert_equal([0, 1], opened)
    io.read
    assert_equal([0, 1, 2], opened)
  end

  def test_disk_ending_before_its_reported_size_raises
    io = ::Zip::MultiVolumeIo.new(0 => LyingIo.new('too short'))
    error = assert_raises(::Zip::MultiVolumeError) { io.read(50) }
    assert_equal(0, error.disk_number)
    assert_equal(9, error.disk_offset)
    assert_match(/disk 0/, error.message)
  end

  def test_close_does_not_close_disk_ios
    io, ios = build_io
    io.close
    refute(ios.any?(&:closed?))
    assert_raises(IOError) { io.read(1) }
  end

  def test_dup_has_an_independent_position
    io = ::Zip::MultiVolumeIo.new(3) { |disk| StringIO.new(DISKS[disk]) }
    io.seek_disk(2, 3)
    copy = io.dup
    assert_equal(::Zip::MultiVolumeIo::Position.new(2, 3), copy.tell)
    copy.seek_disk(0, 1)
    assert_equal(::Zip::MultiVolumeIo::Position.new(2, 3), io.tell)
  end

  def test_size_and_disk_size
    io, = build_io
    assert_equal(25, io.size)
    assert_equal(10, io.disk_size(1))
  end

  def test_hash_form_validation
    assert_raises(ArgumentError) { ::Zip::MultiVolumeIo.new({}) }
    assert_raises(ArgumentError) { ::Zip::MultiVolumeIo.new(1 => StringIO.new('a')) }
    assert_raises(ArgumentError) do
      ::Zip::MultiVolumeIo.new(0 => StringIO.new('a'), 2 => StringIO.new('b'))
    end
  end

  def test_block_form_validation
    assert_raises(ArgumentError) { ::Zip::MultiVolumeIo.new(2) }
    assert_raises(ArgumentError) { ::Zip::MultiVolumeIo.new('nope') }
    assert_raises(ArgumentError) { ::Zip::MultiVolumeIo.new(0 => StringIO.new('a')) { 'b' } }
  end
end
