# frozen_string_literal: true

require_relative 'test_helper'

class MultiVolumeIOTest < Minitest::Test
  DATA = 'Hello, multi-volume world!'.b

  def make_io(sizes = [6, 10, 26])
    volumes = {}
    offset = 0
    sizes.each_with_index do |size, disk|
      volumes[disk] = StringIO.new(DATA[offset, size] || '')
      offset += size
    end
    ::Zip::MultiVolumeIO.new(volumes)
  end

  def test_read_all_across_volumes
    assert_equal(DATA, make_io.read)
  end

  def test_read_with_length_across_volumes
    io = make_io
    assert_equal('Hello', io.read(5))
    assert_equal(', multi', io.read(7))
    assert_equal('-volume world!', io.read(100))
    assert_nil(io.read(1))
  end

  def test_read_zero_length
    io = make_io
    assert_equal('', io.read(0))
    assert_equal(0, io.pos)
  end

  def test_read_all_at_eof_returns_empty_string
    io = make_io
    io.read
    assert_equal('', io.read)
  end

  def test_read_into_outbuf
    io = make_io
    outbuf = +''
    assert_same(outbuf, io.read(5, outbuf))
    assert_equal('Hello', outbuf)
  end

  def test_read_negative_length_raises
    assert_raises(ArgumentError) { make_io.read(-1) }
  end

  def test_seek_and_tell
    io = make_io
    assert_equal(0, io.seek(7))
    assert_equal(7, io.tell)
    assert_equal('multi', io.read(5))

    assert_equal(0, io.seek(-5, ::IO::SEEK_CUR))
    assert_equal(7, io.pos)

    assert_equal(0, io.seek(-6, ::IO::SEEK_END))
    assert_equal(DATA.bytesize - 6, io.pos)
    assert_equal('world!', io.read)
  end

  def test_rewind
    io = make_io
    io.read(10)
    assert_equal(0, io.rewind)
    assert_equal(0, io.pos)
  end

  def test_pos_writer
    io = make_io
    io.pos = 7
    assert_equal(7, io.pos)
    assert_equal('multi', io.read(5))
  end

  def test_seek_to_exactly_end_is_allowed
    io = make_io
    io.seek(DATA.bytesize)
    assert(io.eof?)
    assert_nil(io.read(1))
  end

  def test_seek_negative_raises_einval
    io = make_io
    assert_raises(Errno::EINVAL) { io.seek(-1) }
    assert_raises(Errno::EINVAL) { io.seek(-DATA.bytesize - 1, ::IO::SEEK_END) }
  end

  def test_seek_unknown_whence_raises
    assert_raises(ArgumentError) { make_io.seek(0, 99) }
  end

  def test_seek_beyond_end_raises_volume_offset_error
    io = make_io
    error = assert_raises(::Zip::VolumeOffsetError) { io.seek(DATA.bytesize + 1) }
    assert_equal(DATA.bytesize + 1, error.offset)
  end

  def test_seek_onto_missing_volume_raises_missing_volume_error
    io = ::Zip::MultiVolumeIO.new(
      0 => StringIO.new('aaaa'),
      2 => StringIO.new('cccc')
    )
    error = assert_raises(::Zip::MissingVolumeError) { io.seek(5) }
    assert_equal(1, error.disk_number)
  end

  def test_read_from_missing_volume_raises_missing_volume_error
    io = ::Zip::MultiVolumeIO.new(
      0 => StringIO.new('aaaa'),
      2 => StringIO.new('cccc')
    )
    io.seek(4)
    assert_raises(::Zip::MissingVolumeError) { io.read(1) }
  end

  def test_size_only_counts_unbroken_sequence_from_disk_zero
    io = ::Zip::MultiVolumeIO.new(
      0 => StringIO.new('aaaa'),
      2 => StringIO.new('cccc')
    )
    assert_equal(4, io.size)
  end

  def test_add_volume_after_initialize
    io = ::Zip::MultiVolumeIO.new
    io.add_volume(0, StringIO.new('aaaa'))
    assert_equal(4, io.size)
    io.add_volume(1, StringIO.new('bbbb'))
    assert_equal(8, io.size)
    assert_equal('aaaabbbb', io.read)
  end

  def test_add_duplicate_volume_raises
    io = ::Zip::MultiVolumeIO.new(0 => StringIO.new('aaaa'))
    error = assert_raises(::Zip::DuplicateVolumeError) do
      io.add_volume(0, StringIO.new('bbbb'))
    end
    assert_equal(0, error.disk_number)
  end

  def test_add_volume_with_negative_disk_number_raises
    assert_raises(ArgumentError) do
      ::Zip::MultiVolumeIO.new.add_volume(-1, StringIO.new('aaaa'))
    end
  end

  def test_add_volume_with_non_seekable_io_raises
    assert_raises(ArgumentError) do
      ::Zip::MultiVolumeIO.new.add_volume(0, Object.new)
    end
  end

  def test_first_missing_disk
    assert_equal(0, ::Zip::MultiVolumeIO.new.first_missing_disk)
    assert_nil(make_io.first_missing_disk)
    gapped = ::Zip::MultiVolumeIO.new(
      0 => StringIO.new('aaaa'),
      2 => StringIO.new('cccc')
    )
    assert_equal(1, gapped.first_missing_disk)
  end

  def test_disk_number_for_offset
    io = make_io([4, 4, 4])
    assert_equal(0, io.disk_number_for_offset(0))
    assert_equal(0, io.disk_number_for_offset(3))
    assert_equal(1, io.disk_number_for_offset(4))
    assert_equal(2, io.disk_number_for_offset(11))
    assert_nil(io.disk_number_for_offset(12))
  end

  def test_volume_accessors
    v0 = StringIO.new('aaaa')
    v1 = StringIO.new('bbbb')
    io = ::Zip::MultiVolumeIO.new(0 => v0, 1 => v1)
    assert_same(v0, io[0])
    assert_same(v1, io[1])
    assert_nil(io[2])
    assert(io.volume?(1))
    refute(io.volume?(2))
    assert_equal([0, 1], io.disk_numbers)
    assert_equal(2, io.volume_count)
  end

  def test_close_does_not_close_volumes
    volumes = { 0 => StringIO.new('aaaa'), 1 => StringIO.new('bbbb') }
    io = ::Zip::MultiVolumeIO.new(volumes)
    io.close
    assert(io.closed?)
    volumes.each_value { |volume| refute(volume.closed?) }
  end

  def test_read_after_close_raises
    io = make_io
    io.close
    assert_raises(IOError) { io.read(1) }
    assert_raises(IOError) { io.seek(0) }
  end

  def test_dup_shares_volumes_but_not_position
    io = make_io
    io.read(3)
    copy = io.dup
    copy.seek(10)
    assert_equal(3, io.pos)
    assert_equal(10, copy.pos)
    assert_same(io[0], copy[0])
    copy.close
    refute(io.closed?)
  end

  def test_volumes_without_a_size_method
    # A minimal seekable IO that does not respond to #size: the size is
    # discovered by seeking to the end instead.
    wrapper_class = Class.new do
      def initialize(string)
        @io = StringIO.new(string)
      end

      def read(length = nil, outbuf = nil)
        @io.read(length, outbuf)
      end

      def seek(offset, whence = ::IO::SEEK_SET)
        @io.seek(offset, whence)
      end

      def tell
        @io.tell
      end
    end

    io = ::Zip::MultiVolumeIO.new(
      0 => wrapper_class.new('aaaa'),
      1 => wrapper_class.new('bbbb')
    )
    assert_equal(8, io.size)
    assert_equal('aaaabbbb', io.read)
  end

  def test_truncated_volume_raises
    # A volume whose IO returns fewer bytes than its reported size.
    io = ::Zip::MultiVolumeIO.new(0 => TruncatedIO.new(StringIO.new('aa')))
    assert_raises(::Zip::Error) { io.read }
  end

  # A StringIO wrapper that lies about its size.
  class TruncatedIO
    def initialize(io)
      @io = io
    end

    def read(length = nil, outbuf = nil)
      @io.read(length, outbuf)
    end

    def seek(offset, whence = ::IO::SEEK_SET)
      @io.seek(offset, whence)
    end

    def size
      4
    end
  end
end
