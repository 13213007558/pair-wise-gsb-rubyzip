# frozen_string_literal: true

require_relative 'test_helper'

class ZipMultipartReaderTest < Minitest::Test
  def reader_for(strings)
    ::Zip::MultipartReader.new(strings.map { |s| StringIO.new(s) })
  end

  def test_size_is_the_sum_of_the_volumes
    assert_equal(8, reader_for(%w[aaa bbb cc]).size)
  end

  def test_read_crosses_volume_boundaries
    reader = reader_for(%w[aaa bbb cc])
    reader.seek(1)
    assert_equal('aabb', reader.read(4))
    assert_equal(5, reader.tell)
    assert_equal('bcc', reader.read(3))
    assert(reader.eof?)
  end

  def test_read_without_length_reads_to_the_end
    reader = reader_for(%w[aaa bbb cc])
    reader.seek(6)
    assert_equal('cc', reader.read)
    assert_equal('', reader.read)
  end

  def test_read_with_length_at_the_end_returns_nil
    reader = reader_for(%w[aaa bbb cc])
    reader.seek(8)
    assert_nil(reader.read(5))
    assert_equal('', reader.read(0))
  end

  def test_read_returns_binary_strings
    assert_equal(Encoding::ASCII_8BIT, reader_for(%w[aaa]).read(1).encoding)
  end

  def test_read_into_an_out_buffer
    reader = reader_for(%w[aaa bbb])
    out = +''
    assert_same(out, reader.read(4, out))
    assert_equal('aaab', out)
  end

  def test_seek_whences_and_rewind
    reader = reader_for(%w[aaa bbb cc])
    reader.seek(2)
    reader.seek(3, IO::SEEK_CUR)
    assert_equal(5, reader.tell)
    reader.seek(-3, IO::SEEK_END)
    assert_equal(5, reader.tell)
    reader.pos = 1
    assert_equal(1, reader.tell)
    reader.rewind
    assert_equal(0, reader.tell)
  end

  def test_seek_past_the_end_raises_volume_offset_error
    reader = reader_for(%w[aaa bbb cc])
    error = assert_raises(::Zip::VolumeOffsetError) { reader.seek(9) }
    assert_equal(9, error.offset)
    assert_equal(8, error.size)
    # Seeking exactly to the end is fine.
    reader.seek(8)
    assert(reader.eof?)
  end

  def test_seek_to_a_negative_position_raises_einval_like_io
    assert_raises(Errno::EINVAL) { reader_for(%w[aaa]).seek(-1) }
    assert_raises(Errno::EINVAL) { reader_for(%w[aaa]).seek(-4, IO::SEEK_END) }
  end

  def test_dup_has_an_independent_position
    reader = reader_for(%w[aaa bbb])
    reader.seek(2)
    copy = reader.dup
    copy.seek(0)
    assert_equal('a', copy.read(1))
    assert_equal(2, reader.tell)
  end

  def test_close_does_not_close_the_volumes
    ios = [StringIO.new('aaa'), StringIO.new('bbb')]
    reader = ::Zip::MultipartReader.new(ios)
    reader.close
    assert(reader.closed?)
    assert(ios.none?(&:closed?))
    assert_raises(IOError) { reader.read(1) }
  end

  def test_volumes_can_be_registered_one_by_one
    reader = ::Zip::MultipartReader.new
    reader.add_volume(0, StringIO.new('aaa'))
    reader.add_volume(1, StringIO.new('bbb'))
    assert_equal(2, reader.volume_count)
    assert_equal(6, reader.size)
  end

  def test_volumes_can_be_given_as_a_hash
    reader = ::Zip::MultipartReader.new(0 => StringIO.new('aa'), 2 => StringIO.new('cc'))
    assert_raises(::Zip::MissingVolumeError) { reader.size }
  end

  def test_duplicate_volume_raises
    reader = ::Zip::MultipartReader.new
    reader.add_volume(0, StringIO.new('aaa'))
    error = assert_raises(::Zip::DuplicateVolumeError) do
      reader.add_volume(0, StringIO.new('bbb'))
    end
    assert_equal(0, error.disk_number)
  end

  def test_missing_volume_in_the_sequence_raises
    reader = ::Zip::MultipartReader.new(0 => StringIO.new('aaa'),
                                        2 => StringIO.new('ccc'))
    error = assert_raises(::Zip::MissingVolumeError) { reader.size }
    assert_equal(1, error.disk_number)
  end

  def test_volume_io_must_be_seekable
    assert_raises(ArgumentError) do
      ::Zip::MultipartReader.new.add_volume(0, Object.new)
    end
  end

  def test_negative_disk_numbers_are_rejected
    assert_raises(ArgumentError) do
      ::Zip::MultipartReader.new.add_volume(-1, StringIO.new('aaa'))
    end
  end

  def test_no_volumes_raises
    assert_raises(::Zip::Error) { ::Zip::MultipartReader.new.size }
  end

  def test_volume_offset_translates_per_disk_offsets
    reader = reader_for(%w[aaa bbb cc])
    assert_equal(0, reader.volume_offset(0, 0))
    assert_equal(5, reader.volume_offset(1, 2))
    assert_equal(7, reader.volume_offset(2, 1))
  end

  def test_volume_offset_for_an_unknown_disk_raises_missing_volume
    reader = reader_for(%w[aaa bbb])
    error = assert_raises(::Zip::MissingVolumeError) do
      reader.volume_offset(2, 0)
    end
    assert_equal(2, error.disk_number)
  end

  def test_volumes_may_be_repositioned_by_the_caller_between_reads
    io = StringIO.new('aabbcc')
    reader = ::Zip::MultipartReader.new([io])
    assert_equal('aa', reader.read(2))
    io.seek(0) # The caller moves the volume around...
    assert_equal('bb', reader.read(2)) # ...and the reader still works.
  end

  def test_file_volumes_are_supported_and_left_open
    Dir.mktmpdir do |dir|
      paths = %w[aaa bbb].each_with_index.map do |data, i|
        path = File.join(dir, "vol#{i}")
        ::File.binwrite(path, data)
        path
      end
      ios = paths.map { |p| ::File.open(p, 'rb') }
      reader = ::Zip::MultipartReader.new(ios)
      assert_equal('aaabbb', reader.read)
      reader.close
      assert(ios.none?(&:closed?))
    ensure
      ios&.each { |io| io.close unless io.closed? }
    end
  end
end
