# frozen_string_literal: true

require_relative '../test_helper'

require 'zip/ioextras'

class WriteOnlyIOTest < Minitest::Test
  class Target
    attr_reader :written, :binmode_count, :flush_count

    def initialize
      @written = +''.b
      @binmode_count = 0
      @flush_count = 0
    end

    def write(data)
      @written << data
      data.bytesize
    end

    def binmode
      @binmode_count += 1
      self
    end

    def flush
      @flush_count += 1
      self
    end
  end

  class AppendTarget
    attr_reader :written

    def initialize
      @written = +''.b
    end

    def <<(data)
      @written << data
      self
    end
  end

  def test_requires_a_writable_destination
    assert_raises(ArgumentError) do
      ::Zip::IOExtras::WriteOnlyIO.new(Object.new)
    end
  end

  def test_write_passes_bytes_through_and_counts_them
    target = Target.new
    io = ::Zip::IOExtras::WriteOnlyIO.new(target)

    assert_equal(5, io.write('hello'))
    io << ' world'
    assert_equal('hello world', target.written)
    assert_equal(11, io.tell)
    assert_equal(11, io.pos)
  end

  def test_append_only_destination_is_supported
    target = AppendTarget.new
    io = ::Zip::IOExtras::WriteOnlyIO.new(target)
    io.write('a')
    io << 'b'
    assert_equal('ab', target.written)
    assert_equal(2, io.tell)
  end

  def test_binmode_and_flush_are_optional_and_forwarded
    target = Target.new
    io = ::Zip::IOExtras::WriteOnlyIO.new(target)
    io.binmode
    io.flush
    assert_equal(1, target.binmode_count)
    assert_equal(1, target.flush_count)
  end

  def test_start_offset_is_added_to_the_count
    target = Target.new
    io = ::Zip::IOExtras::WriteOnlyIO.new(target, start_offset: 0x1000)
    io.write('abc')
    assert_equal(0x1003, io.tell)
    assert_equal('abc', target.written)
  end

  def test_no_seek_is_provided
    io = ::Zip::IOExtras::WriteOnlyIO.new(Target.new)
    refute_respond_to(io, :seek)
    refute_respond_to(io, :pos=)
    refute_respond_to(io, :close)
  end
end
