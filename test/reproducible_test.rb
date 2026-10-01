# frozen_string_literal: true

require 'digest'
require 'fileutils'

require_relative 'test_helper'

class ReproducibleTest < Minitest::Test
  SRC_DIR = ::File.join(Dir.tmpdir, 'repro_src').freeze
  ZIP_PATHS = (1..6).map { |n| ::File.join(Dir.tmpdir, "repro_#{n}.zip").freeze }.freeze

  def setup
    FileUtils.rm_rf(SRC_DIR)
    FileUtils.mkdir_p(::File.join(SRC_DIR, 'dir'))
    ::File.write(::File.join(SRC_DIR, 'a.txt'), "alpha\n")
    ::File.write(::File.join(SRC_DIR, 'b.txt'), "bravo\n" * 200)
    ::File.write(::File.join(SRC_DIR, 'dir', 'c.txt'), "charlie\n")
  end

  def teardown
    FileUtils.rm_rf(SRC_DIR)
    ZIP_PATHS.each { |path| FileUtils.rm_f(path) }
  end

  def test_shuffled_order_and_changed_metadata_produce_identical_archives
    first = build_zip(ZIP_PATHS[0], %w[a.txt b.txt dir/c.txt])

    # Change source file mtimes and permissions, then repackage in a
    # different order.
    ::File.utime(::Time.now - 86_400, ::Time.now - 86_400, ::File.join(SRC_DIR, 'a.txt'))
    ::File.utime(::Time.now + 86_400, ::Time.now + 86_400, ::File.join(SRC_DIR, 'b.txt'))
    ::File.chmod(0o600, ::File.join(SRC_DIR, 'dir', 'c.txt'))

    second = build_zip(ZIP_PATHS[1], %w[dir/c.txt b.txt a.txt])

    assert_equal first, second
  end

  def test_non_reproducible_output_still_varies_with_source_mtime
    first = build_zip(ZIP_PATHS[0], %w[a.txt], reproducible: false)
    ::File.utime(::Time.now - 3600, ::Time.now - 3600, ::File.join(SRC_DIR, 'a.txt'))
    second = build_zip(ZIP_PATHS[1], %w[a.txt], reproducible: false)

    refute_equal first, second
  end

  def test_entries_are_sorted_with_fixed_time_and_permissions
    build_zip(ZIP_PATHS[0], %w[b.txt dir/c.txt a.txt])

    ::Zip::File.open(ZIP_PATHS[0]) do |zf|
      names = zf.entries.map(&:name)
      assert_equal names.sort, names

      zf.each do |entry|
        assert_equal [1980, 1, 1, 0, 0, 0],
                     [entry.mtime.year, entry.mtime.month, entry.mtime.day,
                      entry.mtime.hour, entry.mtime.min, entry.mtime.sec]
        assert_equal(entry.directory? ? 0o755 : 0o644, entry.unix_perms)
      end
    end
  end

  def test_explicitly_provided_extra_field_raises_with_reason
    extra = ::Zip::ExtraField.new
    extra.create(:universaltime)

    zf = ::Zip::File.new(ZIP_PATHS[0], create: true, reproducible: true)
    zf.get_output_stream('x.txt', extra: extra) { |os| os << 'x' }

    error = assert_raises(::Zip::NonReproducibleError) { zf.commit }
    assert_match(/universaltime/, error.message)
    assert_match(/allowed_extra_fields/, error.message)
  end

  def test_gathered_extra_fields_are_silently_stripped
    entry = ::Zip::Entry.new(ZIP_PATHS[0], 'x.txt')
    entry.time = ::Time.now # creates a universaltime extra field implicitly

    zf = ::Zip::File.new(ZIP_PATHS[0], create: true, reproducible: true)
    zf.get_output_stream(entry) { |os| os << 'x' }
    zf.commit

    ::Zip::File.open(ZIP_PATHS[0]) do |zip|
      refute zip.get_entry('x.txt').extra.key?(:universaltime)
    end
  end

  def test_allowed_extra_fields_can_be_extended
    extra = ::Zip::ExtraField.new
    extra.create(:universaltime)

    zf = ::Zip::File.new(
      ZIP_PATHS[0], create: true,
                    reproducible: { allowed_extra_fields: [:zip64, :universaltime] }
    )
    zf.get_output_stream('x.txt', extra: extra) { |os| os << 'x' }
    zf.commit

    ::Zip::File.open(ZIP_PATHS[0]) do |zip|
      assert zip.get_entry('x.txt').extra.key?(:universaltime)
    end
  end

  def test_invalid_utf8_entry_name_raises_with_reason
    zf = ::Zip::File.new(ZIP_PATHS[0], create: true, reproducible: true)
    zf.add("bad_\xFF.txt", ::File.join(SRC_DIR, 'a.txt'))

    error = assert_raises(::Zip::NonReproducibleError) { zf.commit }
    assert_match(/UTF-8/, error.message)
  end

  def test_non_utf8_entry_names_are_transcoded
    zf = ::Zip::File.new(ZIP_PATHS[0], create: true, reproducible: true)
    zf.get_output_stream('日本語.txt'.encode(::Encoding::SHIFT_JIS)) { |os| os << 'x' }
    zf.commit

    ::Zip::File.open(ZIP_PATHS[0]) do |zip|
      entry = zip.entries.first
      assert_equal '日本語.txt', entry.name.dup.force_encoding(::Encoding::UTF_8)
      refute_equal 0, entry.gp_flags & ::Zip::Entry::EFS
    end
  end

  def test_source_date_epoch_sets_the_fixed_time
    ENV['SOURCE_DATE_EPOCH'] = '1000000000' # 2001-09-09 01:46:40 UTC
    build_zip(ZIP_PATHS[0], %w[a.txt])

    ::Zip::File.open(ZIP_PATHS[0]) do |zip|
      mtime = zip.get_entry('a.txt').mtime
      assert_equal [2001, 9, 9, 1, 46, 40],
                   [mtime.year, mtime.month, mtime.day, mtime.hour, mtime.min, mtime.sec]
    end
  ensure
    ENV.delete('SOURCE_DATE_EPOCH')
  end

  def test_custom_fixed_time_option
    zf = ::Zip::File.new(
      ZIP_PATHS[0], create: true,
                    reproducible: { time: ::Time.utc(1999, 12, 31, 23, 59, 58) }
    )
    zf.get_output_stream('x.txt') { |os| os << 'x' }
    zf.commit

    ::Zip::File.open(ZIP_PATHS[0]) do |zip|
      mtime = zip.get_entry('x.txt').mtime
      assert_equal [1999, 12, 31, 23, 59, 58],
                   [mtime.year, mtime.month, mtime.day, mtime.hour, mtime.min, mtime.sec]
    end
  end

  def test_unknown_reproducible_option_raises
    assert_raises(ArgumentError) do
      ::Zip::File.new(ZIP_PATHS[0], create: true, reproducible: { bogus: 1 })
    end
  end

  def test_unknown_allowed_extra_field_raises
    assert_raises(ArgumentError) do
      ::Zip::File.new(ZIP_PATHS[0], create: true, reproducible: { allowed_extra_fields: [:bogus] })
    end
  end

  def test_open_buffer_produces_identical_bytes_regardless_of_order
    buffers = [%w[a.txt b.txt], %w[b.txt a.txt]].map do |order|
      ::Zip::File.open_buffer(::StringIO.new, create: true, reproducible: true) do |zf|
        order.each { |name| zf.get_output_stream(name) { |os| os << "content of #{name}" } }
      end
    end

    assert_equal buffers[0].string, buffers[1].string
  end

  def test_output_stream_normalizes_entries
    2.times do |i|
      ::Zip::OutputStream.open(ZIP_PATHS[i], reproducible: true) do |zos|
        entry = ::Zip::Entry.new(ZIP_PATHS[i], 'a.txt', time: ::Time.now + (i * 3600))
        zos.put_next_entry(entry)
        zos << 'content'
      end
    end

    assert_equal Digest::SHA256.file(ZIP_PATHS[0]).hexdigest,
                 Digest::SHA256.file(ZIP_PATHS[1]).hexdigest
  end

  def test_output_stream_rejects_encryption_as_non_reproducible
    assert_raises(::Zip::NonReproducibleError) do
      ::Zip::OutputStream.new(
        ZIP_PATHS[0],
        encrypter: ::Zip::TraditionalEncrypter.new('password'),
        reproducible: true
      )
    end
  end

  private

  def build_zip(path, entry_names, reproducible: true)
    ::Zip::File.open(path, create: true, reproducible: reproducible) do |zf|
      entry_names.each { |name| zf.add(name, ::File.join(SRC_DIR, name)) }
      zf.get_output_stream('streamed.txt') { |os| os << 'streamed content' }
      zf.mkdir('empty_dir')
    end
    Digest::SHA256.file(path).hexdigest
  end
end
