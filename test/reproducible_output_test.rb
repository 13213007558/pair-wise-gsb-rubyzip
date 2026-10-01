# frozen_string_literal: true

require 'digest'
require 'fileutils'

require_relative 'test_helper'

class ZipReproducibleOutputTest < Minitest::Test
  def setup
    @tmpdir = Dir.mktmpdir('rubyzip-reproducible')
    @source_dir = File.join(@tmpdir, 'source')
    FileUtils.mkdir_p(File.join(@source_dir, 'subdir'))
    FileUtils.mkdir_p(File.join(@source_dir, 'empty_dir'))
    write_source_file('b.txt', 'second', 0o600, Time.utc(2001, 2, 3, 4, 5, 6))
    write_source_file('a.txt', 'first', 0o755, Time.utc(2002, 3, 4, 5, 6, 7))
    write_source_file('subdir/c.txt', 'third', 0o640, Time.utc(2003, 4, 5, 6, 7, 8))
  end

  def teardown
    FileUtils.rm_rf(@tmpdir)
    Zip.reset!
  end

  def test_file_archive_is_byte_identical_regardless_of_input_order_and_source_times
    first = archive_from_paths(['empty_dir', 'b.txt', 'subdir/c.txt', 'a.txt'])
    write_source_file('b.txt', 'second', 0o600, Time.utc(2020, 1, 2, 3, 4, 5))
    write_source_file('a.txt', 'first', 0o755, Time.utc(2021, 2, 3, 4, 5, 6))
    second = archive_from_paths(['a.txt', 'b.txt', 'subdir/c.txt', 'empty_dir'])

    assert_equal Digest::SHA256.file(first).hexdigest,
                 Digest::SHA256.file(second).hexdigest
  end

  def test_output_stream_is_byte_identical_regardless_of_entry_order
    first = build_stream_archive(%w[b.txt a.txt subdir/c.txt])
    second = build_stream_archive(%w[a.txt subdir/c.txt b.txt])

    assert_equal Digest::SHA256.digest(first), Digest::SHA256.digest(second)
  end

  def test_output_stream_is_independent_of_zip64_configuration
    Zip.write_zip64_support = false
    first = build_stream_archive(%w[a.txt b.txt])
    Zip.write_zip64_support = true
    second = build_stream_archive(%w[a.txt b.txt])

    assert_equal Digest::SHA256.digest(first), Digest::SHA256.digest(second)
  ensure
    Zip.write_zip64_support = true
  end

  def test_archive_uses_canonical_order_time_permissions_and_extra_fields
    archive = archive_from_paths(['b.txt', 'a.txt', 'subdir/c.txt', 'empty_dir'])

    Zip::File.open(archive) do |zip|
      entry_names = zip.entries.map(&:name)
      assert_equal %w[a.txt b.txt empty_dir/ subdir/c.txt], entry_names

      zip.entries.each do |entry|
        assert_equal Time.local(1980, 1, 1, 0, 0, 0), entry.mtime
        assert_predicate(entry.name.dup.force_encoding(Encoding::UTF_8), :valid_encoding?)
        assert_predicate entry.gp_flags & Zip::Entry::EFS, :positive?
        assert_empty entry.extra
      end

      assert_equal [0o644, 0o644, 0o755, 0o644], zip.entries.map(&:unix_perms)
    end
  end

  def test_explicit_canonicalizable_time_is_normalized_without_an_error
    archive = File.join(@tmpdir, 'explicit.zip')

    Zip::OutputStream.open(archive, reproducible: true) do |zos|
      zos.put_next_entry(Zip::Entry.new(nil, 'a.txt', time: Time.utc(2001, 1, 1)))
      zos.write 'first'
    end

    Zip::File.open(archive) do |zip|
      assert_equal Time.local(1980, 1, 1), zip.get_entry('a.txt').mtime
    end
  end

  def test_explicit_permissions_and_time_are_normalized_for_stream_entries
    archive = File.join(@tmpdir, 'stream-entry.zip')

    Zip::File.open(archive, create: true, reproducible: true) do |zip|
      zip.get_output_stream('a.txt', permissions: 0o600, time: Time.utc(2001, 1, 1)) do |io|
        io.write 'first'
      end
    end

    Zip::File.open(archive) do |zip|
      entry = zip.get_entry('a.txt')
      assert_equal 0o644, entry.unix_perms
      assert_equal Time.local(1980, 1, 1), entry.mtime
    end
  end

  def test_unknown_extra_fields_are_rejected_with_an_explicit_reason
    extra = Zip::ExtraField.new("\x01\x02\x03\x00abc".b)
    entry = Zip::Entry.new(nil, 'a.txt', extra: extra)

    error = assert_raises(ArgumentError) do
      Zip::OutputStream.write_buffer(reproducible: true) do |zos|
        zos.put_next_entry(entry)
        zos.write 'first'
      end
    end

    assert_match(/unknown extra field/, error.message)
  end

  def test_known_timestamp_extra_fields_are_removed
    entry = Zip::Entry.new(nil, 'a.txt')
    entry.atime = Time.utc(2001, 1, 1)
    entry.mtime = Time.utc(2002, 2, 2)

    buffer = Zip::OutputStream.write_buffer(reproducible: true) do |zos|
      zos.put_next_entry(entry)
      zos.write 'first'
    end

    Zip::File.open_buffer(buffer) do |zip|
      stored = zip.get_entry('a.txt')
      assert_empty stored.extra
      assert_equal Time.local(1980, 1, 1), stored.mtime
    end
  end

  def test_random_encryption_is_rejected_with_an_explicit_reason
    encrypter = Zip::TraditionalEncrypter.new('password')

    error = assert_raises(ArgumentError) do
      Zip::OutputStream.write_buffer(reproducible: true, encrypter: encrypter) do |zos|
        zos.put_next_entry('a.txt')
        zos.write 'first'
      end
    end

    assert_match(/random header data/, error.message)
  end

  def test_duplicate_entry_names_are_rejected
    Zip.allow_duplicate_entry_names = true

    error = assert_raises(ArgumentError) do
      Zip::OutputStream.write_buffer(reproducible: true) do |zos|
        zos.put_next_entry('a.txt')
        zos.write 'first'
        zos.put_next_entry('a.txt')
        zos.write 'second'
      end
    end

    assert_match(/duplicate entry name/, error.message)
  end

  def test_non_utf8_entry_names_are_rejected_with_an_explicit_reason
    name = "\x80.txt".dup.force_encoding(Encoding::UTF_8)

    error = assert_raises(ArgumentError) do
      Zip::OutputStream.write_buffer(reproducible: true) do |zos|
        zos.put_next_entry(name)
        zos.write 'first'
      end
    end

    assert_match(/entry name is not valid UTF-8/, error.message)
  end

  def test_non_utf8_entry_comments_are_rejected_with_an_explicit_reason
    comment = "\x80".dup.force_encoding(Encoding::UTF_8)

    error = assert_raises(ArgumentError) do
      Zip::OutputStream.write_buffer(reproducible: true) do |zos|
        zos.put_next_entry('a.txt', comment)
        zos.write 'first'
      end
    end

    assert_match(/entry comment is not valid UTF-8/, error.message)
  end

  private

  def write_source_file(relative_name, contents, mode, mtime)
    path = File.join(@source_dir, relative_name)
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, contents)
    File.chmod(mode, path)
    FileUtils.touch(path, mtime: mtime)
  end

  def archive_from_paths(paths)
    archive = File.join(@tmpdir, "#{paths.hash}.zip")
    FileUtils.rm_f(archive)

    Zip::File.open(archive, create: true, reproducible: true) do |zip|
      paths.each { |path| zip.add(path, File.join(@source_dir, path)) }
    end

    archive
  end

  def build_stream_archive(paths)
    Zip::OutputStream.write_buffer(reproducible: true) do |zos|
      paths.each do |path|
        zos.put_next_entry(path)
        zos.write(File.binread(File.join(@source_dir, path)))
      end
    end.string
  end
end
