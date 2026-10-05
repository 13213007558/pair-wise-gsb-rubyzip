# frozen_string_literal: true

require_relative 'test_helper'

# Tests for reading entry names that are stored as legacy (e.g. CP437)
# bytes alongside an Info-ZIP Unicode Path extra field (0x7075), and for
# preserving the original name representation when writing entries back.
class UnicodePathNamesTest < Minitest::Test
  CP437_NAME = "caf\x82.txt".b # 'café.txt' with é in CP437
  UTF8_NAME  = "caf\u00e9.txt"

  def teardown
    ::Zip.reset!
  end

  def test_adopts_valid_unicode_path_name
    entry = ::Zip::Entry.new('zf.zip', CP437_NAME,
                             extra: unicode_path_extra(CP437_NAME, UTF8_NAME))
    buffer = write_zip([[entry, 'data']])

    ::Zip::File.open_buffer(buffer.string) do |zf|
      read_entry = zf.entries.first
      assert_equal(UTF8_NAME, read_entry.name)
      assert_equal(Encoding::UTF_8, read_entry.name.encoding)
      assert_equal(CP437_NAME, read_entry.raw_name)
      assert_equal(Encoding::BINARY, read_entry.raw_name.encoding)
      assert_equal('data', read_entry.get_input_stream(&:read))
    end

    ::Zip::InputStream.open(::StringIO.new(buffer.string)) do |io|
      read_entry = io.get_next_entry
      assert_equal(UTF8_NAME, read_entry.name)
      assert_equal(CP437_NAME, read_entry.raw_name)
    end
  end

  def test_efs_flagged_name_is_decoded_as_utf8
    entry = ::Zip::Entry.new('zf.zip', UTF8_NAME)
    entry.gp_flags |= ::Zip::Entry::EFS
    buffer = write_zip([[entry, 'data']])

    ::Zip::File.open_buffer(buffer.string) do |zf|
      read_entry = zf.entries.first
      assert_equal(UTF8_NAME, read_entry.name)
      assert_equal(Encoding::UTF_8, read_entry.name.encoding)
      assert_equal(UTF8_NAME.b, read_entry.raw_name)
    end
  end

  def test_unicode_path_with_crc_mismatch_is_not_adopted
    entry = ::Zip::Entry.new('zf.zip', CP437_NAME,
                             extra: unicode_path_extra(CP437_NAME, UTF8_NAME, crc: 0))
    buffer = write_zip([[entry, 'data']])

    ::Zip::File.open_buffer(buffer.string) do |zf|
      read_entry = zf.entries.first
      assert_equal(CP437_NAME, read_entry.name)
      refute_nil(read_entry.extra[:unicodepath], 'extra field should still be preserved')
    end
  end

  def test_unicode_path_with_invalid_utf8_is_not_adopted
    entry = ::Zip::Entry.new('zf.zip', CP437_NAME,
                             extra: unicode_path_extra(CP437_NAME, "bad\xff\xfe.txt".b))
    buffer = write_zip([[entry, 'data']])

    ::Zip::File.open_buffer(buffer.string) do |zf|
      assert_equal(CP437_NAME, zf.entries.first.name)
    end
  end

  def test_unicode_path_with_unknown_version_is_not_adopted
    entry = ::Zip::Entry.new('zf.zip', CP437_NAME,
                             extra: unicode_path_extra(CP437_NAME, UTF8_NAME, version: 2))
    buffer = write_zip([[entry, 'data']])

    ::Zip::File.open_buffer(buffer.string) do |zf|
      assert_equal(CP437_NAME, zf.entries.first.name)
    end
  end

  def test_entries_with_same_display_name_are_both_kept_and_readable
    ::Zip.allow_duplicate_entry_names = true
    cp437_entry = ::Zip::Entry.new('zf.zip', CP437_NAME,
                                   extra: unicode_path_extra(CP437_NAME, UTF8_NAME))
    efs_entry = ::Zip::Entry.new('zf.zip', UTF8_NAME)
    efs_entry.gp_flags |= ::Zip::Entry::EFS
    buffer = write_zip([[cp437_entry, 'data-cp437'], [efs_entry, 'data-efs']])

    ::Zip::File.open_buffer(buffer.string) do |zf|
      assert_equal(2, zf.entries.size)
      assert_equal([UTF8_NAME, UTF8_NAME], zf.entries.map(&:name))

      found = zf.find_entry(UTF8_NAME)
      assert_equal(2, found.size)
      assert_equal(%w[data-cp437 data-efs],
                   found.map { |entry| entry.get_input_stream(&:read) }.sort)
    end
  end

  def test_unrenamed_entry_roundtrips_original_name_representation
    with_temp_zip do |path|
      entry = ::Zip::Entry.new(path, CP437_NAME,
                               extra: unicode_path_extra(CP437_NAME, UTF8_NAME))
      ::Zip::OutputStream.open(path) do |zos|
        zos.put_next_entry(entry)
        zos << 'data'
      end

      ::Zip::File.open(path) { |zf| zf.comment = 'force a rewrite' }

      rewritten = ::File.binread(path)
      assert_includes(rewritten, CP437_NAME, 'raw name bytes should be preserved')
      assert_includes(rewritten, unicode_path_bin(CP437_NAME, UTF8_NAME),
                      'unicode path extra field should be preserved')

      ::Zip::File.open(path) do |zf|
        read_entry = zf.entries.first
        assert_equal(UTF8_NAME, read_entry.name)
        assert_equal(CP437_NAME, read_entry.raw_name)
        assert_equal(0, read_entry.gp_flags & ::Zip::Entry::EFS)
        refute_nil(read_entry.extra[:unicodepath])
      end
    end
  end

  def test_rename_updates_flags_and_removes_unicode_path_extra
    with_temp_zip do |path|
      entry = ::Zip::Entry.new(path, CP437_NAME,
                               extra: unicode_path_extra(CP437_NAME, UTF8_NAME))
      ::Zip::OutputStream.open(path) do |zos|
        zos.put_next_entry(entry)
        zos << 'data'
      end

      ::Zip::File.open(path) do |zf|
        zf.rename(UTF8_NAME, "n\u00e9w.txt")
      end

      rewritten = ::File.binread(path)
      assert_includes(rewritten, "n\u00e9w.txt".b)
      refute_includes(rewritten, CP437_NAME)
      refute_includes(rewritten, unicode_path_bin(CP437_NAME, UTF8_NAME))

      ::Zip::File.open(path) do |zf|
        read_entry = zf.find_entry("n\u00e9w.txt")
        refute_nil(read_entry)
        assert_equal(::Zip::Entry::EFS, read_entry.gp_flags & ::Zip::Entry::EFS)
        assert_nil(read_entry.extra[:unicodepath])
        assert_equal("n\u00e9w.txt".b, read_entry.raw_name)
        assert_equal('data', read_entry.get_input_stream(&:read))
      end
    end
  end

  def test_ascii_rename_clears_efs_flag
    with_temp_zip do |path|
      entry = ::Zip::Entry.new(path, UTF8_NAME)
      entry.gp_flags |= ::Zip::Entry::EFS
      ::Zip::OutputStream.open(path) do |zos|
        zos.put_next_entry(entry)
        zos << 'data'
      end

      ::Zip::File.open(path) do |zf|
        zf.rename(UTF8_NAME, 'plain.txt')
      end

      ::Zip::File.open(path) do |zf|
        read_entry = zf.find_entry('plain.txt')
        refute_nil(read_entry)
        assert_equal(0, read_entry.gp_flags & ::Zip::Entry::EFS)
      end
    end
  end

  private

  def unicode_path_bin(raw_name, utf8_name, crc: nil, version: 1)
    crc = Zlib.crc32(raw_name) if crc.nil?
    content = [version, crc].pack('CV') + utf8_name.b
    "\x70\x75".b + [content.bytesize].pack('v') + content
  end

  def unicode_path_extra(raw_name, utf8_name, crc: nil, version: 1)
    ::Zip::ExtraField.new(
      unicode_path_bin(raw_name, utf8_name, crc: crc, version: version)
    )
  end

  def write_zip(entries)
    ::Zip::OutputStream.write_buffer do |zos|
      entries.each do |entry, data|
        zos.put_next_entry(entry)
        zos << data
      end
    end
  end

  def with_temp_zip
    file = Tempfile.new(['rubyzip-unicode-path', '.zip'])
    path = file.path
    file.close!
    yield path
  ensure
    FileUtils.rm_f(path)
  end
end
