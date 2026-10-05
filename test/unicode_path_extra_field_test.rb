# frozen_string_literal: true

require_relative 'test_helper'
require 'tmpdir'

# Tests for reading entry names stored as CP437 bytes, UTF-8 bytes (EFS
# flag) and/or an Info-ZIP Unicode Path extra field (0x7075), covering:
#
# * preservation of both the raw name bytes and the Unicode display name
# * CRC validation of the 0x7075 field before it is trusted
# * invalid UTF-8 fallbacks
# * entries whose names normalise to the same Unicode display name
# * write-back of unrenamed entries vs. explicit renames
class UnicodePathExtraFieldTest < Minitest::Test
  # 'café.txt' in CP437 (0x82 == é) and in UTF-8.
  CP437_NAME = "caf\x82.txt".b
  UTF8_NAME = "caf\u00e9.txt"

  def setup
    @tmpdir = Dir.mktmpdir
    @zip_path = File.join(@tmpdir, 'test.zip')
  end

  def teardown
    ::Zip.reset!
    FileUtils.rm_rf(@tmpdir)
  end

  def test_cp437_name_displayed_as_unicode_and_raw_preserved
    write_zip([[build_entry(CP437_NAME), 'content']])

    ::Zip::File.open(@zip_path) do |zip|
      entry = zip.entries.first
      assert_equal(UTF8_NAME, entry.name)
      assert_equal(Encoding::UTF_8, entry.name.encoding)
      assert_equal(CP437_NAME, entry.raw_name)
      assert_equal(Encoding::BINARY, entry.raw_name.encoding)
    end

    ::Zip::InputStream.open(@zip_path) do |io|
      entry = io.get_next_entry
      assert_equal(UTF8_NAME, entry.name)
      assert_equal(CP437_NAME, entry.raw_name)
    end
  end

  def test_efs_flag_name_read_as_utf8
    write_zip([[build_entry(UTF8_NAME, efs: true), 'content']])

    ::Zip::File.open(@zip_path) do |zip|
      entry = zip.entries.first
      assert_equal(UTF8_NAME, entry.name)
      assert_equal(UTF8_NAME.b, entry.raw_name)
    end
  end

  def test_unicode_path_extra_field_used_when_crc_valid
    unicode_name = 'café ☕.txt'
    write_zip([[build_entry(CP437_NAME, unicode_path: unicode_name), 'content']])

    ::Zip::File.open(@zip_path) do |zip|
      entry = zip.entries.first
      assert_equal(unicode_name, entry.name)
      assert_equal(CP437_NAME, entry.raw_name)
    end
  end

  def test_unicode_path_extra_field_ignored_when_crc_invalid
    write_zip([[build_entry(CP437_NAME, unicode_path: 'stale-name.txt',
                           corrupt_crc: true), 'content']])

    ::Zip::File.open(@zip_path) do |zip|
      entry = zip.entries.first
      # The stale field is ignored: fall back to the CP437 interpretation.
      assert_equal(UTF8_NAME, entry.name)
      # ... but the field itself is still parsed and preserved.
      refute_nil(entry.extra[:unicodepath])
      assert_equal('stale-name.txt', entry.extra[:unicodepath].name)
    end
  end

  def test_unicode_path_extra_field_ignored_when_not_valid_utf8
    write_zip([[build_entry(CP437_NAME, unicode_path: "bad\xff\xfe".b), 'content']])

    ::Zip::File.open(@zip_path) do |zip|
      assert_equal(UTF8_NAME, zip.entries.first.name)
    end
  end

  def test_invalid_utf8_bytes_with_efs_flag_fall_back_to_cp437
    write_zip([[build_entry(CP437_NAME, efs: true), 'content']])

    ::Zip::File.open(@zip_path) do |zip|
      assert_equal(UTF8_NAME, zip.entries.first.name)
    end
  end

  def test_force_entry_names_encoding_takes_precedence
    write_zip([[build_entry(CP437_NAME, unicode_path: UTF8_NAME), 'content']])

    ::Zip.force_entry_names_encoding = 'CP437'
    ::Zip::File.open(@zip_path) do |zip|
      entry = zip.entries.first
      assert_equal(CP437_NAME.dup.force_encoding('CP437'), entry.name)
      assert_equal(Encoding::CP437, entry.name.encoding)
    end
  end

  def test_entries_normalising_to_same_display_name_are_all_kept_and_readable
    cp437_entry = build_entry(CP437_NAME)
    utf8_entry = build_entry(UTF8_NAME, efs: true)
    write_zip([[cp437_entry, 'cp437 content'], [utf8_entry, 'utf8 content']])

    ::Zip::File.open(@zip_path) do |zip|
      # Both entries survive in the entry set; neither overwrote the other.
      assert_equal(2, zip.entries.size)
      assert_equal([UTF8_NAME, UTF8_NAME], zip.entries.map(&:name))

      # ... and each one can still be read individually.
      contents = zip.entries.map { |entry| zip.get_input_stream(entry).read }
      assert_equal(['cp437 content', 'utf8 content'], contents)

      refute_nil(zip.find_entry(UTF8_NAME))
    end
  end

  def test_find_entry_by_display_name_for_cp437_entry
    write_zip([[build_entry(CP437_NAME), 'data']])

    ::Zip::File.open(@zip_path) do |zip|
      entry = zip.find_entry(UTF8_NAME)
      refute_nil(entry)
      assert_equal(CP437_NAME, entry.raw_name)
      assert_equal('data', zip.read(UTF8_NAME))
    end
  end

  def test_unrenamed_entry_written_back_with_original_representation
    write_zip([[build_entry(CP437_NAME, unicode_path: UTF8_NAME), 'data']])

    # Force a commit without touching the entry itself.
    ::Zip::File.open(@zip_path) { |zip| zip.comment = 'force a rewrite' }

    ::Zip::File.open(@zip_path) do |zip|
      entry = zip.entries.first
      assert_equal(CP437_NAME, entry.raw_name)
      assert_equal(0, entry.gp_flags & ::Zip::Entry::EFS)
      refute_nil(entry.extra[:unicodepath])
      assert(entry.extra[:unicodepath].crc_valid_for?(CP437_NAME))
      assert_equal(UTF8_NAME, entry.name)
    end

    ::Zip::InputStream.open(@zip_path) do |io|
      assert_equal(CP437_NAME, io.get_next_entry.raw_name)
    end
  end

  def test_explicit_rename_unifies_flags_and_extra_field
    write_zip([[build_entry(CP437_NAME, unicode_path: UTF8_NAME), 'data']])

    ::Zip::File.open(@zip_path) do |zip|
      zip.rename(UTF8_NAME, 'thé.txt')
    end

    ::Zip::File.open(@zip_path) do |zip|
      entry = zip.entries.first
      assert_equal('thé.txt', entry.name)
      assert_equal('thé.txt'.b, entry.raw_name)
      assert_equal(::Zip::Entry::EFS, entry.gp_flags & ::Zip::Entry::EFS)
      assert_nil(entry.extra[:unicodepath])
    end
  end

  def test_name_setter_forgets_raw_name_and_updates_flags_and_extra_field
    write_zip([[build_entry(CP437_NAME, unicode_path: UTF8_NAME), 'data']])

    ::Zip::File.open(@zip_path) do |zip|
      entry = zip.entries.first
      entry.name = 'new.txt'
      assert_nil(entry.raw_name)
      assert_equal(::Zip::Entry::EFS, entry.gp_flags & ::Zip::Entry::EFS)
      assert_nil(entry.extra[:unicodepath])
      assert(entry.dirty?)
    end
  end

  private

  def build_entry(raw_name, efs: false, unicode_path: nil, corrupt_crc: false)
    entry = ::Zip::Entry.new('test.zip', raw_name)
    entry.gp_flags |= ::Zip::Entry::EFS if efs
    if unicode_path
      crc = Zlib.crc32(raw_name)
      crc ^= 0xFFFFFFFF if corrupt_crc
      payload = [1, crc].pack('CV') + unicode_path.b
      entry.extra.merge('up' + [payload.bytesize].pack('v') + payload)
    end
    entry
  end

  def write_zip(entries_and_contents)
    ::Zip::OutputStream.open(@zip_path) do |zos|
      entries_and_contents.each do |entry, content|
        zos.put_next_entry(entry)
        zos.write(content)
      end
    end
  end
end
