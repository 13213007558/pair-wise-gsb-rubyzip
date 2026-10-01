# frozen_string_literal: true

require_relative 'test_helper'
require 'zlib'
require 'stringio'

# Builds minimal single-entry, STORED-compressed zip archives with explicit
# primary name/comment bytes, EFS flags and extra fields, so that legacy
# encoded (non-UTF-8) entries can be exercised.
module UnicodeZipBuilder
  module_function

  def unicode_field(id, primary_bytes, utf8_bytes, version: 1, crc: Zlib.crc32(primary_bytes))
    body = [version, crc].pack('CV') + utf8_bytes
    id + [body.bytesize].pack('v') + body
  end

  def build(name:, extra_local: +'', extra_cdir: extra_local, gp_flags: 0,
            comment: +'', data: +'content')
    crc = Zlib.crc32(data)
    dos_time = 0
    dos_date = 0x21

    local_header =
      [0x04034B50, 20, gp_flags, 0, dos_time, dos_date, crc,
       data.bytesize, data.bytesize, name.bytesize, extra_local.bytesize]
      .pack('VvvvvvVVVvv') + name + extra_local

    cdir_offset = local_header.bytesize
    cdir_entry =
      [0x02014B50, 20, 0, 20, gp_flags, 0, dos_time, dos_date, crc,
       data.bytesize, data.bytesize, name.bytesize, extra_cdir.bytesize,
       comment.bytesize, 0, 0, 0, cdir_offset]
      .pack('VCCvvvvvVVVvvvvvVV') + name + extra_cdir + comment

    cdir_start = cdir_offset + data.bytesize
    eocd =
      [0x06054B50, 0, 0, 1, 1, cdir_entry.bytesize, cdir_start, 0].pack('VvvvvVVv')

    local_header + data + cdir_entry + eocd
  end
end

class ZipExtraFieldUnicodeTest < Minitest::Test
  NAME_UTF8 = '中文文件.txt'
  # The same name encoded with GBK (the kind of legacy local encoding these
  # archives used before UTF-8/EFS). Kept as raw bytes so the tests do not
  # depend on the host Ruby build providing a GBK transcoder.
  NAME_GBK = "\xD6\xD0\xCE\xC4\xCE\xC4\xBC\xFE.txt".b
  COMMENT_UTF8 = '批注'
  COMMENT_GBK = "\xC5\xFA\xD7\xA2".b

  # Rewrite +zip+ into a fresh buffer, always serializing (even when the
  # source archive is considered untouched).
  def rewrite_zip(zip)
    out = StringIO.new
    ::Zip::File.open_buffer(StringIO.new(zip)) do |zf|
      yield zf if block_given?
      ::Zip::OutputStream.write_buffer(out) do |zos|
        zf.each { |entry| entry.write_to_zip_output_stream(zos) }
        zos.comment = zf.comment
      end
    end
    out.string.b
  end

  def path_field(primary, utf8 = NAME_UTF8, **kwargs)
    UnicodeZipBuilder.unicode_field('up', primary, utf8.b, **kwargs)
  end

  def comment_field(primary, utf8, **kwargs)
    UnicodeZipBuilder.unicode_field('uc', primary, utf8.b, **kwargs)
  end

  # --- Extra field object: trust rules -------------------------------------

  def test_unicode_path_and_comment_are_registered
    assert_equal(::Zip::ExtraField::UnicodePath,
                 ::Zip::ExtraField::ID_MAP['up'])
    assert_equal(::Zip::ExtraField::UnicodeComment,
                 ::Zip::ExtraField::ID_MAP['uc'])
  end

  def test_extra_field_plumbing_checks_crc_against_the_primary_name
    record = path_field(NAME_GBK.b)

    good = ::Zip::ExtraField.new(record, local: true, name: NAME_GBK.b)
    assert_equal(NAME_UTF8, good[:unicodepath].unicode_value(local: true))

    bad = ::Zip::ExtraField.new(
      record, local: true, name: 'something-else'.b
    )
    assert_nil(bad[:unicodepath].unicode_value(local: true))
  end

  def test_extra_field_plumbing_passes_comment_bytes
    record = comment_field(COMMENT_GBK, COMMENT_UTF8)

    extra = ::Zip::ExtraField.new(record, comment: COMMENT_GBK)
    assert_equal(COMMENT_UTF8,
                 extra[:unicodecomment].unicode_value(local: false))
  end

  def test_accepts_version_one_with_matching_crc
    field = ::Zip::ExtraField::UnicodePath.new(
      path_field(NAME_GBK.b), local: true, primary_bytes: NAME_GBK.b
    )
    assert_equal(NAME_UTF8, field.unicode_value(local: true))
  end

  def test_rejects_unknown_version_but_keeps_raw
    raw = path_field(NAME_GBK.b, version: 42)
    field = ::Zip::ExtraField::UnicodePath.new(
      raw, local: true, primary_bytes: NAME_GBK.b
    )
    assert_nil(field.unicode_value(local: true))
    assert_equal(raw.b, field.to_local_bin)
  end

  def test_rejects_stale_crc_but_keeps_raw
    raw = path_field(NAME_GBK.b, crc: Zlib.crc32(NAME_GBK.b) ^ 0xFFFF)
    field = ::Zip::ExtraField::UnicodePath.new(
      raw, local: true, primary_bytes: NAME_GBK.b
    )
    assert_nil(field.unicode_value(local: true))
    assert_equal(raw.b, field.to_local_bin)
  end

  def test_rejects_invalid_utf8_but_keeps_raw
    raw = path_field(NAME_GBK.b, "\xff\xfebad".b)
    field = ::Zip::ExtraField::UnicodePath.new(
      raw, local: true, primary_bytes: NAME_GBK.b
    )
    assert_nil(field.unicode_value(local: true))
    assert_equal(raw.b, field.to_local_bin)
  end

  def test_regenerates_with_fresh_crc_after_the_value_changes
    field = ::Zip::ExtraField::UnicodePath.new(
      path_field(NAME_GBK.b), local: true, primary_bytes: NAME_GBK.b
    )
    new_name = 'renamed.txt'
    field.prepare_for_write(new_name.b, local: true, modified: true)
    written = field.to_local_bin
    reparsed = ::Zip::ExtraField::UnicodePath.new(
      written, local: true, primary_bytes: new_name.b
    )
    assert_equal(new_name, reparsed.unicode_value(local: true))
  end

  # --- Reading archives -----------------------------------------------------

  def test_reads_unicode_name_from_legacy_encoded_zip
    zip = UnicodeZipBuilder.build(
      name: NAME_GBK.b,
      extra_local: path_field(NAME_GBK.b),
      extra_cdir: path_field(NAME_GBK.b)
    )
    ::Zip::File.open_buffer(StringIO.new(zip)) do |zf|
      entry = zf.entries.first
      assert_equal(NAME_UTF8, entry.name)
      assert_equal(Encoding::UTF_8, entry.name.encoding)
    end

    # Streaming reads go through the local header only.
    ::Zip::InputStream.open(StringIO.new(zip)) do |is|
      assert_equal(NAME_UTF8, is.get_next_entry.name)
    end
  end

  def test_corrupt_crc_falls_back_to_primary_field_rules
    bad_extra = path_field(NAME_GBK.b, crc: Zlib.crc32(NAME_GBK.b) ^ 0xFFFF)
    zip = UnicodeZipBuilder.build(
      name: NAME_GBK.b,
      extra_local: bad_extra,
      extra_cdir: bad_extra
    )

    # EFS is clear, so without a trusted record the primary bytes are not
    # interpreted as UTF-8.
    ::Zip::File.open_buffer(StringIO.new(zip)) do |zf|
      entry = zf.entries.first
      assert_equal(Encoding::ASCII_8BIT, entry.name.encoding)
      assert_equal(NAME_GBK.b, entry.name)
      refute_equal(NAME_UTF8, entry.name)
    end
  end

  def test_corrupt_crc_with_efs_still_honours_the_efs_flag
    bad_extra = path_field(NAME_GBK.b, crc: Zlib.crc32(NAME_GBK.b) ^ 0xFFFF)
    zip = UnicodeZipBuilder.build(
      name: NAME_GBK.b,
      extra_local: bad_extra,
      extra_cdir: bad_extra,
      gp_flags: ::Zip::Entry::EFS
    )

    ::Zip::File.open_buffer(StringIO.new(zip)) do |zf|
      entry = zf.entries.first
      # The corrupt Unicode field is ignored; EFS declares the primary
      # bytes to be UTF-8, but here they are GBK and therefore invalid.
      assert_equal(NAME_GBK.b, entry.name)
    end
  end

  def test_efs_flag_marks_valid_utf8_primary_name
    zip = UnicodeZipBuilder.build(
      name: NAME_UTF8.b, gp_flags: ::Zip::Entry::EFS
    )
    ::Zip::File.open_buffer(StringIO.new(zip)) do |zf|
      entry = zf.entries.first
      assert_equal(NAME_UTF8, entry.name)
      assert_equal(Encoding::UTF_8, entry.name.encoding)
    end
  end

  def test_local_and_cdir_declarations_are_checked_separately
    good = path_field(NAME_GBK.b)
    bad = path_field(NAME_GBK.b, crc: Zlib.crc32(NAME_GBK.b) ^ 0xFFFF)

    # Only the local header carries a trusted record.
    zip = UnicodeZipBuilder.build(
      name: NAME_GBK.b, extra_local: good, extra_cdir: bad
    )
    ::Zip::InputStream.open(StringIO.new(zip)) do |is|
      assert_equal(NAME_UTF8, is.get_next_entry.name)
    end
    ::Zip::File.open_buffer(StringIO.new(zip)) do |zf|
      # Central directory declaration is corrupt, so fall back to primary.
      assert_equal(NAME_GBK.b, zf.entries.first.name)
    end
  end

  def test_unicode_comment_is_read_and_not_emitted_in_local_header
    cdir_extra = comment_field(COMMENT_GBK, COMMENT_UTF8)
    zip = UnicodeZipBuilder.build(
      name: NAME_GBK.b,
      extra_local: path_field(NAME_GBK.b),
      extra_cdir: path_field(NAME_GBK.b) + cdir_extra,
      comment: COMMENT_GBK
    )

    ::Zip::File.open_buffer(StringIO.new(zip)) do |zf|
      entry = zf.entries.first
      assert_equal('批注', entry.comment)
      assert_equal(Encoding::UTF_8, entry.comment.encoding)
    end

    # A stray Unicode Comment in a local header is not permitted by the
    # specification; it must be ignored (kept only as unknown raw data).
    local_only = UnicodeZipBuilder.build(
      name: NAME_GBK.b,
      extra_local: path_field(NAME_GBK.b) + cdir_extra,
      extra_cdir: path_field(NAME_GBK.b),
      comment: COMMENT_GBK
    )
    ::Zip::InputStream.open(StringIO.new(local_only)) do |is|
      entry = is.get_next_entry
      refute(entry.extra.member?(:unicodecomment))
    end
  end

  # --- Writing / rewriting archives ----------------------------------------

  def test_legacy_zip_is_rewritten_losslessly
    field = path_field(NAME_GBK.b)
    zip = UnicodeZipBuilder.build(
      name: NAME_GBK.b, extra_local: field, extra_cdir: field
    )

    rewritten = rewrite_zip(zip)

    assert_includes(rewritten, field)
    ::Zip::File.open_buffer(StringIO.new(rewritten)) do |zf|
      assert_equal(NAME_UTF8, zf.entries.first.name)
    end
  end

  def test_rename_updates_primary_bytes_crc_and_unicode_value
    field = path_field(NAME_GBK.b)
    zip = UnicodeZipBuilder.build(
      name: NAME_GBK.b, extra_local: field, extra_cdir: field
    )

    rewritten = rewrite_zip(zip) do |zf|
      zf.rename(NAME_UTF8, 'new_name.txt')
    end

    refute_includes(rewritten, NAME_GBK.b)
    entry = nil
    ::Zip::File.open_buffer(StringIO.new(rewritten)) do |zf|
      entry = zf.entries.first
      assert_equal('new_name.txt', entry.name)
    end

    up = entry.extra[:unicodepath]
    assert_equal('new_name.txt', up.unicode_value(local: false))
  end

  def test_unknown_version_record_is_rewritten_losslessly
    field = path_field(NAME_GBK.b, version: 42)
    zip = UnicodeZipBuilder.build(
      name: NAME_GBK.b, extra_local: field, extra_cdir: field
    )

    rewritten = rewrite_zip(zip) do |zf|
      # Unknown version: primary name is used, but the raw field survives.
      assert_equal(NAME_GBK.b, zf.entries.first.name)
    end

    assert_includes(rewritten, field)
  end

  def test_corrupt_crc_record_is_rewritten_losslessly
    field = path_field(NAME_GBK.b, crc: Zlib.crc32(NAME_GBK.b) ^ 0xFFFF)
    zip = UnicodeZipBuilder.build(
      name: NAME_GBK.b, extra_local: field, extra_cdir: field
    )

    rewritten = rewrite_zip(zip) do |zf|
      assert_equal(NAME_GBK.b, zf.entries.first.name)
    end

    assert_includes(rewritten, field)
  end

  def test_cdir_only_declaration_is_echoed_into_local_header
    field = path_field(NAME_GBK.b)
    # Only the central directory carries the Unicode Path field.
    zip = UnicodeZipBuilder.build(
      name: NAME_GBK.b, extra_local: +'', extra_cdir: field
    )

    rewritten = rewrite_zip(zip) do |zf|
      assert_equal(NAME_UTF8, zf.entries.first.name)
    end

    ::Zip::InputStream.open(StringIO.new(rewritten)) do |is|
      assert_equal(NAME_UTF8, is.get_next_entry.name)
    end
  end

  def test_comment_change_regenerates_unicode_comment
    field = comment_field(COMMENT_GBK, COMMENT_UTF8)
    zip = UnicodeZipBuilder.build(
      name: NAME_GBK.b,
      extra_local: path_field(NAME_GBK.b),
      extra_cdir: path_field(NAME_GBK.b) + field,
      comment: COMMENT_GBK
    )

    rewritten = rewrite_zip(zip) do |zf|
      zf.entries.first.comment = 'new comment'
    end

    ::Zip::File.open_buffer(StringIO.new(rewritten)) do |zf|
      entry = zf.entries.first
      assert_equal('new comment', entry.comment)
      assert_equal('new comment',
                   entry.extra[:unicodecomment].unicode_value(local: false))
    end
  end

  def test_writing_a_unicode_path_field_from_scratch
    io = ::Zip::OutputStream.write_buffer do |zos|
      entry = ::Zip::Entry.new(nil, NAME_UTF8)
      entry.extra.create(:unicodepath)
      zos.put_next_entry(entry)
      zos.write('hello')
    end

    ::Zip::InputStream.open(io) do |is|
      assert_equal(NAME_UTF8, is.get_next_entry.name)
    end
  end

  def test_force_entry_names_encoding_overrides_corrupt_record
    bad_extra = path_field(NAME_GBK.b, crc: Zlib.crc32(NAME_GBK.b) ^ 0xFFFF)
    zip = UnicodeZipBuilder.build(
      name: NAME_GBK.b, extra_local: bad_extra, extra_cdir: bad_extra
    )

    ::Zip.force_entry_names_encoding = 'GBK'
    ::Zip::File.open_buffer(StringIO.new(zip)) do |zf|
      # The corrupt Unicode record is ignored; the user-declared encoding
      # tags the primary bytes instead of them staying BINARY.
      name = zf.entries.first.name
      assert_equal('GBK', name.encoding.name)
      assert_equal(NAME_GBK, name.b)
    end
  ensure
    ::Zip.reset!
  end
end
