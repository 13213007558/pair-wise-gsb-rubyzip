# frozen_string_literal: true

require_relative 'test_helper'

# Tests for the Info-ZIP Unicode Path (0x7075) and Unicode Comment (0x6375)
# extra fields. The main name/comment bytes use a local (legacy) encoding;
# the true unicode value lives in the extra field.
class ZipUnicodeExtraFieldTest < Minitest::Test
  FIXTURE_DIR = File.join(File.dirname(__FILE__), 'data', 'unicode_extra')

  NAME          = '中文文件名.txt'
  GBK_NAME      = NAME.encode('GBK')
  COMMENT       = '渠道升级'
  GBK_COMMENT   = COMMENT.encode('GBK')
  NEW_NAME      = '新名称.txt'
  NEW_COMMENT   = '新评论'

  def fixture(name)
    File.join(FIXTURE_DIR, name)
  end

  # ---------- extra field class level ----------

  def unicode_extra(id, unicode_name, primary, crc_override: nil, version: 1)
    crc = crc_override || Zlib.crc32(primary.b)
    body = [version, crc].pack('CV') + unicode_name.encode('UTF-8').b + "\x00".b
    [id].pack('v') + [body.bytesize].pack('v') + body
  end

  def test_field_ids_registered
    assert_equal([0x7075].pack('v'), Zip::ExtraField::UnicodePath::HEADER_ID)
    assert_equal([0x6375].pack('v'), Zip::ExtraField::UnicodeComment::HEADER_ID)
  end

  def test_valid_version1_field_is_adopted
    bin = unicode_extra(0x7075, NAME, GBK_NAME)
    field = Zip::ExtraField.new(bin)[:unicodepath]
    assert_equal(NAME, field.valid_name(local: false, primary_bytes: GBK_NAME))
  end

  def test_bad_crc_is_rejected
    bin = unicode_extra(0x7075, NAME, GBK_NAME, crc_override: 0xDEADBEEF)
    field = Zip::ExtraField.new(bin)[:unicodepath]
    assert_nil(field.valid_name(local: false, primary_bytes: GBK_NAME))
  end

  def test_unknown_version_is_rejected_but_preserved
    bin = unicode_extra(0x7075, NAME, GBK_NAME, version: 2)
    field = Zip::ExtraField.new(bin)[:unicodepath]
    assert_nil(field.valid_name(local: false, primary_bytes: GBK_NAME))
    assert_equal(bin.b, field.to_c_dir_bin)
  end

  def test_invalid_utf8_is_rejected
    body = [1, Zlib.crc32(GBK_NAME)].pack('CV') + "\xFF\xFE".b + "\x00".b
    bin = [0x7075].pack('v') + [body.bytesize].pack('v') + body
    field = Zip::ExtraField.new(bin)[:unicodepath]
    assert_nil(field.valid_name(local: false, primary_bytes: GBK_NAME))
  end

  def test_local_and_cdir_declarations_are_kept_separate
    local_bin = unicode_extra(0x7075, NAME, GBK_NAME)
    fields = Zip::ExtraField.new(local_bin, local: true)
    assert(fields[:unicodepath].present?(local: true))
    refute(fields[:unicodepath].present?(local: false))
    assert_equal(local_bin.b, fields.to_local_bin)
    assert_equal(+'', fields.to_c_dir_bin)
  end

  def test_round_trip_regenerates_a_version1_record
    field = Zip::ExtraField::UnicodePath.new
    field.cdir_record.build(NAME, GBK_NAME)
    assert_equal(1, field.cdir_record.version)
    assert_equal(Zlib.crc32(GBK_NAME), field.cdir_record.crc)
    parsed = Zip::ExtraField.new(field.to_c_dir_bin)[:unicodepath]
    assert_equal(NAME, parsed.valid_name(local: false, primary_bytes: GBK_NAME))
  end

  # ---------- reading whole archives ----------

  def test_gbk_main_name_is_decoded_from_extra
    Zip::File.open(fixture('gbk-with-unicode-extra.zip')) do |zip|
      entry = zip.entries.first
      assert_equal(NAME, entry.name)
      assert_equal(Encoding::UTF_8, entry.name.encoding)
      assert_equal(COMMENT, entry.comment)
      assert_equal(Encoding::UTF_8, entry.comment.encoding)
    end
  end

  def test_local_header_uses_the_unicode_extra
    Zip::InputStream.open(fixture('gbk-with-unicode-extra.zip')) do |io|
      entry = io.get_next_entry
      assert_equal(NAME, entry.name)
      assert_equal(Encoding::UTF_8, entry.name.encoding)
      assert_equal('hello 中文'.b, io.read.b)
    end
  end

  def test_utf8_efs_name_reads_normally
    Zip::File.open(fixture('utf8-efs.zip')) do |zip|
      entry = zip.entries.first
      assert_equal(NAME, entry.name)
      assert_equal(Encoding::UTF_8, entry.name.encoding)
      assert((entry.gp_flags & Zip::Entry::EFS) != 0)
    end
  end

  def test_corrupt_crc_falls_back_to_main_field_rules
    Zip::File.open(fixture('gbk-bad-crc.zip')) do |zip|
      entry = zip.entries.first
      # The stale extra must not be trusted: the raw GBK bytes remain.
      assert_equal(Encoding::ASCII_8BIT, entry.name.encoding)
      assert_equal(GBK_NAME.b, entry.name.b)
      refute_equal(NAME, entry.name)
    end
  end

  def test_unknown_version_falls_back_to_main_field_rules
    Zip::File.open(fixture('gbk-unknown-version.zip')) do |zip|
      entry = zip.entries.first
      assert_equal(Encoding::ASCII_8BIT, entry.name.encoding)
      assert_equal(GBK_NAME.b, entry.name.b)
    end
  end

  # ---------- writing / rewriting ----------

  def with_copy(name)
    Dir.mktmpdir do |dir|
      path = File.join(dir, name)
      File.binwrite(path, File.binread(fixture(name)))
      yield(path, dir)
    end
  end

  def force_rewrite(zip)
    # Touch a scalar field so the archive is rewritten without altering
    # its semantic content.
    entry = zip.entries.first
    entry.compressed_size = entry.compressed_size
  end

  def test_unchanged_archive_rewrites_byte_identically
    %w[gbk-with-unicode-extra.zip utf8-efs.zip gbk-bad-crc.zip
       gbk-unknown-version.zip].each do |name|
      original = File.binread(fixture(name))
      with_copy(name) do |path, dir|
        out = File.join(dir, 'out.zip')
        io = StringIO.new
        Zip::File.open(path) do |zip|
          force_rewrite(zip)
          zip.write_buffer(io)
        end
        File.binwrite(out, io.string)
        assert_equal(original, io.string,
                     "#{name} should round-trip losslessly")
      end
    end
  end

  def test_unknown_version_bytes_survive_rewrite
    body = [2, Zlib.crc32(GBK_NAME.b)].pack('CV') + NAME.b + "\x00".b
    raw = [0x7075].pack('v') + [body.bytesize].pack('v') + body
    with_copy('gbk-unknown-version.zip') do |path, dir|
      io = StringIO.new
      Zip::File.open(path) do |zip|
        force_rewrite(zip)
        zip.write_buffer(io)
      end
      assert(io.string.include?(raw), 'version 2 record must survive')
    end
  end

  def test_rename_updates_name_crc_and_primary
    with_copy('gbk-with-unicode-extra.zip') do |path, dir|
      io = StringIO.new
      Zip::File.open(path) do |zip|
        zip.rename(NAME, NEW_NAME)
        zip.write_buffer(io)
      end
      out = File.join(dir, 'out.zip')
      File.binwrite(out, io.string)

      Zip::File.open(out) do |zip|
        entry = zip.get_entry(NEW_NAME)
        refute_nil(entry)
        field = entry.extra[:unicodepath].cdir_record
        assert_equal(Zlib.crc32(NEW_NAME.b), field.crc)
        assert_equal(NEW_NAME, field.unicode_name)
        # The EFS bit is not touched; the 0x7075 field carries the encoding.
        assert((entry.gp_flags & Zip::Entry::EFS).zero?)
        assert_equal('hello 中文'.b, entry.get_input_stream.read.b)
      end
    end
  end

  def test_rename_to_ascii_keeps_crc_valid_without_efs
    with_copy('gbk-with-unicode-extra.zip') do |path, dir|
      io = StringIO.new
      Zip::File.open(path) do |zip|
        zip.rename(NAME, 'ascii.txt')
        zip.write_buffer(io)
      end
      out = File.join(dir, 'out.zip')
      File.binwrite(out, io.string)

      Zip::File.open(out) do |zip|
        entry = zip.get_entry('ascii.txt')
        assert((entry.gp_flags & Zip::Entry::EFS).zero?)
        field = entry.extra[:unicodepath].cdir_record
        assert_equal(Zlib.crc32('ascii.txt'), field.crc)
      end
    end
  end

  def test_comment_change_updates_unicode_comment
    with_copy('gbk-with-unicode-extra.zip') do |path, dir|
      io = StringIO.new
      Zip::File.open(path) do |zip|
        zip.entries.first.comment = NEW_COMMENT
        zip.write_buffer(io)
      end
      out = File.join(dir, 'out.zip')
      File.binwrite(out, io.string)

      Zip::File.open(out) do |zip|
        entry = zip.entries.first
        assert_equal(NEW_COMMENT, entry.comment)
        field = entry.extra[:unicodecomment].cdir_record
        assert_equal(Zlib.crc32(NEW_COMMENT.b), field.crc)
        assert_equal(NEW_COMMENT, field.unicode_name)
        # The untouched name extra must remain valid against the GBK name.
        name_field = entry.extra[:unicodepath].cdir_record
        assert_equal(Zlib.crc32(GBK_NAME), name_field.crc)
      end
    end
  end

  def test_corrupt_crc_copy_is_rewritten_but_still_falls_back
    # An untouched corrupt copy stays byte identical ...
    original = File.binread(fixture('gbk-bad-crc.zip'))
    with_copy('gbk-bad-crc.zip') do |path, dir|
      io = StringIO.new
      Zip::File.open(path) do |zip|
        force_rewrite(zip)
        zip.write_buffer(io)
      end
      assert_equal(original, io.string)

      # ... and when re-read it still follows the main-field rules.
      out = File.join(dir, 'out.zip')
      File.binwrite(out, io.string)
      Zip::File.open(out) do |zip|
        entry = zip.entries.first
        assert_equal(GBK_NAME.b, entry.name.b)
        assert_equal(Encoding::ASCII_8BIT, entry.name.encoding)
      end
    end
  end
end
