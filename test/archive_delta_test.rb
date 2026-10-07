# frozen_string_literal: true

require_relative 'test_helper'
require 'digest'
require 'fileutils'
require 'zlib'

class ArchiveDeltaTest < Minitest::Test
  LOCAL_SIG  = 0x04034b50
  CDIR_SIG   = 0x02014b50
  EOCD_SIG   = 0x06054b50
  DD_SIG     = 0x08074b50
  DD_BIT     = 0b1000
  UNKNOWN_EXTRA_ID = "\x42\x42".b

  RawZipEntry = Struct.new(:name, :payload, :crc, :uncompressed_size, :method,
                           :gp_flags, :dos_time, :dos_date, :extra, keyword_init: true)

  def setup
    @work_dir = "test/data/generated/delta_#{object_id}"
    FileUtils.mkdir_p(@work_dir)
  end

  def teardown
    FileUtils.rm_rf(@work_dir)
    ::Zip.reset!
  end

  def path(name)
    File.join(@work_dir, name)
  end

  def write_rubyzip(file_name, specs)
    ::Zip::File.open(path(file_name), create: true) do |zip|
      specs.each do |name, content, method|
        if name.end_with?('/')
          zip.mkdir(name.delete_suffix('/'))
        else
          zip.get_output_stream(name, compression_method: method || ::Zip::Entry::DEFLATED) do |out|
            out.write(content)
          end
        end
      end
    end
  end

  # Build a minimal zip from explicit local records. This lets the tests
  # exercise data descriptors and arbitrary extra fields precisely.
  def write_raw_zip(file_name, entries, comment: '')
    local_offsets = []
    body = +''.b
    central = +''.b
    entries.each do |entry|
      local_offsets << body.bytesize
      body << [
        LOCAL_SIG, 20, 0, entry.gp_flags, entry.method,
        entry.dos_time, entry.dos_date,
        (entry.gp_flags & DD_BIT).zero? ? entry.crc : 0,
        (entry.gp_flags & DD_BIT).zero? ? entry.payload.bytesize : 0,
        (entry.gp_flags & DD_BIT).zero? ? entry.uncompressed_size : 0,
        entry.name.bytesize, entry.extra.bytesize
      ].pack('VCCvvvvVVVvv')
      body << entry.name
      body << entry.extra
      body << entry.payload
      if (entry.gp_flags & DD_BIT) != 0
        body << [DD_SIG, entry.crc, entry.payload.bytesize, entry.uncompressed_size].pack('VVVV')
      end
    end

    cdir_offset = body.bytesize
    entries.each_with_index do |entry, index|
      central << [
        CDIR_SIG, 0x0328, 3, 20, entry.gp_flags, entry.method,
        entry.dos_time, entry.dos_date, entry.crc, entry.payload.bytesize,
        entry.uncompressed_size, entry.name.bytesize, entry.extra.bytesize,
        0, 0, 0, 0, local_offsets[index]
      ].pack('VCCvvvvvVVVvvvvvVV')
      central << entry.name
      central << entry.extra
    end

    cdir_size = central.bytesize
    body << central
    body << [EOCD_SIG, 0, 0, entries.size, entries.size,
             cdir_size, cdir_offset, comment.bytesize].pack('VvvvvVVv')
    body << comment
    File.binwrite(path(file_name), body)
  end

  def stored(name, content, gp_flags: 0, extra: +''.b, time: 0x6800, date: 0x554a)
    RawZipEntry.new(
      name: name.b, payload: content.b, crc: Zlib.crc32(content),
      uncompressed_size: content.bytesize, method: ::Zip::COMPRESSION_METHOD_STORE,
      gp_flags: gp_flags, dos_time: time, dos_date: date, extra: extra
    )
  end

  def read_entries(file_name)
    entries = {}
    ::Zip::File.open(path(file_name)) do |zip|
      zip.each do |entry|
        entries[entry.name] = {
          content: zip.read(entry),
          size: entry.size,
          compressed_size: entry.compressed_size,
          crc: entry.crc,
          gp_flags: entry.gp_flags,
          method: entry.compression_method
        }
      end
    end
    entries
  end

  def raw_payloads(file_name)
    generator = ::Zip::ArchiveDelta.new
    archive = generator.send(:parse_archive, File.binread(path(file_name)))
    archive.entries.to_h do |entry|
      [entry.local.name, archive.raw.byteslice(entry.payload_offset, entry.local.compressed_size)]
    end
  end

  def assert_target_matches(target_name, output_name)
    expected = read_entries(target_name)
    actual = read_entries(output_name)
    assert_equal expected.keys, actual.keys
    expected.each do |name, metadata|
      assert_equal metadata, actual[name], "metadata mismatch for #{name}"
    end
  end

  def test_generate_and_apply_with_reuse_rename_replace_add_delete
    write_rubyzip('base.zip', [
      ['keep.txt', 'same ' * 20, nil],
      ['rename_me.txt', 'renamed body ' * 5, ::Zip::Entry::STORED],
      ['change.txt', 'old body ' * 6, nil],
      ['gone.txt', 'delete me ' * 3, nil]
    ])
    write_rubyzip('target.zip', [
      ['keep.txt', 'same ' * 20, nil],
      ['renamed.txt', 'renamed body ' * 5, ::Zip::Entry::STORED],
      ['change.txt', 'new body ' * 9, nil],
      ['added.txt', 'brand new ' * 4, nil]
    ])

    delta = ::Zip::ArchiveDelta.generate(path('base.zip'), path('target.zip'))

    # The two unchanged/reused payloads must not be embedded in the delta.
    base_payloads = raw_payloads('base.zip')
    refute_includes delta, base_payloads['keep.txt']
    refute_includes delta, base_payloads['rename_me.txt']
    # But the genuinely changed/new payloads are embedded.
    target_payloads = raw_payloads('target.zip')
    assert_includes delta, target_payloads['change.txt']
    assert_includes delta, target_payloads['added.txt']

    ::Zip::ArchiveDelta.apply(path('base.zip'), delta, path('out.zip'))
    assert_target_matches('target.zip', 'out.zip')

    # The compressed bytes of the unchanged entry are literally reused.
    out_payloads = raw_payloads('out.zip')
    assert_equal base_payloads['keep.txt'], out_payloads['keep.txt']
    assert_equal base_payloads['rename_me.txt'], out_payloads['renamed.txt']
  end

  def test_generate_to_file_and_apply_from_file
    write_rubyzip('base.zip', [['a.txt', 'alpha ' * 3, nil]])
    write_rubyzip('target.zip', [['a.txt', 'alpha ' * 3, nil], ['b.txt', 'beta', nil]])

    returned = ::Zip::ArchiveDelta.generate(path('base.zip'), path('target.zip'),
                                            delta_path: path('delta.bin'))
    assert_equal path('delta.bin'), returned
    assert File.size(path('delta.bin')).positive?

    ::Zip::ArchiveDelta.apply(path('base.zip'), path('delta.bin'), path('out.zip'))
    assert_target_matches('target.zip', 'out.zip')
  end

  def test_apply_accepts_delta_io
    write_rubyzip('base.zip', [['a.txt', 'alpha ' * 3, nil]])
    write_rubyzip('target.zip', [['a.txt', 'alpha ' * 3, nil], ['b.txt', 'beta', nil]])
    delta = ::Zip::ArchiveDelta.generate(path('base.zip'), path('target.zip'))

    ::Zip::ArchiveDelta.apply(path('base.zip'), StringIO.new(delta), path('out.zip'))
    assert_target_matches('target.zip', 'out.zip')
  end

  def test_unknown_extra_fields_are_preserved
    known_gap = stored('a.txt', 'alpha')
    extra = UNKNOWN_EXTRA_ID + [3].pack('v') + 'abc'.b
    with_extra = stored('b.txt', 'bravo', extra: extra)
    write_raw_zip('base.zip', [known_gap])
    write_raw_zip('target.zip', [known_gap, with_extra])

    delta = ::Zip::ArchiveDelta.generate(path('base.zip'), path('target.zip'))
    ::Zip::ArchiveDelta.apply(path('base.zip'), delta, path('out.zip'))
    assert_target_matches('target.zip', 'out.zip')

    archive = ::Zip::ArchiveDelta.new.send(:parse_archive, File.binread(path('out.zip')))
    entry = archive.entries.find { |e| e.local.name == 'b.txt' }
    assert_includes entry.local.extra, extra
    assert_includes entry.cdir.extra, extra
  end

  def test_data_descriptor_is_part_of_segment_boundary
    entry_a = stored('a.txt', 'aaaa', gp_flags: DD_BIT)
    entry_b = stored('b.txt', 'bbbb', gp_flags: DD_BIT)
    write_raw_zip('base.zip', [entry_a, entry_b])
    # Same payloads, same DD flag: both segments can be reused.
    renamed_b = stored('renamed.txt', 'bbbb', gp_flags: DD_BIT)
    write_raw_zip('target.zip', [entry_a, renamed_b])

    delta = ::Zip::ArchiveDelta.generate(path('base.zip'), path('target.zip'))
    ::Zip::ArchiveDelta.apply(path('base.zip'), delta, path('out.zip'))
    assert_target_matches('target.zip', 'out.zip')

    base_payloads = raw_payloads('base.zip')
    out_payloads = raw_payloads('out.zip')
    assert_equal base_payloads['a.txt'], out_payloads['a.txt']
    assert_equal base_payloads['b.txt'], out_payloads['renamed.txt']
  end

  def test_dd_flag_difference_forces_no_reuse
    with_dd = stored('a.txt', 'aaaa', gp_flags: DD_BIT)
    without_dd = stored('a.txt', 'aaaa', gp_flags: 0)
    write_raw_zip('base.zip', [with_dd])
    write_raw_zip('target.zip', [without_dd])

    delta = ::Zip::ArchiveDelta.generate(path('base.zip'), path('target.zip'))
    # The payload must be embedded because the DD flag differs.
    target_payloads = raw_payloads('target.zip')
    assert_includes delta, target_payloads['a.txt']
    ::Zip::ArchiveDelta.apply(path('base.zip'), delta, path('out.zip'))
    assert_target_matches('target.zip', 'out.zip')
  end

  def test_wrong_base_is_rejected_and_leaves_no_output
    write_rubyzip('base.zip', [['a.txt', 'base a', nil]])
    write_rubyzip('other.zip', [['a.txt', 'other a is longer ' * 5, nil]])
    write_rubyzip('target.zip', [['a.txt', 'target a', nil]])
    delta = ::Zip::ArchiveDelta.generate(path('base.zip'), path('target.zip'))

    assert_raises(::Zip::DeltaError) do
      ::Zip::ArchiveDelta.apply(path('other.zip'), delta, path('out.zip'))
    end
    refute File.exist?(path('out.zip'))
  end

  def test_corrupt_delta_is_rejected
    write_rubyzip('base.zip', [['a.txt', 'base a', nil]])
    write_rubyzip('target.zip', [['a.txt', 'target a', nil]])
    delta = ::Zip::ArchiveDelta.generate(path('base.zip'), path('target.zip')).dup
    corrupt = delta.dup
    corrupt.setbyte(-20, corrupt.getbyte(-20) ^ 0xff)

    assert_raises(::Zip::DeltaError) do
      ::Zip::ArchiveDelta.apply(path('base.zip'), corrupt, path('out.zip'))
    end
    refute File.exist?(path('out.zip'))
  end

  def test_existing_output_is_not_overwritten_by_default
    write_rubyzip('base.zip', [['a.txt', 'base a', nil]])
    write_rubyzip('target.zip', [['a.txt', 'target a', nil]])
    delta = ::Zip::ArchiveDelta.generate(path('base.zip'), path('target.zip'))
    File.binwrite(path('out.zip'), 'sentinel')

    assert_raises(::Zip::DeltaError) do
      ::Zip::ArchiveDelta.apply(path('base.zip'), delta, path('out.zip'))
    end
    assert_equal 'sentinel', File.binread(path('out.zip'))
  end

  def test_tampered_base_segment_fails_validation
    write_rubyzip('base.zip', [['a.txt', 'same content ' * 10, nil]])
    write_rubyzip('target.zip', [['a.txt', 'same content ' * 10, nil]])
    delta = ::Zip::ArchiveDelta.generate(path('base.zip'), path('target.zip'))

    FileUtils.cp(path('base.zip'), path('tampered.zip'))
    tampered = File.binread(path('tampered.zip'))
    # Flip a bit in the compressed payload region.
    tampered.setbyte(60, tampered.getbyte(60) ^ 0x01)
    File.binwrite(path('tampered.zip'), tampered)

    assert_raises(::Zip::DeltaError) do
      ::Zip::ArchiveDelta.apply(path('tampered.zip'), delta, path('out.zip'))
    end
    refute File.exist?(path('out.zip'))
  end

  def test_encrypted_segment_with_data_descriptor_is_reused
    password = 'swordfish'
    content = 'encrypted payload ' * 4
    encrypted_buffer = ::Zip::OutputStream.write_buffer(
      StringIO.new,
      encrypter: ::Zip::TraditionalEncrypter.new(password)
    ) do |out|
      out.put_next_entry('enc.txt')
      out.write(content)
    end
    encrypted_zip = encrypted_buffer.string

    # Build base and target archives that both embed the exact encrypted
    # local record (header + ciphertext + data descriptor) verbatim.
    generator = ::Zip::ArchiveDelta.new
    parsed = generator.send(:parse_archive, encrypted_zip)
    entry = parsed.entries.first
    record = parsed.raw.byteslice(entry.local.offset, entry.segment_length)
    cdir_record = entry.cdir.raw

    write_assembled = lambda do |file_name, name|
      header = record.byteslice(0, 30 + entry.local.name.bytesize + entry.local.extra.bytesize)
      tail = record.byteslice(header.bytesize, record.bytesize - header.bytesize)
      renamed_header = header.byteslice(0, 26) + [name.bytesize].pack('v') +
                       header.byteslice(28, 2) + name.b + entry.local.extra
      central_values = cdir_record.unpack('VCCvvvvvVVVvvvvvVV')
      central_values[11] = name.bytesize
      central_values[17] = 0
      central_tail = cdir_record.byteslice(46 + entry.local.name.bytesize,
                                           cdir_record.bytesize - 46 - entry.local.name.bytesize)
      central_static = central_values.pack('VCCvvvvvVVVvvvvvVV') + name.b + central_tail
      blob = renamed_header + tail
      cdir_offset = blob.bytesize
      zip = blob + central_static +
            [EOCD_SIG, 0, 0, 1, 1, central_static.bytesize, cdir_offset, 0].pack('VvvvvVVv')
      File.binwrite(path(file_name), zip)
    end

    write_assembled.call('base.zip', 'enc.txt')
    write_assembled.call('target.zip', 'enc_same.txt')

    # First, identical archives (same name) must share the whole segment.
    File.binwrite(path('identical_base.zip'), encrypted_zip)
    File.binwrite(path('identical_target.zip'), encrypted_zip)
    identical_delta = ::Zip::ArchiveDelta.generate(path('identical_base.zip'),
                                                    path('identical_target.zip'))
    refute_includes identical_delta, parsed.raw.byteslice(entry.payload_offset,
                                                          entry.local.compressed_size)
    ::Zip::ArchiveDelta.apply(path('identical_base.zip'), identical_delta,
                              path('identical_out.zip'))

    delta = ::Zip::ArchiveDelta.generate(path('base.zip'), path('target.zip'))
    refute_includes delta, parsed.raw.byteslice(entry.payload_offset, entry.local.compressed_size)

    ::Zip::ArchiveDelta.apply(path('base.zip'), delta, path('out.zip'))

    ::Zip::InputStream.open(path('out.zip'),
                           decrypter: ::Zip::TraditionalDecrypter.new(password)) do |zis|
      result = zis.get_next_entry
      assert_equal 'enc_same.txt', result.name
      assert_equal content, zis.read
    end
  end
end
