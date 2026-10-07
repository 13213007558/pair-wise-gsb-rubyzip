# frozen_string_literal: true

require_relative 'test_helper'

class ZipDeltaTest < Minitest::Test
  PASSWORD = 'swordfish'

  def test_generates_and_applies_a_delta_with_reused_renamed_replaced_and_deleted_entries
    base_bytes, expected_unknown = build_base_archive
    target_bytes = build_target_archive(base_bytes)
    delta = Zip::Delta.generate(StringIO.new(base_bytes), StringIO.new(target_bytes))

    operations = Zip::Delta.info(delta).fetch(:entries).to_h { |entry| [entry.fetch(:name), entry.fetch(:operation)] }
    assert_equal(
      {
        'stored.txt' => :reuse,
        'deflated.txt' => :reuse,
        'renamed.txt' => :reuse,
        'metadata.txt' => :reuse,
        'replace.txt' => :full,
        'added.txt' => :full,
        'unknown.txt' => :reuse
      },
      operations
    )

    Dir.mktmpdir do |directory|
      output_path = File.join(directory, 'target.zip')
      Zip::Delta.apply(StringIO.new(base_bytes), delta, output_path)

      output_bytes = File.binread(output_path)
      assert_target_contents(output_bytes)
      assert_target_metadata(output_bytes, target_bytes, expected_unknown)
      assert_compressed_segments_were_reused(base_bytes, target_bytes, output_bytes)
    end
  end

  def test_applies_encrypted_data_descriptor_entries_by_reusing_their_bytes
    archive = build_encrypted_archive
    delta = Zip::Delta.generate(StringIO.new(archive.string), StringIO.new(archive.string))

    assert_equal :reuse, Zip::Delta.info(delta).fetch(:entries).first.fetch(:operation)

    Dir.mktmpdir do |directory|
      output_path = File.join(directory, 'encrypted.zip')
      Zip::Delta.apply(StringIO.new(archive.string), delta, output_path)
      output_bytes = File.binread(output_path)

      Zip::InputStream.open(
        StringIO.new(output_bytes),
        decrypter: Zip::TraditionalDecrypter.new(PASSWORD)
      ) do |input|
        entry = input.get_next_entry
        assert_equal 'secret.txt', entry.name
        assert_equal 'secret payload ' * 20, input.read
        assert_nil input.get_next_entry
      end

      base_entry = read_entries(archive.string).first
      output_entry = read_entries(output_bytes).first
      assert_equal raw_segment(archive.string, base_entry), raw_segment(output_bytes, output_entry)
    end
  end

  def test_apply_rejects_an_archive_whose_base_identity_does_not_match
    base_bytes, = build_base_archive
    target_bytes = build_target_archive(base_bytes)
    delta = Zip::Delta.generate(StringIO.new(base_bytes), StringIO.new(target_bytes))

    Dir.mktmpdir do |directory|
      wrong_base = File.join(directory, 'base.zip')
      output_path = File.join(directory, 'target.zip')
      File.binwrite(wrong_base, build_simple_zip('stored.txt', 'different base'))
      File.binwrite(output_path, 'previous output')

      error = assert_raises(Zip::DeltaError) do
        Zip::Delta.apply(wrong_base, delta, output_path)
      end
      assert_equal 'Base archive identity does not match delta', error.message
      assert_equal 'previous output', File.binread(output_path)
    end
  end

  def test_apply_rejects_a_corrupt_delta_without_replacing_the_output
    base_bytes, = build_base_archive
    target_bytes = build_target_archive(base_bytes)
    delta_io = Zip::Delta.generate(StringIO.new(base_bytes), StringIO.new(target_bytes))
    delta_io.string.setbyte(100, delta_io.string.getbyte(100) ^ 0xff)

    Dir.mktmpdir do |directory|
      output_path = File.join(directory, 'target.zip')
      File.binwrite(output_path, 'previous output')

      assert_raises(Zip::DeltaError) do
        Zip::Delta.apply(StringIO.new(base_bytes), delta_io, output_path)
      end
      assert_equal 'previous output', File.binread(output_path)
      refute File.exist?(File.join(directory, 'target.zip.tmp'))
    end
  end

  def test_does_not_reuse_when_only_the_name_matches
    base_bytes, = build_base_archive
    target_bytes = build_target_archive(base_bytes)
    target_entries = read_entries(target_bytes)
    stored = target_entries.find { |entry| entry.name == 'stored.txt' }
    offset = stored.local_header_offset
    target_bytes.setbyte(offset + 8, target_bytes.getbyte(offset + 8) ^ 1)

    assert_raises(Zip::Error) do
      Zip::Delta.generate(StringIO.new(base_bytes), StringIO.new(target_bytes))
    end
  end

  def test_does_not_reuse_when_segment_metadata_changes
    base_bytes, = build_base_archive
    target_bytes = build_target_archive(base_bytes)
    target_entries = read_entries(target_bytes)
    stored = target_entries.find { |entry| entry.name == 'stored.txt' }
    target_bytes.setbyte(
      stored.local_header_offset + 6,
      target_bytes.getbyte(stored.local_header_offset + 6) | 0x01
    )
    central_offset = target_central_offset(target_bytes)
    target_bytes.setbyte(central_offset + 8, target_bytes.getbyte(central_offset + 8) | 0x01)
    delta = Zip::Delta.generate(StringIO.new(base_bytes), StringIO.new(target_bytes))

    assert_equal :full, Zip::Delta.info(delta).fetch(:entries).first.fetch(:operation)
  end

  private

  def target_central_offset(bytes)
    cdir = Zip::CentralDirectory.new
    cdir.read_from_stream(StringIO.new(bytes))
    cdir.instance_variable_get(:@cdir_offset)
  end

  def build_base_archive
    io = StringIO.new
    unknown_local = "\xCA\xFE\x03\x00loc".b
    unknown_central = "\xCA\xFE\x04\x00cdir".b
    unknown_extra = Zip::ExtraField.new
    unknown_extra.merge(unknown_central)
    unknown_extra[:unknown].merge(unknown_local, local: true)

    Zip::OutputStream.write_buffer(io) do |out|
      write_stored(out, 'stored.txt', 'stored unchanged')
      write_deflated(out, 'deflated.txt', 'deflated unchanged ' * 20)
      write_deflated(out, 'rename.txt', 'renamed payload ' * 20)
      write_deflated(out, 'metadata.txt', 'metadata payload ' * 20)
      write_deflated(out, 'delete.txt', 'deleted payload ' * 20)
      write_deflated(out, 'replace.txt', 'old replaced payload ' * 20)

      unknown_content = 'unknown extra field'
      unknown_entry = Zip::Entry.new(
        nil,
        'unknown.txt',
        size: unknown_content.bytesize,
        crc: Zlib.crc32(unknown_content),
        compression_method: Zip::Entry::STORED,
        extra: unknown_extra
      )
      out.put_next_entry(unknown_entry)
      out.write(unknown_content)
    end

    [io.string, { local: unknown_local, central: unknown_central }]
  end

  def build_target_archive(base_bytes)
    base_entries = read_entries(base_bytes).to_h { |entry| [entry.name, entry] }
    io = StringIO.new

    Zip::OutputStream.write_buffer(io) do |out|
      copy_raw(out, base_entries.fetch('stored.txt'))
      copy_raw(out, base_entries.fetch('deflated.txt'))
      copy_raw(out, base_entries.fetch('rename.txt'), name: 'renamed.txt')
      copy_raw(
        out,
        base_entries.fetch('metadata.txt'),
        comment: 'updated comment',
        time: Time.local(2020, 5, 6, 7, 8, 9)
      )

      write_deflated(out, 'replace.txt', 'new replaced payload ' * 20)
      write_deflated(out, 'added.txt', 'added payload ' * 20)
      copy_raw(out, base_entries.fetch('unknown.txt'))
    end

    io.string
  end

  def build_encrypted_archive
    Zip::OutputStream.write_buffer(
      StringIO.new,
      encrypter: Zip::TraditionalEncrypter.new(PASSWORD)
    ) do |out|
      out.put_next_entry('secret.txt')
      out.write('secret payload ' * 20)
    end
  end

  def build_simple_zip(name, content)
    io = StringIO.new
    Zip::OutputStream.write_buffer(io) do |out|
      write_stored(out, name, content)
    end
    io.string
  end

  def write_stored(out, name, content)
    out.put_next_entry(name, '', Zip::ExtraField.new, Zip::Entry::STORED)
    out.write(content)
  end

  def write_deflated(out, name, content)
    out.put_next_entry(name, '', Zip::ExtraField.new, Zip::Entry::DEFLATED)
    out.write(content)
  end

  def copy_raw(out, entry, name: nil, comment: nil, time: nil)
    copied = entry.dup
    copied.name = name if name
    copied.comment = comment if comment
    copied.time = time if time
    out.copy_raw_entry(copied)
  end

  def read_entries(bytes)
    io = StringIO.new(bytes)
    cdir = Zip::CentralDirectory.new
    cdir.read_from_stream(io)
    cdir.entries
  end

  def assert_target_contents(output_bytes)
    Zip::File.open_buffer(output_bytes) do |zip|
      assert_equal %w[
        stored.txt
        deflated.txt
        renamed.txt
        metadata.txt
        replace.txt
        added.txt
        unknown.txt
      ], zip.entries.map(&:name)

      assert_equal 'stored unchanged', zip.read('stored.txt')
      assert_equal 'deflated unchanged ' * 20, zip.read('deflated.txt')
      assert_equal 'renamed payload ' * 20, zip.read('renamed.txt')
      assert_equal 'metadata payload ' * 20, zip.read('metadata.txt')
      assert_equal 'new replaced payload ' * 20, zip.read('replace.txt')
      assert_equal 'added payload ' * 20, zip.read('added.txt')
      assert_equal 'unknown extra field', zip.read('unknown.txt')
      assert_nil zip.find_entry('delete.txt')
    end
  end

  def assert_target_metadata(output_bytes, target_bytes, expected_unknown)
    output_entries = read_entries(output_bytes)
    target_entries = read_entries(target_bytes)

    assert_equal target_entries.map(&:name), output_entries.map(&:name)
    target_entries.zip(output_entries).each do |expected, actual|
      assert_equal metadata_values(expected), metadata_values(actual)
      assert_equal expected.local_header_offset.zero?, actual.local_header_offset.zero?
      assert_equal actual.local_header_offset, local_signature_offset(output_bytes, actual)
    end

    metadata_entry = output_entries.find { |entry| entry.name == 'metadata.txt' }
    assert_equal 'updated comment', metadata_entry.comment
    assert_equal Time.local(2020, 5, 6, 7, 8, 9).to_i, metadata_entry.time.to_i

    unknown_entry = output_entries.find { |entry| entry.name == 'unknown.txt' }
    assert_equal expected_unknown.fetch(:central), unknown_entry.extra[:unknown].to_c_dir_bin
    assert_equal expected_unknown.fetch(:local), unknown_entry.extra[:unknown].to_local_bin
  end

  def metadata_values(entry)
    [
      entry.name,
      entry.comment,
      entry.gp_flags,
      entry.crc,
      entry.compressed_size,
      entry.size,
      entry.compression_method,
      entry.fstype,
      entry.internal_file_attributes,
      entry.external_file_attributes,
      entry.time.to_i
    ]
  end

  def local_signature_offset(bytes, entry)
    read_entries(bytes).find { |candidate| candidate.name == entry.name }.local_header_offset
  end

  def assert_compressed_segments_were_reused(base_bytes, target_bytes, output_bytes)
    base_entries = read_entries(base_bytes)
    target_entries = read_entries(target_bytes)
    output_entries = read_entries(output_bytes)

    reused_sources = {
      'stored.txt' => 'stored.txt',
      'deflated.txt' => 'deflated.txt',
      'renamed.txt' => 'rename.txt',
      'metadata.txt' => 'metadata.txt',
      'unknown.txt' => 'unknown.txt'
    }

    target_entries.zip(output_entries).each do |target, output|
      assert_equal raw_segment(target_bytes, target), raw_segment(output_bytes, output)

      source_name = reused_sources[output.name]
      next unless source_name

      source = base_entries.find { |entry| entry.name == source_name }
      assert_equal raw_segment(base_bytes, source), raw_segment(output_bytes, output)
    end
  end

  def raw_segment(bytes, entry)
    start = entry.local_header_offset + entry.calculate_local_header_size
    descriptor_size = data_descriptor_size(bytes, entry, start)
    bytes.byteslice(start, entry.compressed_size + descriptor_size)
  end

  def data_descriptor_size(bytes, entry, data_start)
    return 0 unless (entry.gp_flags & 0x08).positive?

    descriptor_start = data_start + entry.compressed_size
    signature = bytes.byteslice(descriptor_start, 4)&.unpack1('V')
    signature == Zip::SPLIT_FILE_SIGNATURE ? 16 : 12
  end
end
