# frozen_string_literal: true

require_relative 'test_helper'
require 'tmpdir'
require 'digest'

class ZipRecoveryTest < Minitest::Test
  DESCRIPTOR_SIGNATURE = [::Zip::Recovery::DATA_DESCRIPTOR_SIGNATURE].pack('V')

  def teardown
    ::Zip.reset!
  end

  # Builds a zip with the given [[name, content, method], ...] entries and
  # then cuts off everything from the central directory onwards, simulating
  # an upload that lost the central directory.
  def build_broken_zip(dir, entries, trailer: ''.b)
    path = File.join(dir, 'broken.zip')
    ::Zip::OutputStream.open(path) do |zos|
      entries.each do |name, content, method|
        zos.put_next_entry(name, '', nil, method)
        zos << content
      end
    end
    data = File.binread(path)
    eocd_offset = data.rindex([::Zip::CentralDirectory::END_OF_CD_SIG].pack('V'))
    cd_offset = data.byteslice(eocd_offset + 16, 4).unpack1('V')
    File.binwrite(path, data.byteslice(0, cd_offset) + trailer)
    path
  end

  def deflate_raw(content)
    deflater = Zlib::Deflate.new(Zlib::DEFAULT_COMPRESSION, -Zlib::MAX_WBITS)
    compressed = deflater.deflate(content, Zlib::FINISH)
    deflater.close
    compressed
  end

  def local_header(name, gp_flags: 0, method: ::Zip::Entry::DEFLATED,
                   crc: 0, csize: 0, size: 0)
    [::Zip::LOCAL_ENTRY_SIGNATURE, 20, gp_flags, method, 0, 0,
     crc, csize, size, name.bytesize, 0].pack('VvvvvvVVVvv') + name
  end

  def test_scans_deflated_and_stored_entries
    Dir.mktmpdir do |dir|
      path = build_broken_zip(dir, [
                                ['deflated.txt', 'deflated content' * 100, ::Zip::Entry::DEFLATED],
                                ['stored.txt', 'stored content', ::Zip::Entry::STORED]
                              ])
      report = ::Zip::Recovery.scan(path)

      assert_equal(2, report.entries.size)
      assert(report.entries.all?(&:recoverable?))
      assert_equal(%w[deflated.txt stored.txt], report.entries.map(&:name))
      assert_equal([::Zip::Entry::DEFLATED, ::Zip::Entry::STORED],
                   report.entries.map(&:compression_method))
      assert_nil(report.trailing_note)

      first = report.entries[0]
      assert_equal(0, first.local_header_offset)
      name_length, extra_length = File.binread(path, 4, 26).unpack('vv')
      assert_equal(30 + name_length + extra_length, first.data_offset)
      assert(first.data_end_offset > first.data_offset)
      assert_equal(first.data_end_offset, first.end_offset)
      assert(first.evidence.any? { |line| line.include?('deflate stream ended cleanly') })
      assert_nil(first.failure)

      second = report.entries[1]
      assert_equal(first.end_offset, second.local_header_offset)
      assert(second.evidence.any? { |line| line.include?('exact boundary') })
    end
  end

  def test_deflated_entry_with_data_descriptors
    content = 'streamed content' * 50
    compressed = deflate_raw(content)
    crc = Zlib.crc32(content)

    Dir.mktmpdir do |dir|
      path = File.join(dir, 'broken.zip')
      image = +''.b
      image << local_header('with_sig.txt', gp_flags: 0x08)
      image << compressed
      image << DESCRIPTOR_SIGNATURE + [crc, compressed.bytesize, content.bytesize].pack('VVV')
      image << local_header('without_sig.txt', gp_flags: 0x08)
      image << compressed
      image << [crc, compressed.bytesize, content.bytesize].pack('VVV')
      File.binwrite(path, image)

      report = ::Zip::Recovery.scan(path)

      assert_equal(2, report.entries.size)
      assert(report.entries.all?(&:recoverable?))
      assert(report.entries[0].evidence.any? { |l| l.include?('with signature') })
      assert(report.entries[1].evidence.any? { |l| l.include?('data descriptor') })
      assert_equal(report.entries[1].end_offset, image.bytesize)
    end
  end

  def test_deflated_entry_with_bad_descriptor_fails
    content = 'streamed content'
    compressed = deflate_raw(content)

    Dir.mktmpdir do |dir|
      path = File.join(dir, 'broken.zip')
      image = local_header('bad_desc.txt', gp_flags: 0x08)
      image << compressed
      image << DESCRIPTOR_SIGNATURE +
               [0xDEADBEEF, compressed.bytesize, content.bytesize].pack('VVV')
      File.binwrite(path, image)

      report = ::Zip::Recovery.scan(path)

      assert_equal(1, report.entries.size)
      entry = report.entries[0]
      refute(entry.recoverable?)
      assert_match(/data descriptor.*inconsistent/, entry.failure)
    end
  end

  def test_stored_entry_with_data_descriptor_is_not_guessed
    content = 'stored streamed content'
    crc = Zlib.crc32(content)

    Dir.mktmpdir do |dir|
      path = File.join(dir, 'broken.zip')
      image = local_header('stored_stream.txt', gp_flags: 0x08, method: ::Zip::Entry::STORED)
      image << content
      image << DESCRIPTOR_SIGNATURE + [crc, content.bytesize, content.bytesize].pack('VVV')
      File.binwrite(path, image)

      report = ::Zip::Recovery.scan(path)

      assert_equal(1, report.entries.size)
      entry = report.entries[0]
      refute(entry.recoverable?)
      assert_match(/boundary cannot be determined without guessing/, entry.failure)
      assert_empty(report.recoverable_entries)
    end
  end

  def test_truncated_stored_entry_fails
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'broken.zip')
      image = local_header('truncated.txt', method: ::Zip::Entry::STORED,
                                            crc: 0, csize: 100, size: 100)
      image << 'only fifty bytes of actual data are present here!!'
      File.binwrite(path, image)

      report = ::Zip::Recovery.scan(path)

      entry = report.entries[0]
      refute(entry.recoverable?)
      assert_match(/stored data is truncated/, entry.failure)
    end
  end

  def test_truncated_deflated_entry_fails
    compressed = deflate_raw('some deflated content' * 50)

    Dir.mktmpdir do |dir|
      path = File.join(dir, 'broken.zip')
      image = local_header('truncated.txt')
      image << compressed.byteslice(0, compressed.bytesize / 2)
      File.binwrite(path, image)

      report = ::Zip::Recovery.scan(path)

      entry = report.entries[0]
      refute(entry.recoverable?)
      assert_match(/no end marker/, entry.failure)
    end
  end

  def test_crc_mismatch_fails
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'broken.zip')
      image = local_header('corrupt.txt', method: ::Zip::Entry::STORED,
                                          crc: 0xDEADBEEF, csize: 5, size: 5)
      image << 'hello'
      File.binwrite(path, image)

      report = ::Zip::Recovery.scan(path)

      entry = report.entries[0]
      refute(entry.recoverable?)
      assert_match(/CRC mismatch/, entry.failure)
    end
  end

  def test_zip_like_bytes_inside_content_are_not_recovered
    # Content that itself looks like a plausible local file header.
    fake_header = local_header('fake.txt', method: ::Zip::Entry::STORED,
                                           crc: 0, csize: 4, size: 4)
    content = 'prefix ' + fake_header + 'fake' + ' suffix'

    Dir.mktmpdir do |dir|
      path = build_broken_zip(dir, [
                                ['real.txt', content, ::Zip::Entry::STORED]
                              ],
                              # Trailing garbage that also looks like a header.
                              trailer: local_header('trailing_fake.txt',
                                                    method: ::Zip::Entry::STORED,
                                                    csize: 10_000, size: 10_000))

      report = ::Zip::Recovery.scan(path)

      names = report.entries.map(&:name)
      assert_equal(1, report.recoverable_entries.size)
      assert_equal('real.txt', report.recoverable_entries[0].name)
      refute_includes(names, 'fake.txt')
      # The trailing fake header is reported as failed, never as recoverable.
      trailing = report.entries.find { |e| e.name == 'trailing_fake.txt' }
      assert(trailing)
      refute(trailing.recoverable?)
    end
  end

  def test_empty_stored_entry_is_recoverable
    Dir.mktmpdir do |dir|
      path = build_broken_zip(dir, [['dir/', ''.b, ::Zip::Entry::STORED]])

      report = ::Zip::Recovery.scan(path)

      assert_equal(1, report.entries.size)
      assert(report.entries[0].recoverable?)
      assert_equal('dir/', report.entries[0].name)
    end
  end

  def test_intact_zip_reports_central_directory_note
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'intact.zip')
      ::Zip::OutputStream.open(path) do |zos|
        zos.put_next_entry('a.txt')
        zos << 'content a'
      end

      report = ::Zip::Recovery.scan(path)

      assert_equal(1, report.entries.size)
      assert(report.entries[0].recoverable?)
      assert_match(/central directory/, report.trailing_note)
    end
  end

  def test_recover_writes_confirmed_entries_only
    Dir.mktmpdir do |dir|
      path = build_broken_zip(dir, [
                                ['one.txt', 'content one' * 50, ::Zip::Entry::DEFLATED],
                                ['two.txt', 'content two', ::Zip::Entry::STORED],
                                ['three.txt', 'content three', ::Zip::Entry::DEFLATED]
                              ])
      destination = File.join(dir, 'recovered.zip')

      ::Zip::Recovery.recover(path, destination, confirm: %w[one.txt two.txt])

      ::Zip::File.open(destination) do |zf|
        assert_equal(%w[one.txt two.txt], zf.entries.map(&:name))
        assert_equal('content one' * 50, zf.read('one.txt'))
        assert_equal('content two', zf.read('two.txt'))
      end
    end
  end

  def test_recover_requires_explicit_confirmation
    Dir.mktmpdir do |dir|
      path = build_broken_zip(dir, [['one.txt', 'content', ::Zip::Entry::DEFLATED]])

      assert_raises(ArgumentError) do
        ::Zip::Recovery.recover(path, File.join(dir, 'out.zip'))
      end
    end
  end

  def test_recover_refuses_failed_or_unknown_entries
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'broken.zip')
      image = local_header('truncated.txt', method: ::Zip::Entry::STORED,
                                            crc: 0, csize: 100, size: 100)
      image << 'short'
      File.binwrite(path, image)
      destination = File.join(dir, 'out.zip')

      assert_raises(::Zip::Error) do
        ::Zip::Recovery.recover(path, destination, confirm: ['truncated.txt'])
      end
      assert_raises(::Zip::Error) do
        ::Zip::Recovery.recover(path, destination, confirm: ['missing.txt'])
      end
      refute(File.exist?(destination))
    end
  end

  def test_recover_refuses_to_overwrite_source
    Dir.mktmpdir do |dir|
      path = build_broken_zip(dir, [['one.txt', 'content', ::Zip::Entry::DEFLATED]])

      assert_raises(::Zip::Error) do
        ::Zip::Recovery.recover(path, path, confirm: ['one.txt'])
      end
    end
  end

  def test_source_archive_is_not_modified
    Dir.mktmpdir do |dir|
      path = build_broken_zip(dir, [['one.txt', 'content one', ::Zip::Entry::DEFLATED]])
      checksum_before = Digest::SHA256.file(path).hexdigest
      mtime_before = File.mtime(path)

      ::Zip::Recovery.scan(path)
      ::Zip::Recovery.recover(path, File.join(dir, 'recovered.zip'), confirm: ['one.txt'])

      assert_equal(checksum_before, Digest::SHA256.file(path).hexdigest)
      assert_equal(mtime_before, File.mtime(path))
    end
  end
end
