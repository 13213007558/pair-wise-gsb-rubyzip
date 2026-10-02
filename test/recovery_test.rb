# frozen_string_literal: true

require_relative 'test_helper'
require 'tmpdir'
require 'digest'

class ZipRecoveryTest < Minitest::Test
  DOS_TIME = 0x7C00 # 15:32:00
  DOS_DATE = 0x5821 # 2024-01-01

  def setup
    @tmpdir = Dir.mktmpdir
  end

  def teardown
    FileUtils.rm_rf(@tmpdir)
  end

  def test_scan_verifies_deflated_entries_with_header_sizes
    path = write_source(
      deflate_entry_bytes('a.txt', 'Hello recovery!') +
      deflate_entry_bytes('b.txt', 'Second entry contents.' * 10)
    )

    report = Zip::Recovery.new(path).scan

    assert_equal 2, report.entries.size
    assert_equal %w[a.txt b.txt], report.entries.map(&:name)
    assert(report.entries.all?(&:verified?))
    assert(report.entries.all?(&:recoverable?))
    assert_empty(report.failed_entries)

    first = report.entries.first
    assert_equal 0, first.local_header_offset
    assert_equal 30 + 'a.txt'.bytesize, first.data_offset
    assert_equal first.data_offset + first.compressed_size, first.data_end_offset
    assert_equal first.data_end_offset, first.entry_end_offset
    assert_equal 'Hello recovery!'.bytesize, first.size
    assert_equal Zlib.crc32('Hello recovery!'), first.crc
    assert_equal 8, first.compression_method
    assert(first.evidence.any? { |line| line =~ /Deflate stream ends at offset/ })
    assert(first.evidence.any? { |line| line =~ /match the local header/ })

    second = report.entries[1]
    assert_equal first.entry_end_offset, second.local_header_offset
  end

  def test_scan_verifies_deflated_entry_with_signed_data_descriptor
    path = write_source(deflate_entry_bytes('streamed.txt', 'streamed contents',
                                            descriptor: :signature))

    report = Zip::Recovery.new(path).scan
    entry = report.entries.first

    assert_equal 1, report.entries.size
    assert_predicate(entry, :verified?)
    assert_equal 'streamed.txt', entry.name
    assert_equal 'streamed contents'.bytesize, entry.size
    assert_equal entry.data_end_offset + 16, entry.entry_end_offset
    assert(entry.evidence.any? { |line| line =~ /Data descriptor .with signature./ })
    assert(entry.evidence.any? { |line| line =~ /confirmed by the data descriptor/ })
  end

  def test_scan_verifies_deflated_entry_with_unsigned_data_descriptor
    path = write_source(deflate_entry_bytes('streamed.txt', 'streamed contents',
                                            descriptor: :no_signature))

    report = Zip::Recovery.new(path).scan
    entry = report.entries.first

    assert_equal 1, report.entries.size
    assert_predicate(entry, :verified?)
    assert_equal entry.data_end_offset + 12, entry.entry_end_offset
    assert(entry.evidence.any? { |line| line =~ /Data descriptor .without signature./ })
  end

  def test_scan_verifies_stored_entry
    path = write_source(stored_entry_bytes('plain.txt', 'plain stored contents'))

    report = Zip::Recovery.new(path).scan
    entry = report.entries.first

    assert_predicate(entry, :verified?)
    assert_equal 0, entry.compression_method
    assert_equal 'plain stored contents'.bytesize, entry.size
    assert_equal Zlib.crc32('plain stored contents'), entry.crc
    assert(entry.evidence.any? { |line| line =~ /Stored data verified/ })
  end

  def test_stored_entry_with_data_descriptor_is_not_recoverable
    data = 'stored data with deferred sizes'
    archive = local_header(name: 'deferred.bin', method: 0, gp_flags: 8) +
              data +
              [Zip::Recovery::DATA_DESCRIPTOR_SIGNATURE, Zlib.crc32(data),
               data.bytesize, data.bytesize].pack('V4') +
              deflate_entry_bytes('unreachable.txt', 'cannot be found')
    path = write_source(archive)

    report = Zip::Recovery.new(path).scan

    assert_equal 1, report.entries.size
    entry = report.entries.first
    assert_equal 'deferred.bin', entry.name
    assert_predicate(entry, :failed?)
    refute_predicate(entry, :recoverable?)
    assert_match(/boundary cannot be determined/, entry.failure_reason)
    assert_nil(entry.data_end_offset)
    assert(report.notes.any? { |note| note =~ /Scan stopped/ })
  end

  def test_truncated_deflate_entry_fails
    compressed = deflate('truncated deflate contents')
    archive = deflate_entry_bytes('good.txt', 'good contents') +
              local_header(name: 'bad.txt', method: 8, crc: Zlib.crc32('truncated deflate contents'),
                           compressed_size: compressed.bytesize,
                           size: 'truncated deflate contents'.bytesize) +
              compressed[0, compressed.bytesize / 2]
    path = write_source(archive)

    report = Zip::Recovery.new(path).scan

    assert_equal 2, report.entries.size
    assert_predicate(report.entries[0], :verified?)
    bad = report.entries[1]
    assert_equal 'bad.txt', bad.name
    assert_predicate(bad, :failed?)
    assert_match(/truncated/, bad.failure_reason)
  end

  def test_truncated_stored_entry_fails
    archive = local_header(name: 'short.bin', method: 0, crc: 0, compressed_size: 100, size: 100) +
              'only ten!'
    path = write_source(archive)

    report = Zip::Recovery.new(path).scan
    entry = report.entries.first

    assert_predicate(entry, :failed?)
    assert_match(/truncated/, entry.failure_reason)
  end

  def test_crc_mismatch_fails_verification
    path = write_source(stored_entry_bytes('corrupt.txt', 'actual contents', crc: 0xDEADBEEF))

    report = Zip::Recovery.new(path).scan
    entry = report.entries.first

    assert_predicate(entry, :failed?)
    assert_match(/CRC mismatch/, entry.failure_reason)
    assert_empty(report.verified_entries)
  end

  def test_fake_local_header_inside_payload_is_not_recovered
    fake_header = local_header(name: 'evil.txt', method: 0, crc: Zlib.crc32('EVIL!'),
                               compressed_size: 5, size: 5) + 'EVIL!'
    payload = 'Ordinary file contents that happen to contain what looks like a zip header: ' +
              fake_header + ' and some trailing text.'
    path = write_source(
      stored_entry_bytes('notes.txt', payload) +
      deflate_entry_bytes('real.txt', 'real contents')
    )

    report = Zip::Recovery.new(path).scan

    assert_equal %w[notes.txt real.txt], report.entries.map(&:name)
    assert(report.entries.all?(&:verified?))
    assert(report.entries.none? { |entry| entry.name == 'evil.txt' })
  end

  def test_standalone_fake_local_header_does_not_verify
    fake_header = local_header(name: 'evil.txt', method: 0, crc: 0xDEADBEEF,
                               compressed_size: 5, size: 5) + 'EVIL!'
    path = write_source(fake_header)

    report = Zip::Recovery.new(path).scan

    assert_equal 1, report.entries.size
    entry = report.entries.first
    assert_equal 'evil.txt', entry.name
    assert_predicate(entry, :failed?)
    assert_match(/CRC mismatch/, entry.failure_reason)
    assert_empty(report.verified_entries)
  end

  def test_encrypted_entry_is_not_recoverable
    path = write_source(local_header(name: 'secret.txt', method: 8, gp_flags: 1) + 'garbage')

    report = Zip::Recovery.new(path).scan
    entry = report.entries.first

    assert_predicate(entry, :failed?)
    assert_match(/encrypted/, entry.failure_reason)
  end

  def test_scan_notes_central_directory_when_archive_is_intact
    buffer = Zip::OutputStream.write_buffer do |zos|
      zos.put_next_entry('x.txt')
      zos << 'intact archive contents'
    end
    path = write_source(buffer.string)

    report = Zip::Recovery.new(path).scan

    assert_equal %w[x.txt], report.entries.map(&:name)
    assert(report.entries.all?(&:verified?))
    assert(report.notes.any? { |note| note =~ /Central directory/ })
  end

  def test_write_requires_confirmation
    path = write_source(deflate_entry_bytes('a.txt', 'contents'))
    recovery = Zip::Recovery.new(path)
    recovery.scan
    output = File.join(@tmpdir, 'out.zip')

    error = assert_raises(Zip::RecoveryError) { recovery.write(output) }
    assert_match(/No confirmed entries/, error.message)
    refute_path_exists(output)
  end

  def test_write_requires_a_prior_scan
    recovery = Zip::Recovery.new(File.join(@tmpdir, 'broken.zip'))

    assert_raises(Zip::RecoveryError) { recovery.write(File.join(@tmpdir, 'out.zip')) }
  end

  def test_confirm_bang_requires_a_verified_entry
    path = write_source(stored_entry_bytes('corrupt.txt', 'actual contents', crc: 0xDEADBEEF))
    report = Zip::Recovery.new(path).scan

    assert_raises(Zip::RecoveryError) { report.entries.first.confirm! }
  end

  def test_write_recovers_confirmed_entries_and_leaves_source_untouched
    path = write_source(
      deflate_entry_bytes('a.txt', 'Hello recovery!') +
      stored_entry_bytes('b.txt', 'plain stored contents')
    )
    digest_before = Digest::SHA256.file(path).hexdigest

    recovery = Zip::Recovery.new(path)
    report = recovery.scan
    report.verified_entries.each(&:confirm!)
    output = File.join(@tmpdir, 'recovered.zip')
    recovery.write(output)

    assert_equal digest_before, Digest::SHA256.file(path).hexdigest
    Zip::File.open(output) do |zf|
      assert_equal %w[a.txt b.txt], zf.entries.map(&:name)
      assert_equal 'Hello recovery!', zf.read('a.txt')
      assert_equal 'plain stored contents', zf.read('b.txt')
      assert_equal 0, zf.get_entry('b.txt').compression_method
    end
  end

  def test_write_only_writes_confirmed_entries
    path = write_source(
      deflate_entry_bytes('keep.txt', 'keep me') +
      deflate_entry_bytes('skip.txt', 'skip me')
    )
    recovery = Zip::Recovery.new(path)
    report = recovery.scan
    report.entries.first.confirm!
    output = File.join(@tmpdir, 'recovered.zip')
    recovery.write(output)

    Zip::File.open(output) do |zf|
      assert_equal %w[keep.txt], zf.entries.map(&:name)
    end
  end

  def test_write_refuses_to_overwrite_source_or_existing_file
    path = write_source(deflate_entry_bytes('a.txt', 'contents'))
    recovery = Zip::Recovery.new(path)
    report = recovery.scan
    report.entries.each(&:confirm!)

    assert_raises(Zip::RecoveryError) { recovery.write(path) }

    existing = File.join(@tmpdir, 'existing.zip')
    FileUtils.touch(existing)
    assert_raises(Zip::RecoveryError) { recovery.write(existing) }
    assert_equal 0, File.size(existing)
  end

  def test_class_method_scan_returns_report
    path = write_source(deflate_entry_bytes('a.txt', 'contents'))

    report = Zip::Recovery.scan(path)

    assert_kind_of(Zip::Recovery::Report, report)
    assert_equal path, report.source_path
    assert_equal %w[a.txt], report.entries.map(&:name)
  end

  private

  def local_header(name:, method:, gp_flags: 0, crc: 0, compressed_size: 0, size: 0)
    [
      Zip::LOCAL_ENTRY_SIGNATURE, 20, gp_flags, method, DOS_TIME, DOS_DATE,
      crc, compressed_size, size, name.bytesize, 0
    ].pack('VvvvvvVVVvv') + name
  end

  def deflate(data)
    deflater = Zlib::Deflate.new(Zlib::DEFAULT_COMPRESSION, -Zlib::MAX_WBITS)
    compressed = deflater.deflate(data, Zlib::FINISH)
    deflater.close
    compressed
  end

  def deflate_entry_bytes(name, data, descriptor: :none)
    compressed = deflate(data)
    crc = Zlib.crc32(data)
    case descriptor
    when :none
      local_header(name: name, method: 8, crc: crc, compressed_size: compressed.bytesize,
                   size: data.bytesize) + compressed
    when :signature
      local_header(name: name, method: 8, gp_flags: 8) + compressed +
        [Zip::Recovery::DATA_DESCRIPTOR_SIGNATURE, crc, compressed.bytesize,
         data.bytesize].pack('V4')
    when :no_signature
      local_header(name: name, method: 8, gp_flags: 8) + compressed +
        [crc, compressed.bytesize, data.bytesize].pack('V3')
    end
  end

  def stored_entry_bytes(name, data, crc: Zlib.crc32(data))
    local_header(name: name, method: 0, crc: crc, compressed_size: data.bytesize,
                 size: data.bytesize) + data
  end

  def write_source(bytes)
    path = File.join(@tmpdir, 'broken.zip')
    File.binwrite(path, bytes)
    path
  end
end
