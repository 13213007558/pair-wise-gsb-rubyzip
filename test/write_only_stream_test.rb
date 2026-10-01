# frozen_string_literal: true

require_relative 'test_helper'

# Tests for the write-only, non-seekable streaming mode of Zip::OutputStream.
#
# Every archive here is produced through a destination that rejects #seek
# (and does not provide #tell), so nothing in the library can rely on
# random access or buffering the archive anywhere. The archives are then
# checked by an independent parser written directly against the ZIP wire
# format (not the library's own reader), and additionally by the system
# `unzip` tool where available.
class WriteOnlyOutputStreamTest < Minitest::Test
  TEST_ZIP = 'test/data/generated/write_only.zip'

  # A destination that only accepts bytes. It deliberately raises if
  # anything tries to seek, rewind or set the position, and it provides no
  # #tell, modelling something like an HTTP response body.
  class WriteOnlySink
    attr_reader :bytes, :flush_count

    def initialize
      @bytes = +''.b
      @flush_count = 0
    end

    def write(data)
      @bytes << data
      data.bytesize
    end

    def <<(data)
      write(data)
      self
    end

    def flush
      @flush_count += 1
    end

    def seek(*)
      raise 'seek must never be called on a write-only destination'
    end

    def rewind
      raise 'rewind must never be called on a write-only destination'
    end

    def pos=(*)
      raise 'pos= must never be called on a write-only destination'
    end
  end

  # Same idea, but only #<< is implemented (as Rack response bodies can
  # use).
  class AppendOnlySink
    attr_reader :bytes

    def initialize
      @bytes = +''.b
    end

    def <<(data)
      @bytes << data
      self
    end
  end

  def teardown
    ::Zip.reset!
  end

  def test_stored_and_deflated_entries_round_trip
    sink = WriteOnlySink.new
    stored = 'stored content, written a few bytes at a time'
    deflated = 'deflate me! ' * 100

    ::Zip::OutputStream.write_stream(sink) do |zos|
      zos.put_next_entry('stored.txt', '', ::Zip::ExtraField.new,
                         ::Zip::Entry::STORED)
      stored.each_char.each_slice(7) { |c| zos.write(c.join) }
      zos.put_next_entry('deflated.txt')
      zos << deflated
    end

    assert_equal(1, sink.flush_count)

    zip = ParsedZip.new(sink.bytes, test_context: self)
    assert_equal(%w[stored.txt deflated.txt], zip.names)

    stored_entry = zip.entry('stored.txt')
    assert_equal(::Zip::COMPRESSION_METHOD_STORE, stored_entry.method)
    stored_entry.verify!(stored, local_uses_descriptor: true)

    deflated_entry = zip.entry('deflated.txt')
    assert_equal(::Zip::COMPRESSION_METHOD_DEFLATE, deflated_entry.method)
    deflated_entry.verify!(deflated, local_uses_descriptor: true)
  end

  def test_entries_can_be_provided_piece_by_piece
    pieces = ['first piece', '', ' second ', 'piece']
    sink = WriteOnlySink.new

    ::Zip::OutputStream.write_stream(sink) do |zos|
      zos.put_next_entry('chunked.bin', nil, nil, ::Zip::Entry::STORED)
      pieces.each { |piece| zos.write(piece) }
    end

    ParsedZip.new(sink.bytes, test_context: self).entry('chunked.bin')
             .verify!(pieces.join, local_uses_descriptor: true)
  end

  def test_empty_file_entries_and_directories_have_determined_policy
    sink = WriteOnlySink.new

    ::Zip::OutputStream.write_stream(sink) do |zos|
      zos.put_next_entry('empty_deflated.txt')
      zos.put_next_entry('empty_stored.bin', nil, nil, ::Zip::Entry::STORED)
      zos.write('')
      zos.put_next_entry('adir/')
    end

    zip = ParsedZip.new(sink.bytes, test_context: self)
    assert_equal(%w[empty_deflated.txt empty_stored.bin adir/], zip.names)

    empty_deflated = zip.entry('empty_deflated.txt')
    empty_deflated.verify!('', local_uses_descriptor: true)
    assert_equal(::Zip::COMPRESSION_METHOD_DEFLATE, empty_deflated.method)
    # The canonical empty deflate stream is two bytes. The size is carried
    # in the Zip64 extra field (the entry's size was unknown up front).
    assert_equal(2, empty_deflated.resolved_sizes.last)

    empty_stored = zip.entry('empty_stored.bin')
    empty_stored.verify!('', local_uses_descriptor: true)
    assert_equal(0, empty_stored.resolved_sizes.last)

    directory = zip.entry('adir/')
    assert_equal(::Zip::COMPRESSION_METHOD_STORE, directory.method)
    assert_equal(0, directory.uncompressed_size)
    assert_equal(0, directory.compressed_size)
    # Directories have no data, so they do not use a data descriptor.
    refute(directory.gp_flags & 0x08 == 0x08)
  end

  def test_append_only_destination_works
    sink = AppendOnlySink.new
    ::Zip::OutputStream.write_stream(sink) do |zos|
      zos.put_next_entry('a.txt')
      zos.write('hello')
    end

    ParsedZip.new(sink.bytes, test_context: self).entry('a.txt').verify!('hello', local_uses_descriptor: true)
  end

  def test_destination_is_not_closed
    sink = WriteOnlySink.new
    zos = ::Zip::OutputStream.new(sink, write_only: true)
    zos.put_next_entry('a.txt')
    zos.write('hello')
    zos.close

    # The sink has no #close at all; reaching here means close was never
    # attempted. It can still be written to by the caller.
    sink.write('post-close bytes are fine')
    assert(sink.bytes.end_with?('post-close bytes are fine'))
  end

  def test_data_descriptors_are_well_formed
    sink = WriteOnlySink.new
    ::Zip::OutputStream.write_stream(sink) do |zos|
      zos.put_next_entry('one.txt', nil, nil, ::Zip::Entry::STORED)
      zos.write('abc')
    end

    ParsedZip.new(sink.bytes, test_context: self).entry('one.txt').tap do |entry|
      descriptor = entry.data_descriptor
      refute_nil(descriptor, 'a data descriptor must follow the entry data')
      assert_equal(0x08074B50, descriptor.signature)
      assert_equal(Zlib.crc32('abc'), descriptor.crc)
      assert_equal(3, descriptor.compressed_size)
      assert_equal(3, descriptor.uncompressed_size)
    end
  end

  def test_comment_is_written
    sink = WriteOnlySink.new
    ::Zip::OutputStream.write_stream(sink) do |zos|
      zos.comment = 'archive comment'
      zos.put_next_entry('a.txt')
      zos.write('x')
    end

    assert_equal('archive comment', ParsedZip.new(sink.bytes, test_context: self).comment)
  end

  def test_duplicate_entry_names_still_rejected
    sink = WriteOnlySink.new
    assert_raises(::Zip::EntryExistsError) do
      ::Zip::OutputStream.write_stream(sink) do |zos|
        zos.put_next_entry('dup.txt')
        zos.write('first')
        zos.put_next_entry('dup.txt')
      end
    end
  end

  def test_copy_raw_entry_is_rejected
    sink = WriteOnlySink.new
    error = assert_raises(::Zip::Error) do
      ::Zip::OutputStream.write_stream(sink) do |zos|
        zos.copy_raw_entry(::Zip::Entry.new(nil, 'x.txt'))
      end
    end
    assert_match(/write-only/, error.message)
  end

  def test_encryption_is_rejected
    assert_raises(ArgumentError) do
      ::Zip::OutputStream.new(
        WriteOnlySink.new,
        write_only: true,
        encrypter:  ::Zip::TraditionalEncrypter.new('secret')
      )
    end
  end

  def test_stream_and_write_only_are_mutually_exclusive
    assert_raises(ArgumentError) do
      ::Zip::OutputStream.new(WriteOnlySink.new, stream: true, write_only: true)
    end
  end

  def test_existing_seekable_behaviour_is_unchanged
    File.binwrite(TEST_ZIP, '')
    ::Zip::OutputStream.open(TEST_ZIP) do |zos|
      zos.put_next_entry('a.txt')
      zos.write('hello world')
    end

    ParsedZip.new(File.binread(TEST_ZIP), test_context: self).entry('a.txt').then do |entry|
      # The existing path writes no data descriptors and keeps no bit 3.
      refute(entry.gp_flags & 0x08 == 0x08)
      assert_nil(entry.data_descriptor)
      entry.verify!('hello world', local_uses_descriptor: false)
    end
  ensure
    FileUtils.rm_f(TEST_ZIP)
  end

  def test_zip64_support_off_uses_plain_headers
    ::Zip.write_zip64_support = false
    sink = WriteOnlySink.new
    ::Zip::OutputStream.write_stream(sink) do |zos|
      zos.put_next_entry('stored.txt', nil, nil, ::Zip::Entry::STORED)
      zos.write('plain')
    end

    entry = ParsedZip.new(sink.bytes, test_context: self).entry('stored.txt')
    refute(entry.zip64?)
    entry.verify!('plain', local_uses_descriptor: true)
  end

  def test_zip64_support_off_raises_when_the_archive_grows_past_4gib
    ::Zip.write_zip64_support = false
    wio = ::Zip::IOExtras::WriteOnlyIO.new(
      WriteOnlySink.new, start_offset: 0xFFFFFF00
    )
    zos = ::Zip::OutputStream.new(wio, write_only: true)
    zos.put_next_entry('a.txt', nil, nil, ::Zip::Entry::STORED)
    zos.write('x' * 0x200)
    error = assert_raises(::Zip::Error) { zos.close }
    assert_match(/Zip64/i, error.message)
  end

  def test_zip64_is_emitted_when_central_directory_offset_crosses_4gib
    # Simulate that ~4GiB of archive data was already written using a
    # counting IO. Only a handful of bytes actually hit the sink.
    sink = WriteOnlySink.new
    wio = ::Zip::IOExtras::WriteOnlyIO.new(sink, start_offset: 0xFFFFFFF0)
    zos = ::Zip::OutputStream.new(wio, write_only: true)
    zos.put_next_entry('a.txt', nil, nil, ::Zip::Entry::STORED)
    zos.write('abc')
    zos.close

    parsed = ParsedZip.new(sink.bytes, virtual_base: 0xFFFFFFF0, test_context: self)
    assert(parsed.zip64?, 'a Zip64 EOCD record must be present')
    assert_equal(0xFFFFFFF0 + sink.bytes.index([0x02014B50].pack('V')),
                 parsed.zip64_central_directory_offset)
    parsed.entry('a.txt').verify!('abc', local_uses_descriptor: true)
  end

  def test_zip64_is_emitted_when_local_header_offset_crosses_4gib
    # An unknown-size stored entry occupies: a 55-byte local header (with its
    # Zip64 extra), 3 bytes of data, and a 24-byte Zip64 data descriptor.
    # Position the stream so the second entry's local header lands just
    # beyond 0xFFFFFFFF.
    first_entry_size = 55 + 3 + 24
    start = 0x100000000 - first_entry_size + 1
    sink = WriteOnlySink.new
    wio = ::Zip::IOExtras::WriteOnlyIO.new(sink, start_offset: start)
    zos = ::Zip::OutputStream.new(wio, write_only: true)
    zos.put_next_entry('a.txt', nil, nil, ::Zip::Entry::STORED)
    zos.write('abc')
    zos.put_next_entry('b.txt')
    zos.write('defg')
    zos.close

    parsed = ParsedZip.new(sink.bytes, virtual_base: start, test_context: self)
    second = parsed.entry('b.txt')
    assert(second.zip64?, 'the second entry must carry a Zip64 extra field')
    assert_equal(start + first_entry_size, second.virtual_local_header_offset)
    second.verify!('defg', local_uses_descriptor: true)
  end

  def test_entry_near_4gib_uses_64bit_data_descriptor
    # An unknown-size streamed entry whose data finishes past 4GiB must
    # end with a Zip64 data descriptor (crc + two 64-bit sizes).
    sink = WriteOnlySink.new
    # Local header of a stored unknown-size entry is 55 bytes; start so the
    # entry data crosses the 4GiB boundary 5 bytes in.
    start = 0x100000000 - 55 - 5
    wio = ::Zip::IOExtras::WriteOnlyIO.new(sink, start_offset: start)
    zos = ::Zip::OutputStream.new(wio, write_only: true)
    zos.put_next_entry('big.txt', nil, nil, ::Zip::Entry::STORED)
    zos.write('abcdefgh') # uncompressed size 8, crossing 4GiB virtually
    zos.close

    parsed = ParsedZip.new(sink.bytes, virtual_base: start, test_context: self)
    entry = parsed.entry('big.txt')
    assert(entry.zip64?)
    descriptor = entry.data_descriptor
    assert_equal(24, descriptor.record_size,
                 'a Zip64 data descriptor is signature+crc+two Q words')
    assert_equal(8, descriptor.uncompressed_size)
    assert_equal(8, descriptor.compressed_size)
    entry.verify!('abcdefgh', local_uses_descriptor: true)
  end

  def test_system_unzip_can_read_the_streamed_archive
    skip unless system('which unzip > /dev/null 2>&1')

    sink = WriteOnlySink.new
    ::Zip::OutputStream.write_stream(sink) do |zos|
      zos.put_next_entry('stored.txt', nil, nil, ::Zip::Entry::STORED)
      zos.write('unzip can read this')
      zos.put_next_entry('deflated.txt')
      zos.write('compressed ' * 50)
      zos.put_next_entry('empty.txt')
      zos.put_next_entry('dir/')
    end

    path = File.join(Dir.tmpdir, "write-only-#{Process.pid}.zip")
    File.binwrite(path, sink.bytes)
    assert(system("unzip -tqq #{path}"), 'system unzip rejected the archive')
  ensure
    FileUtils.rm_f(path)
  end

  # Minimal, self-contained reader for the subset of the ZIP format these
  # archives use. It deliberately does not use Zip::File or
  # Zip::InputStream, so it provides genuinely independent verification.
  class ParsedZip
    # The raw archive bytes, indexed with physical (captured) offsets.
    attr_reader :bytes, :virtual_base

    Entry = Struct.new(
      :name, :method, :gp_flags, :crc, :compressed_size, :uncompressed_size,
      :local_header_offset, :data_offset, :zip64_extra, :data_descriptor,
      :local_zip64, :archive, :test_context,
      keyword_init: true
    ) do
      def zip64?
        !zip64_extra.nil?
      end

      def local_has_zip64?
        local_zip64
      end

      # The local header offset as a virtual archive coordinate (resolving
      # the Zip64 extra field when the base field is 0xFFFFFFFF).
      def resolved_local_header_offset
        if local_header_offset == 0xFFFFFFFF && zip64_extra
          zip64_extra.byteslice(zip64_extra.bytesize - 8, 8).unpack1('Q<')
        else
          local_header_offset
        end
      end

      # The absolute local header offset as a virtual archive coordinate
      # (the zip64 extra stores it directly when the base field is FFFFFFFF).
      def virtual_local_header_offset
        resolved_local_header_offset
      end

      def verify!(expected_content, local_uses_descriptor:)
        # Resolve sizes through the Zip64 extra field when the base fields
        # are all-FF placeholders.
        uncompressed, compressed = resolved_sizes
        test_context.assert_equal(
          expected_content.bytesize, uncompressed,
          "central directory size mismatch for #{name}"
        )
        test_context.assert_equal(
          Zlib.crc32(expected_content), crc,
          "central directory CRC mismatch for #{name}"
        )

        data = archive.bytes.byteslice(data_offset, compressed)
        actual =
          if method == ::Zip::COMPRESSION_METHOD_STORE
            data
          else
            Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(data)
          end
        test_context.assert_equal(
          expected_content, actual, "content mismatch for #{name}"
        )

        if local_uses_descriptor
          test_context.assert(
            (gp_flags & 0x08) == 0x08,
            "bit 3 must be set for streamed entry #{name}"
          )
          test_context.refute_nil(
            data_descriptor, "missing data descriptor for #{name}"
          )
          test_context.assert_equal(crc, data_descriptor.crc)
          test_context.assert_equal(compressed, data_descriptor.compressed_size)
          test_context.assert_equal(
            uncompressed, data_descriptor.uncompressed_size
          )
        end
      end

      def resolved_sizes
        uncompressed = uncompressed_size
        compressed = compressed_size
        if zip64_extra
          idx = 0
          if uncompressed == 0xFFFFFFFF
            uncompressed = zip64_extra.byteslice(idx, 8).unpack1('Q<')
            idx += 8
          end
          if compressed == 0xFFFFFFFF
            compressed = zip64_extra.byteslice(idx, 8).unpack1('Q<')
          end
        end
        [uncompressed, compressed]
      end
    end

    Descriptor = Struct.new(:signature, :crc, :compressed_size,
                            :uncompressed_size, :record_size, keyword_init: true)

    attr_reader :entries, :comment

    def initialize(bytes, virtual_base: 0, test_context: nil)
      @bytes = bytes
      @virtual_base = virtual_base
      @test_context = test_context
      @entries = []
      parse
    end

    def names
      @entries.map(&:name)
    end

    def entry(name)
      @entries.find { |e| e.name == name } || raise("no entry #{name}")
    end

    def zip64?
      !@zip64_eocd_offset.nil?
    end

    def zip64_central_directory_offset
      @zip64_central_directory_offset
    end

    private

    def parse
      parse_end_of_central_directory
      parse_central_directory
      parse_local_parts
    end

    def parse_end_of_central_directory
      eocd = @bytes.rindex([0x06054B50].pack('V'))
      raise 'classic EOCD not found' unless eocd

      _, _, _, count, _total, cdir_size, cdir_offset, comment_length =
        @bytes.byteslice(eocd, 22).unpack('VvvvvVVv')
      @comment = @bytes.byteslice(eocd + 22, comment_length)

      if cdir_offset == 0xFFFFFFFF || cdir_size == 0xFFFFFFFF ||
         count == 0xFFFF
        locator = @bytes.rindex([0x07064B50].pack('V'))
        raise 'Zip64 EOCD locator not found' unless locator

        zip64_eocd_virtual =
          @bytes.byteslice(locator + 8, 8).unpack1('Q<')
        @zip64_eocd_offset = physical(zip64_eocd_virtual)
        fields = @bytes.byteslice(@zip64_eocd_offset, 56)
                    .unpack('VQ<vvVVQ<Q<Q<Q<')
        count = fields[7]
        cdir_size = fields[8]
        cdir_offset = fields[9]
        @zip64_central_directory_offset = cdir_offset
      end

      @entry_count = count
      @cdir_offset = physical(cdir_offset)
      @cdir_size = cdir_size
    end

    def parse_central_directory
      pos = @cdir_offset
      @entry_count.times do
        header = @bytes.byteslice(pos, 46)
        raise 'bad central directory signature' unless
          header.byteslice(0, 4).unpack1('V') == 0x02014B50

        fields = header.unpack('VCCvvvvvVVVvvvvvVV')
        crc = fields[8]
        compressed_size = fields[9]
        uncompressed_size = fields[10]
        name_length = fields[11]
        extra_length = fields[12]
        comment_length = fields[13]
        gp_flags = fields[4]
        method = fields[5]
        local_header_offset = fields[17]

        name = @bytes.byteslice(pos + 46, name_length)
        extra = @bytes.byteslice(pos + 46 + name_length, extra_length)

        zip64_extra = nil
        extra_pos = 0
        while extra_pos + 4 <= extra.bytesize
          id, length = extra.byteslice(extra_pos, 4).unpack('vv')
          body = extra.byteslice(extra_pos + 4, length)
          zip64_extra = body if id == 0x0001
          extra_pos += 4 + length
        end

        @entries << Entry.new(
          name: name, method: method, gp_flags: gp_flags, crc: crc,
          compressed_size: compressed_size,
          uncompressed_size: uncompressed_size,
          local_header_offset: local_header_offset,
          data_offset: nil,
          zip64_extra: zip64_extra,
          archive: self,
          test_context: @test_context
        )

        pos += 46 + name_length + extra_length + comment_length
      end
    end

    def parse_local_parts
      @entries.each do |entry|
        local_pos = physical(entry.resolved_local_header_offset)
        header = @bytes.byteslice(local_pos, 30)
        raise 'bad local header signature' unless
          header.byteslice(0, 4).unpack1('V') == 0x04034B50

        name_length = header.unpack1('x26v')
        extra_length = header.unpack1('x28v')
        data_pos = local_pos + 30 + name_length + extra_length
        local_extra = @bytes.byteslice(local_pos + 30 + name_length, extra_length)
        entry.local_zip64 = local_extra_contains_zip64(local_extra)
        entry.data_offset = data_pos

        _, compressed = entry.resolved_sizes
        descriptor_pos = data_pos + compressed
        if entry.gp_flags & 0x08 == 0x08
          entry.data_descriptor = parse_descriptor(descriptor_pos, entry.local_has_zip64?)
        end
      end
    end

    def parse_descriptor(pos, zip64)
      sig = @bytes.byteslice(pos, 4).unpack1('V')
      if sig == 0x08074B50
        if zip64
          _, crc, compressed, uncompressed =
            @bytes.byteslice(pos, 24).unpack('VVQ<Q<')
          Descriptor.new(signature: sig, crc: crc,
                         compressed_size: compressed,
                         uncompressed_size: uncompressed, record_size: 24)
        else
          _, crc, compressed, uncompressed =
            @bytes.byteslice(pos, 16).unpack('VVVV')
          Descriptor.new(signature: sig, crc: crc,
                         compressed_size: compressed,
                         uncompressed_size: uncompressed, record_size: 16)
        end
      end
    end

    # Translate a possibly virtual (>= physical file size) archive offset
    # into a physical offset in the captured bytes.
    def physical(virtual_offset)
      virtual_offset - @virtual_base
    end

    def local_extra_contains_zip64(extra)
      pos = 0
      while pos + 4 <= extra.bytesize
        id, length = extra.byteslice(pos, 4).unpack('vv')
        return true if id == 0x0001

        pos += 4 + length
      end
      false
    end
  end
end
