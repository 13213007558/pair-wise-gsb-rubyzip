# frozen_string_literal: true

require_relative 'test_helper'
require 'zlib'
require 'tempfile'
require 'fileutils'
require 'shellwords'

# Verifies that Zip::OutputStream can write an archive straight to a
# write-only target (no seeking required), using data descriptors, and that
# the resulting archive is valid. The archive is checked in two independent
# ways: a hand-written parser below (which never uses rubyzip to read) and
# the system `unzip` tool when it is available.
class ZipOutputStreamUnidirectionalTest < Minitest::Test
  # A sink that only supports writing. Any attempt to seek (or otherwise
  # position the stream) raises immediately, which proves the writer never
  # relies on random access. It deliberately does not implement `tell`, so
  # using it also proves the writer keeps its own byte counter.
  class WriteOnlySink
    attr_reader :chunks, :flushed

    def initialize
      @chunks = []
      @flushed = false
    end

    def write(data)
      @chunks << data.dup.force_encoding(Encoding::BINARY)
      data.bytesize
    end

    alias << write

    def binmode
      self
    end

    def flush
      @flushed = true
    end

    def seek(*)
      raise 'seek must never be called on a write-only sink'
    end
    alias pos= seek

    def rewind
      raise 'rewind must never be called on a write-only sink'
    end

    def string
      @chunks.join
    end

    def bytesize
      string.bytesize
    end
  end

  # Counts bytes flowing through without storing the bulk of them: data is
  # forwarded to the wrapped target (normally a null writer) and only a small
  # tail buffer is retained. `start_at` lets the counter pretend the archive
  # begins at an arbitrary (e.g. > 4GiB) offset so the Zip64 central
  # directory handling can be exercised cheaply.
  class CountingIO
    attr_reader :pos, :written

    def initialize(target, start_at: 0, keep_tail: 0)
      @target = target
      @pos = start_at
      @written = 0
      @keep_tail = keep_tail
      @tail = +''.b
    end

    alias tell pos

    def seek(*)
      raise 'this IO is write-only'
    end
    alias pos= seek

    def write(data)
      data = data.dup.force_encoding(Encoding::BINARY)
      @target.write(data)
      @pos += data.bytesize
      @written += data.bytesize
      if @keep_tail.positive?
        @tail << data
        overflow = @tail.bytesize - @keep_tail
        @tail.slice!(0, overflow) if overflow.positive?
      end
      data.bytesize
    end

    alias << write

    def binmode
      self
    end

    def flush; end

    attr_reader :tail
  end

  class NullWriter
    def write(data)
      data.bytesize
    end

    alias << write
  end

  # Raised when the hand-written verifier finds the archive malformed.
  class InvalidZip < StandardError; end

  # A minimal, standalone ZIP reader. It walks local file headers and data
  # descriptors itself (never using rubyzip to read), so a bug shared
  # between rubyzip's writer and reader could not make these checks pass.
  class IndependentZipVerifier
    LOCAL_SIG      = 0x04034b50
    DD_SIG         = 0x08074b50
    CDIR_SIG       = 0x02014b50
    ZIP64_EOCD_SIG = 0x06064b50
    LOCATOR_SIG    = 0x07064b50
    EOCD_SIG       = 0x06054b50
    DESCRIPTOR_LENGTH     = 4 + 4 + 4 + 4      # sig, crc, csize, size
    ZIP64_DESCRIPTOR_LENGTH = 4 + 4 + 8 + 8    # sig, crc, csize, size

    Entry = Struct.new(:name, :method, :gp_flags, :crc, :size,
                       :compressed_size, :local_header_offset, :content)

    attr_reader :entries

    def initialize(data)
      @data = data
      @entries = []
      parse!
    end

    private

    def parse!
      pos = 0
      while pos + 4 <= @data.bytesize
        sig = @data.byteslice(pos, 4).unpack1('V')
        case sig
        when LOCAL_SIG
          pos = parse_local_entry(pos)
        when CDIR_SIG
          pos = skip_cdir_entry(pos)
        when ZIP64_EOCD_SIG
          pos += 4 + 52
        when LOCATOR_SIG
          pos += 4 + 16
        when EOCD_SIG
          clen = @data.byteslice(pos + 20, 2).unpack1('v')
          pos += 22 + clen
          break
        else
          raise InvalidZip,
                format('unexpected signature 0x%08x at offset %d', sig, pos)
        end
      end
    end

    def parse_local_entry(pos)
      _vn, gp, method, _t, _d, _crc, csize, size, nlen, elen =
        @data.byteslice(pos + 4, 26).unpack('vvvvvVVVvv')
      name = @data.byteslice(pos + 30, nlen)
      extra = @data.byteslice(pos + 30 + nlen, elen)
      data_pos = pos + 30 + nlen + elen

      unless (gp & 0x08) == 0x08
        raise InvalidZip, "data descriptor flag missing for #{name}"
      end

      local_zip64 = (csize == 0xFFFFFFFF || size == 0xFFFFFFFF)
      # The markers may appear with zero placeholder values, which is fine;
      # only require the Zip64 extra record to be present at all.
      if local_zip64 && extra.bytesize.zero?
        raise InvalidZip, "zip64 local extra missing for #{name}"
      end

      descriptor = locate_descriptor(data_pos, local_zip64, method)
      raw = @data.byteslice(data_pos, descriptor - data_pos)

      crc, dd_csize, dd_size = read_descriptor(descriptor, local_zip64)

      content =
        case method
        when 0 then raw
        when 8 then inflate(raw)
        else raise InvalidZip, "unsupported compression method #{method}"
        end

      unless dd_size == content.bytesize
        raise InvalidZip,
              "size mismatch for #{name}: header says #{dd_size}, " \
              "content is #{content.bytesize}"
      end
      unless dd_csize == raw.bytesize
        raise InvalidZip,
              "compressed size mismatch for #{name}: header says " \
              "#{dd_csize}, data is #{raw.bytesize}"
      end
      unless Zlib.crc32(content) == crc
        raise InvalidZip, "crc mismatch for #{name}"
      end

      @entries << Entry.new(name, method, gp, crc, content.bytesize,
                            raw.bytesize, pos, content)

      descriptor + (local_zip64 ? ZIP64_DESCRIPTOR_LENGTH : DESCRIPTOR_LENGTH)
    end

    def inflate(raw)
      Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(raw)
    end

    # Find the data descriptor that terminates an entry. A candidate
    # signature is accepted only when (a) the CRC/sizes validate against the
    # data and (b) the descriptor is immediately followed by another local
    # header, a central directory header or the end-of-central-directory
    # record, which eliminates signatures that merely happen to occur inside
    # the entry data.
    def locate_descriptor(data_pos, zip64, method)
      sig_bytes = [DD_SIG].pack('V')
      descriptor_length = zip64 ? ZIP64_DESCRIPTOR_LENGTH : DESCRIPTOR_LENGTH
      scan = data_pos
      while (idx = @data.index(sig_bytes, scan))
        after = idx + descriptor_length
        if after > @data.bytesize || !followed_by_record?(after)
          scan = idx + 1
          next
        end

        crc, csize, size = read_descriptor(idx, zip64)
        raw = @data.byteslice(data_pos, idx - data_pos)
        if csize != raw.bytesize
          scan = idx + 1
          next
        end

        valid =
          case method
          when 0
            size == raw.bytesize && Zlib.crc32(raw) == crc
          when 8
            begin
              out = inflate(raw)
              out.bytesize == size && Zlib.crc32(out) == crc
            rescue Zlib::Error
              false
            end
          end
        return idx if valid

        scan = idx + 1
      end
      raise InvalidZip, 'missing or unparseable data descriptor'
    end

    def followed_by_record?(pos)
      return true if pos + 4 > @data.bytesize

      sig = @data.byteslice(pos, 4).unpack1('V')
      [LOCAL_SIG, CDIR_SIG, ZIP64_EOCD_SIG, LOCATOR_SIG, EOCD_SIG].include?(sig)
    end

    def read_descriptor(pos, zip64)
      # Layout: 4-byte signature, 4-byte CRC, then the two size fields
      # (32-bit each, or 64-bit each in the Zip64 form).
      crc = @data.byteslice(pos + 4, 4).unpack1('V')
      if zip64
        csize = @data.byteslice(pos + 8, 8).unpack1('Q<')
        size = @data.byteslice(pos + 16, 8).unpack1('Q<')
      else
        csize = @data.byteslice(pos + 8, 4).unpack1('V')
        size = @data.byteslice(pos + 12, 4).unpack1('V')
      end
      [crc, csize, size]
    end

    def skip_cdir_entry(pos)
      nlen, elen, clen = @data.byteslice(pos + 28, 6).unpack('vvv')
      pos + 46 + nlen + elen + clen
    end
  end

  def teardown
    ::Zip.reset!
  end

  def build_archive(sink = WriteOnlySink.new, &block)
    ::Zip::OutputStream.write_stream(sink, &block)
    sink
  end

  STORED_CONTENT = 'the quick brown fox jumps over the lazy dog'
  DEFLATED_CONTENT = 'deflate me, please! ' * 5000

  def write_mixed_archive(sink)
    build_archive(sink) do |zos|
      zos.put_next_entry('stored.txt', '', ::Zip::ExtraField.new,
                         ::Zip::Entry::STORED)
      # Provide the content in arbitrary chunk sizes.
      STORED_CONTENT.each_char.each_slice(7) { |c| zos.write(c.join) }

      zos.put_next_entry('deflated.txt')
      offset = 0
      while offset < DEFLATED_CONTENT.bytesize
        zos.write(DEFLATED_CONTENT.byteslice(offset, 4096))
        offset += 4096
      end

      zos.put_next_entry('empty.txt')
      zos.put_next_entry('empty/')
    end
  end

  def test_requires_io_like_target
    err = assert_raises(ArgumentError) do
      ::Zip::OutputStream.new('not/an/io', unidirectional: true)
    end
    assert_match(/unidirectional mode requires an IO object/, err.message)
  end

  def test_never_seeks_and_uses_data_descriptors
    sink = write_mixed_archive(WriteOnlySink.new)

    # The sink raises on any attempt to seek; reaching here proves no seek
    # happened.
    assert(sink.flushed, 'the sink should be flushed on close')

    data = sink.string
    positions = []
    scan = 0
    while (i = data.index("PK\x03\x04".b, scan))
      positions << i
      scan = i + 4
    end
    assert_equal(4, positions.length)

    positions.each do |pos|
      _vn, gp, _m, _t, _d, crc, csize, size =
        data.byteslice(pos + 4, 22).unpack('vvvvvVVV')
      assert_equal(0x08, gp & 0x08, "gp flag bit 3 at #{pos}")
      # The CRC is always a zero placeholder. The size fields are either
      # zero (no Zip64 placeholder) or the 0xFFFFFFFF marker with a zeroed
      # Zip64 extra field; the real values live in the data descriptor.
      assert_equal(0, crc, "local crc placeholder at #{pos}")
      assert([0, 0xFFFFFFFF].include?(csize), "local csize placeholder at #{pos}")
      assert([0, 0xFFFFFFFF].include?(size), "local size placeholder at #{pos}")
    end

    # Each entry is terminated with an explicit data descriptor signature.
    dd_count = 0
    scan = 0
    while (i = data.index([0x08074b50].pack('V'), scan))
      dd_count += 1
      scan = i + 4
    end
    assert_equal(4, dd_count)
  end

  def test_independent_verification_of_stored_deflate_and_empty_entries
    sink = write_mixed_archive(WriteOnlySink.new)
    zip = IndependentZipVerifier.new(sink.string)

    names = zip.entries.map(&:name)
    assert_equal(%w[stored.txt deflated.txt empty.txt empty/], names)

    by_name = zip.entries.to_h { |e| [e.name, e] }
    assert_equal(0, by_name['stored.txt'].method)
    assert_equal(STORED_CONTENT, by_name['stored.txt'].content)
    assert_equal(8, by_name['deflated.txt'].method)
    assert_equal(DEFLATED_CONTENT, by_name['deflated.txt'].content)
    assert_equal('', by_name['empty.txt'].content)
    assert_equal('', by_name['empty/'].content)
  end

  def test_rubyzip_itself_reads_the_streamed_archive_back
    sink = write_mixed_archive(WriteOnlySink.new)
    Tempfile.create(['streamed', '.zip']) do |f|
      f.binmode
      f.write(sink.string)
      f.flush

      ::Zip::File.open(f.path) do |zf|
        assert_equal(%w[stored.txt deflated.txt empty.txt empty/],
                     zf.entries.map(&:name))
        assert_equal(::Zip::Entry::STORED,
                     zf.get_entry('stored.txt').compression_method)
        assert_equal(::Zip::Entry::DEFLATED,
                     zf.get_entry('deflated.txt').compression_method)
        assert_equal(STORED_CONTENT, zf.read('stored.txt'))
        assert_equal(DEFLATED_CONTENT, zf.read('deflated.txt'))
        assert_equal('', zf.read('empty.txt'))
        assert_predicate(zf.get_entry('empty/'), :directory?)
      end
    end
  end

  def test_system_unzip_tool_accepts_the_archive
    unzip = find_executable('unzip')
    skip 'unzip not available' unless unzip

    sink = write_mixed_archive(WriteOnlySink.new)
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'a.zip')
      File.binwrite(path, sink.string)
      test_out = Dir.chdir(dir) { `#{unzip.shellescape} -t #{path.shellescape} 2>&1` }
      assert_predicate($?, :success?, test_out)
      assert_match(/No errors detected/, test_out)

      Dir.chdir(dir) do
        system(unzip, '-o', path, out: File::NULL, err: File::NULL)
      end
      assert_equal(STORED_CONTENT, File.read(File.join(dir, 'stored.txt')))
      assert_equal(DEFLATED_CONTENT, File.read(File.join(dir, 'deflated.txt')))
      assert File.directory?(File.join(dir, 'empty'))
    end
  end

  def test_entry_data_flows_through_before_close
    # The writer must push entry data through as it arrives instead of
    # buffering the whole archive until close.
    sink = WriteOnlySink.new
    zos = ::Zip::OutputStream.write_stream(sink)
    zos.put_next_entry('big.bin', '', ::Zip::ExtraField.new,
                       ::Zip::Entry::STORED)
    chunk = 'x' * 100_000
    streamed_early = false
    10.times do |i|
      zos.write(chunk)
      streamed_early ||= sink.bytesize >= (i + 1) * 100_000 - 100
    end
    assert(streamed_early, 'entry bytes should be visible at the sink before close')
    zos.close

    zip = IndependentZipVerifier.new(sink.string)
    assert_equal(1_000_000, zip.entries.first.size)
  end

  def test_close_does_not_close_the_target
    closed = false
    target = Object.new
    target.define_singleton_method(:write) { |d| d.bytesize }
    target.define_singleton_method(:close) { closed = true }
    target.define_singleton_method(:binmode) { self }

    ::Zip::OutputStream.write_stream(target) do |zos|
      zos.put_next_entry('a')
      zos.write('x')
    end
    refute(closed, 'the caller owns the target IO and must close it')
  end

  def test_duplicate_names_still_rejected
    sink = WriteOnlySink.new
    zos = ::Zip::OutputStream.write_stream(sink)
    zos.put_next_entry('same')
    zos.write('1')
    err = assert_raises(::Zip::EntryExistsError) do
      zos.put_next_entry('same')
    end
    zos.close
    assert_match(/same/, err.message)
  end

  def test_unknown_sizes_use_the_zip64_local_form
    sink = WriteOnlySink.new
    ::Zip::OutputStream.write_stream(sink) do |zos|
      zos.put_next_entry('small_a.txt')
      zos.write('a' * 100)
      zos.put_next_entry('small_b.txt')
      zos.write('b' * 100)
    end
    data = sink.string

    # Unknown streaming sizes with Zip64 support on -> local headers carry
    # the Zip64 size markers and a 20-byte Zip64 extra field.
    first = data.index("PK\x03\x04".b)
    _vn, _gp, _m, _t, _d, _crc, csize, size, _nlen, elen =
      data.byteslice(first + 4, 26).unpack('vvvvvVVVvv')
    assert_equal(0xFFFFFFFF, csize)
    assert_equal(0xFFFFFFFF, size)
    assert_equal(20, elen)

    # The data descriptors use the 24-byte Zip64 form.
    dd_pos = data.index([0x08074b50].pack('V'))
    refute_nil(dd_pos)
    _crc = data.byteslice(dd_pos + 4, 4).unpack1('V')
    dd_csize = data.byteslice(dd_pos + 8, 8).unpack1('Q<')
    dd_size = data.byteslice(dd_pos + 16, 8).unpack1('Q<')
    assert_equal(100, dd_size)
    assert_operator(dd_csize, :<=, 100)

    # And the central directory itself is plain 32-bit (sizes fit, offset
    # fits), i.e. no Zip64 extra leaks into cdir entries for small files.
    cdir_pos = data.index("PK\x01\x02".b)
    # cdir static header: crc at +16, csize at +20, size at +24, then name
    # length and extra length at +28/+30.
    c_csize, c_size, _nlen, c_elen =
      data.byteslice(cdir_pos + 20, 14).unpack('VVvv')
    assert_equal(100, c_size)
    assert_operator(c_csize, :<=, 100)
    assert_equal(0, c_elen)

    zip = IndependentZipVerifier.new(data)
    assert_equal(%w[small_a.txt small_b.txt], zip.entries.map(&:name))
  end

  def test_streaming_beyond_4gib_offset_via_counting_io
    # Simulate writing after 4 GiB + 64 bytes of prior output. The central
    # directory offset and EOCD must use the Zip64 forms; only the small
    # archive tail is retained and verified.
    base = 0x1_0000_0040
    io = CountingIO.new(NullWriter.new, start_at: base, keep_tail: 4096)

    ::Zip::OutputStream.write_stream(io) do |zos|
      zos.put_next_entry('stored_at_huge_offset.txt', '', ::Zip::ExtraField.new,
                         ::Zip::Entry::STORED)
      zos.write('hello from beyond 4GiB')
    end

    tail = io.tail

    assert(tail.include?([0x07064b50].pack('V')), 'zip64 eocd locator present')
    assert(tail.include?([0x06064b50].pack('V')), 'zip64 eocd record present')

    loc = tail.index([0x07064b50].pack('V'))
    _sig, _disk, zip64_eocd_offset, _disks =
      tail.byteslice(loc, 20).unpack('VVQ<V')
    assert(zip64_eocd_offset >= base, 'zip64 eocd offset beyond 4GiB')

    rec = tail.index([0x06064b50].pack('V'))
    _sig, _len, _vmade, _vneed, _disk, _cdisk, _n1, n2, _cdir_size, cdir_offset =
      tail.byteslice(rec, 56).unpack('VQ<vvVVQ<Q<Q<Q<')
    assert_equal(1, n2)
    assert(cdir_offset >= base, 'central directory offset beyond 4GiB')

    # The central directory entry encodes the large local-header offset in
    # its Zip64 extra field and sets the base offset field to the marker.
    cdir = tail.index([0x02014b50].pack('V'))
    _sig, _vm, _fs, _vn, _gp, _method, _t, _d, _crc, _cs, _sz, nlen, elen,
      _cl, _dn, _ia, _ea, off = tail.byteslice(cdir, 46).unpack('VCCvvvvvVVVvvvvvVV')
    assert_equal(0xFFFFFFFF, off, 'cdir local-header offset uses zip64 marker')
    # cdir static layout: name at +46, then extra fields.
    extra = tail.byteslice(cdir + 46 + nlen, elen)
    rel_offset = nil
    p = 0
    while p + 4 <= extra.bytesize
      id, len = extra.byteslice(p, 4).unpack('a2v')
      body = extra.byteslice(p + 4, len)
      if id == "\x01\x00".b
        rel_offset = body.unpack1('Q<')
      end
      p += 4 + len
    end
    refute_nil(rel_offset, 'cdir entry carries a zip64 extra field')
    assert(rel_offset >= base, 'zip64 relative header offset beyond 4GiB')
  end

  def test_entry_actually_beyond_4gib_offset_round_trips
    # End-to-end variant on a real sparse file: only the tail blocks occupy
    # disk, but both rubyzip and the system unzip must accept the archive.
    skip 'set FULL_ZIP64_TEST=1 for the sparse 4GiB round trip' unless
      ENV['FULL_ZIP64_TEST']

    Tempfile.create(['huge_offset', '.zip']) do |f|
      f.binmode
      f.seek(0x1_0000_0100)
      f.write("\0")
      f.flush

      ::Zip::OutputStream.write_stream(f) do |zos|
        zos.put_next_entry('real.txt', '', ::Zip::ExtraField.new,
                           ::Zip::Entry::STORED)
        zos.write('content beyond the barrier')
      end
      f.flush

      ::Zip::File.open(f.path) do |zf|
        assert_equal('content beyond the barrier', zf.read('real.txt'))
      end

      if (unzip = find_executable('unzip'))
        result = `#{unzip.shellescape} -t #{f.path.shellescape} 2>&1`
        assert_predicate($?, :success?, result)
      end
    end
  end

  def test_raises_for_known_large_size_without_zip64
    ::Zip.write_zip64_support = false
    sink = WriteOnlySink.new

    err = assert_raises(::Zip::Error) do
      ::Zip::OutputStream.write_stream(sink) do |zos|
        zos.put_next_entry(Zip::Entry.new(nil, 'big', size: 0x1_0000_0000))
      end
    end
    assert_match(/Zip64/, err.message)
  end

  def test_plain_32bit_streamed_archive_when_zip64_disabled
    # With Zip64 off, small entries of unknown size must still produce a
    # fully legal archive: plain 32-bit zeroed local headers plus 16-byte
    # data descriptors and no Zip64 records anywhere.
    ::Zip.write_zip64_support = false
    sink = WriteOnlySink.new
    ::Zip::OutputStream.write_stream(sink) do |zos|
      zos.put_next_entry('a.txt', '', ::Zip::ExtraField.new,
                         ::Zip::Entry::STORED)
      zos.write('plain stored')
      zos.put_next_entry('b.txt')
      zos.write('plain deflated')
    end
    data = sink.string

    refute(data.include?([0x06064b50].pack('V')), 'no zip64 eocd record')
    # A 0xFFFF disk/entry marker in the plain EOCD would also indicate
    # Zip64 use; the verifier round trip below already confirms otherwise.

    # Every local header is plain: zeroed size fields and no extra fields.
    scan = 0
    while (pos = data.index("PK\x03\x04".b, scan))
      _vn, _gp, _m, _t, _d, _crc, csize, size, _nlen, elen =
        data.byteslice(pos + 4, 26).unpack('vvvvvVVVvv')
      assert_equal(0, csize)
      assert_equal(0, size)
      assert_equal(0, elen)
      scan = pos + 4
    end

    # Every descriptor is the 16-byte 32-bit form (sig + three V fields).
    verifier = IndependentZipVerifier.new(data)
    assert_equal(%w[a.txt b.txt], verifier.entries.map(&:name))
    assert_equal('plain stored', verifier.entries.first.content)
    assert_equal('plain deflated', verifier.entries.last.content)
  end

  def test_raises_when_streamed_size_exceeds_limit_without_zip64
    # The entry starts under Zip64 (size unknown), but the amount of data
    # actually written crosses the 32-bit limit after Zip64 support has been
    # switched off, so finalization must refuse rather than emit a broken
    # archive.
    sink = WriteOnlySink.new
    zos = ::Zip::OutputStream.new(sink, unidirectional: true)
    zos.put_next_entry('grows')
    zos.write('x')
    ::Zip.write_zip64_support = false
    compressor = zos.instance_variable_get(:@compressor)
    def compressor.size
      0x1_0000_0000
    end

    err = assert_raises(::Zip::Error) do
      zos.close
    end
    assert_match(/32-bit limit/, err.message)
  end

  private

  def find_executable(name)
    exts = ENV['PATHEXT'] ? ENV['PATHEXT'].split(';') : ['']
    ENV['PATH'].split(File::PATH_SEPARATOR).each do |path|
      exts.each do |ext|
        exe = File.join(path, "#{name}#{ext}")
        return exe if File.executable?(exe) && !File.directory?(exe)
      end
    end
    nil
  end
end
