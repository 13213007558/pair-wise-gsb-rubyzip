# frozen_string_literal: true

require 'forwardable'

##
module Zip
  # ZipOutputStream is the basic class for writing zip files. It is
  # possible to create a ZipOutputStream object directly, passing
  # the zip file name to the constructor, but more often than not
  # the ZipOutputStream will be obtained from a ZipFile (perhaps using the
  # ZipFileSystem interface) object for a particular entry in the zip
  # archive.
  #
  # A ZipOutputStream inherits IOExtras::AbstractOutputStream in order
  # to provide an IO-like interface for writing to a single zip
  # entry. Beyond methods for mimicking an IO-object it contains
  # the method put_next_entry that closes the current entry
  # and creates a new.
  #
  # There are two ways the archive bytes can be produced:
  #
  # - The normal, seekable modes (a file name, {OutputStream.open},
  #   {OutputStream.write_buffer}) keep the local file headers up to date by
  #   seeking back to them once each entry's CRC and sizes are known. This
  #   requires the underlying IO to support +seek+ and +tell+.
  # - The write-only, streaming mode ({OutputStream.write_stream} or
  #   `new(io, write_only: true)`) never seeks. Each local header is written
  #   with its CRC and sizes left unknown (general purpose bit 3 set), and a
  #   data descriptor record carrying the real values is written immediately
  #   after the entry data, before the next entry starts. The central
  #   directory is written when the stream is closed. The destination only
  #   needs to accept bytes (`#write` or `#<<`); the archive is not buffered
  #   in memory or in a temporary file.
  #
  # Archives produced in write-only mode have local headers that do not
  # contain sizes, so they cannot be parsed sequentially by
  # {InputStream}; they must be read with {File} or another Zip reader that
  # uses the central directory (such as the `unzip` command). Encryption
  # (other than the null encrypter) is not supported in write-only mode.
  #
  # Please refer to ZipInputStream for example code.
  #
  # java.util.zip.ZipOutputStream is the original inspiration for this
  # class.
  class OutputStream
    extend Forwardable
    include ::Zip::IOExtras::AbstractOutputStream

    def_delegators :@cdir, :comment, :comment=

    # Opens the indicated zip file. If a file with that name already
    # exists it will be overwritten.
    #
    # With +write_only: true+, +file_name+ must instead be an IO-like
    # object that accepts bytes (via +#write+ or +#<<+). The archive is
    # streamed to it without seeking: local headers use data descriptors
    # (general purpose bit 3) and the central directory is written on
    # {#close}. The destination itself is not closed by {#close}. See
    # {OutputStream.write_stream} for the block form.
    def initialize(file_name, stream: false, write_only: false, encrypter: nil,
                   suppress_extra_fields: false, **opts)
      super(**opts)
      @file_name = file_name
      @write_only = write_only
      if @write_only
        if stream
          raise ArgumentError, 'write_only and stream cannot both be used'
        end
        unless encrypter.nil? || encrypter.kind_of?(::Zip::NullEncrypter)
          raise ArgumentError,
                'write-only streaming does not support encrypted entries'
        end

        @output_stream = if @file_name.kind_of?(::Zip::IOExtras::WriteOnlyIO)
                           # Allows a counting IO with a simulated starting
                           # offset (for testing Zip64 boundaries) to be
                           # supplied directly.
                           @file_name
                         else
                           ::Zip::IOExtras::WriteOnlyIO.new(@file_name)
                         end
      elsif stream
        iostream = Zip::RUNNING_ON_WINDOWS ? @file_name : @file_name.dup
        iostream.reopen(@file_name)
        iostream.rewind
        @output_stream = iostream
      else
        @output_stream = ::File.new(@file_name, 'wb')
      end
      @cdir = ::Zip::CentralDirectory.new
      @compressor = ::Zip::NullCompressor.instance
      @encrypter = encrypter || ::Zip::NullEncrypter.new
      @suppress_extra_fields = suppress_extra_fields
      @closed = false
      @current_entry = nil
    end

    class << self
      # Same as #initialize but if a block is passed the opened
      # stream is passed to the block and closed when the block
      # returns.
      def open(file_name, encrypter: nil, suppress_extra_fields: false, **opts)
        unless block_given?
          return new(
            file_name,
            encrypter:             encrypter,
            suppress_extra_fields: suppress_extra_fields,
            **opts
          )
        end

        zos = new(file_name, stream: false, encrypter: encrypter,
                  suppress_extra_fields: suppress_extra_fields, **opts)
        yield zos
      ensure
        zos.close if zos
      end

      # Same as #open but writes to a filestream instead
      def write_buffer(io = ::StringIO.new, encrypter: nil, suppress_extra_fields: false, **opts)
        io.binmode if io.respond_to?(:binmode)
        zos = new(io, stream: true, encrypter: encrypter,
                  suppress_extra_fields: suppress_extra_fields, **opts)
        yield zos
        zos.close_buffer
      end

      # Writes the archive to +io+ in write-only, streaming mode: +io+ only
      # has to accept bytes (it needs a +#write+ or +#<<+ method; +seek+ and
      # +tell+ are not used). Nothing is buffered in memory or in a tempfile,
      # and +io+ itself is not closed when the block finishes (it is flushed
      # if it responds to +flush+).
      #
      #   File.open('out.zip', 'wb') do |file|
      #     Zip::OutputStream.write_stream(file) do |zos|
      #       zos.put_next_entry('first.txt')
      #       zos.write('Hello world!')
      #     end
      #   end
      def write_stream(io, encrypter: nil, suppress_extra_fields: false, **opts)
        zos = new(io, write_only: true, encrypter: encrypter,
                     suppress_extra_fields: suppress_extra_fields, **opts)
        return zos unless block_given?

        yield zos
        zos.close
      end
    end

    # Closes the stream and writes the central directory to the zip file.
    #
    # In write-only mode the underlying destination is not closed (the
    # caller owns it); it is flushed if it responds to +flush+.
    def close
      return if @closed

      finalize_current_entry
      update_local_headers unless @write_only
      write_central_directory
      @output_stream.close unless @write_only
      @output_stream.flush if @write_only
      @closed = true
    end

    # Closes the stream and writes the central directory to the zip file
    def close_buffer
      return @output_stream if @closed

      finalize_current_entry
      update_local_headers
      write_central_directory
      @closed = true
      @output_stream.flush
      @output_stream
    end

    # Closes the current entry and opens a new for writing.
    # +entry+ can be a ZipEntry object or a string.
    #
    # Raises Zip::EntryExistsError if an entry with the same name has
    # already been written to this stream, unless
    # Zip.allow_duplicate_entry_names is on.
    def put_next_entry(
      entry_name, comment = '', extra = ExtraField.new,
      compression_method = Entry::DEFLATED, level = Zip.default_compression
    )
      raise Error, 'zip stream is closed' if @closed

      new_entry =
        if entry_name.kind_of?(Entry) || entry_name.kind_of?(StreamableStream)
          entry_name
        else
          Entry.new(
            @file_name, entry_name.to_s, comment: comment, extra: extra,
            compression_method: compression_method, compression_level: level
          )
        end

      init_next_entry(new_entry)
      @current_entry = new_entry
    end

    def copy_raw_entry(entry) # :nodoc:
      raise Error, 'copy_raw_entry cannot be used with a write-only stream' if @write_only

      entry = entry.dup
      raise Error, 'zip stream is closed' if @closed
      raise Error, 'entry is not a ZipEntry' unless entry.kind_of?(Entry)

      finalize_current_entry
      check_duplicate_name(entry, 'copy_raw_entry')
      @cdir << entry
      src_pos = entry.local_header_offset
      entry.write_local_entry(@output_stream)
      @compressor = NullCompressor.instance
      entry.get_raw_input_stream do |is|
        is.seek(src_pos, IO::SEEK_SET)
        ::Zip::Entry.read_local_entry(is)
        IOExtras.copy_stream_n(@output_stream, is, entry.compressed_size)
      end
      @compressor = NullCompressor.instance
      @current_entry = nil
    end

    private

    def finalize_current_entry
      return unless @current_entry

      finish
      @output_stream << @encrypter.trailer unless @current_entry.directory?
      @current_entry.compressed_size = @output_stream.tell -
                                       @current_entry.local_header_offset -
                                       @current_entry.calculate_local_header_size
      @current_entry.size = @compressor.size
      @current_entry.crc = @encrypter.crc(@compressor.crc)
      if @write_only
        finalize_write_only_entry
      else
        @output_stream << @encrypter.data_descriptor(
          @current_entry.crc,
          @current_entry.compressed_size,
          @current_entry.size
        )
        @current_entry.gp_flags |= @encrypter.gp_flags unless @current_entry.directory?
      end
      @current_entry = nil
      @compressor = ::Zip::NullCompressor.instance
    end

    # Finish a single entry in write-only mode: verify the Zip64 policy and
    # emit the data descriptor the local header pointed at.
    def finalize_write_only_entry
      return if @current_entry.directory?

      entry = @current_entry
      unless entry.zip64?
        if entry.size >= 0xFFFFFFFF || entry.compressed_size >= 0xFFFFFFFF
          raise Error,
                'Entry is too large for a non-Zip64 archive (enable Zip.write_zip64_support)'
        end

        @output_stream << [
          SPLIT_FILE_SIGNATURE, entry.crc, entry.compressed_size, entry.size
        ].pack('VVVV')
        return
      end

      # The local header carries a Zip64 extra field, so per the ZIP
      # APPNOTE the data descriptor's two size fields are 64-bit; the CRC is
      # still 32-bit.
      @output_stream << [
        SPLIT_FILE_SIGNATURE, entry.crc, entry.compressed_size, entry.size
      ].pack('VVQ<Q<')
    end

    def init_next_entry(entry)
      finalize_current_entry
      check_duplicate_name(entry, 'put_next_entry')
      if @write_only && !entry.directory?
        # Bit 3 promises the local header carries no CRC or sizes: the real
        # values go in the data descriptor instead, so the local header is
        # written with them blank and the actual sizes come from the bytes
        # written.
        entry.gp_flags |= GP_FLAG_DATA_DESCRIPTOR
        entry.crc = 0
        entry.compressed_size = 0
        entry.local_header_blank_sizes = true
      end
      @encrypter.prepare_entry(entry)
      @cdir << entry
      entry.write_local_entry(@output_stream, suppress_extra_fields: @suppress_extra_fields)
      @encrypter.reset!
      @output_stream << @encrypter.header(entry.mtime) unless entry.directory?
      @compressor = get_compressor(entry)
    end

    def check_duplicate_name(entry, proc_name)
      return if Zip.allow_duplicate_entry_names
      return unless @cdir.include?(entry.name)

      raise EntryExistsError.new(proc_name, entry.name)
    end

    def get_compressor(entry)
      case entry.compression_method
      when Entry::DEFLATED
        ::Zip::Deflater.new(@output_stream, entry.compression_level, @encrypter)
      when Entry::STORED
        ::Zip::PassThruCompressor.new(@output_stream, @encrypter)
      else
        raise ::Zip::CompressionMethodError, entry.compression_method
      end
    end

    def update_local_headers
      pos = @output_stream.pos
      @cdir.each do |entry|
        @output_stream.pos = entry.local_header_offset
        entry.write_local_entry(@output_stream, suppress_extra_fields: @suppress_extra_fields,
                                                rewrite:               true)
      end
      @output_stream.pos = pos
    end

    def write_central_directory
      check_zip64_offsets! if @write_only
      @cdir.write_to_stream(@output_stream, suppress_extra_fields: @suppress_extra_fields)
    end

    # Guard the values that have to fit in the 32-bit fields of the classic
    # end-of-central-directory record when Zip64 support is turned off. The
    # central directory has not been written yet at this point, so its size
    # is summed from the entries' central directory records.
    def check_zip64_offsets!
      return if ::Zip.write_zip64_support

      if @cdir.size > 0xFFFF
        raise Error, 'Archive has too many entries for a non-Zip64 archive'
      end

      cdir_offset = @output_stream.tell
      cdir_size = @cdir.entries.sum(&:cdir_header_size)
      if cdir_offset > 0xFFFFFFFF
        raise Error, 'Archive is too large for a non-Zip64 archive (enable Zip.write_zip64_support)'
      end

      return unless cdir_size > 0xFFFFFFFF

      raise Error, 'Central directory is too large for a non-Zip64 archive ' \
                   '(enable Zip.write_zip64_support)'
    end

    protected

    def finish # :nodoc:
      @compressor.finish
    end

    public

    # Modeled after IO.<<
    def <<(data)
      @compressor << data
      self
    end
  end
end

# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
