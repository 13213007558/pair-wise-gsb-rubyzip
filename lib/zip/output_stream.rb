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
    # When +unidirectional+ is true the archive is written straight to
    # +file_name+ in one direction only: the target only has to support
    # writing (no +seek+ or +pos=+ is ever called on it). In this mode every
    # local file header is written with zero CRC/size fields and the
    # general-purpose "data descriptor" flag set; the real values follow in
    # a data descriptor after each entry's data, and the central directory
    # is written when the stream is closed. This makes it possible to
    # stream zip archives to write-only sinks such as HTTP response bodies.
    # The target IO is *not* closed by {#close} (only flushed, if it
    # supports that), since the caller owns it.
    def initialize(file_name, stream: false, encrypter: nil, suppress_extra_fields: false,
                   unidirectional: false, **opts)
      super(**opts)
      @file_name = file_name
      @unidirectional = unidirectional
      if @unidirectional
        unless @file_name.respond_to?(:write)
          raise ArgumentError, 'unidirectional mode requires an IO object'
        end

        @file_name.binmode if @file_name.respond_to?(:binmode)
        # Use the target directly when it can report its own position via
        # #tell (for example a counting IO simulating a large offset).
        # Otherwise wrap it in a byte counter; in either case nothing is
        # ever seeked or repositioned on the target.
        @output_stream =
          if @file_name.respond_to?(:tell)
            @file_name
          else
            WriteOnlyCountingIO.new(@file_name)
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

      # Opens a unidirectional zip stream that writes to +io+ without ever
      # seeking on it. +io+ only needs to respond to +write+ (+binmode+ and
      # +flush+ are used if available). Local headers use data descriptors
      # and the central directory is appended on close. The underlying +io+
      # is not closed. If a block is given it is yielded the stream and the
      # archive is finalized when the block returns; otherwise the stream
      # itself is returned and must be closed with #close.
      #
      #   Zip::OutputStream.write_stream(response.stream) do |zos|
      #     zos.put_next_entry('report.txt')
      #     zos.write(report_body)
      #   end
      def write_stream(io = nil, encrypter: nil, suppress_extra_fields: false, **opts)
        zos = new(io, unidirectional: true, encrypter: encrypter,
                  suppress_extra_fields: suppress_extra_fields, **opts)
        return zos unless block_given?

        begin
          yield zos
        ensure
          zos.close if zos
        end
      end
    end

    # Closes the stream and writes the central directory to the zip file.
    #
    # In unidirectional mode the underlying IO is not closed (it is only
    # flushed when it responds to +flush+); the caller owns it.
    def close
      return if @closed

      finalize_current_entry
      write_central_directory
      unless @unidirectional
        @output_stream.close
      end
      @closed = true
    end

    # Closes the stream and writes the central directory to the zip file
    def close_buffer
      return @output_stream if @closed

      finalize_current_entry
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

    def write_central_directory
      unless @unidirectional
        update_local_headers
      end
      @cdir.write_to_stream(@output_stream, suppress_extra_fields: @suppress_extra_fields)
      @output_stream.flush if @unidirectional && @output_stream.respond_to?(:flush)
    end

    def finalize_current_entry
      return unless @current_entry

      if @unidirectional
        finalize_unidirectional_entry
      else
        finish
        @output_stream << @encrypter.trailer unless @current_entry.directory?
        @current_entry.compressed_size = @output_stream.tell -
                                         @current_entry.local_header_offset -
                                         @current_entry.calculate_local_header_size
        @current_entry.size = @compressor.size
        @current_entry.crc = @encrypter.crc(@compressor.crc)
        @output_stream << @encrypter.data_descriptor(
          @current_entry.crc,
          @current_entry.compressed_size,
          @current_entry.size
        )
        @current_entry.gp_flags |= @encrypter.gp_flags unless @current_entry.directory?
        @current_entry = nil
        @compressor = ::Zip::NullCompressor.instance
      end
    end

    # Finalize the current entry when writing to a non-seekable stream. The
    # CRC and sizes are only known now, so they are written to a data
    # descriptor that follows the entry data. The local header's Zip64
    # placeholder (if any) is dropped unless the final sizes really need it,
    # since the central directory entry records the authoritative sizes.
    def finalize_unidirectional_entry
      entry = @current_entry
      used_zip64 = entry.local_header_uses_zip64

      finish
      @output_stream << @encrypter.trailer unless entry.directory?

      entry.compressed_size = @output_stream.tell -
                              entry.local_header_offset -
                              entry.local_header_size
      entry.size = @compressor.size
      entry.crc = @encrypter.crc(@compressor.crc)

      unless Zip.write_zip64_support ||
             (entry.size < 0xFFFFFFFF && entry.compressed_size < 0xFFFFFFFF)
        raise Error,
              "entry '#{entry.name}' exceeds the 32-bit limit but Zip64 support is disabled"
      end

      @output_stream << streaming_data_descriptor(entry, used_zip64)
      entry.gp_flags |= @encrypter.gp_flags unless entry.directory?

      # A Zip64 placeholder was written speculatively in the local header.
      # The central directory entry is authoritative and re-adds the extra
      # field only for sizes (or the header offset) that genuinely need it,
      # so drop the stale local placeholder here.
      entry.extra.delete(:zip64) unless
        entry.size >= 0xFFFFFFFF || entry.compressed_size >= 0xFFFFFFFF

      @current_entry = nil
      @compressor = ::Zip::NullCompressor.instance
    end

    # Build the data descriptor for an entry written to a non-seekable
    # stream. When the local header carried a Zip64 placeholder the
    # descriptor uses 64-bit size fields (per the ZIP format spec);
    # otherwise it is the regular 32-bit form. Both forms start with the
    # optional, but unambiguous, data descriptor signature.
    def streaming_data_descriptor(entry, used_zip64)
      # Signature and CRC are explicit V fields before the size fields: a
      # leading V directly followed by Q directives is packed incorrectly by
      # some Ruby versions, whereas VV followed by the size fields is
      # reliable everywhere.
      fields = [DATA_DESCRIPTOR_SIGNATURE, entry.crc,
                entry.compressed_size, entry.size]
      fields.pack(used_zip64 ? 'VVQ<Q<' : 'VVVV')
    end

    def init_next_entry(entry)
      finalize_current_entry
      check_duplicate_name(entry, 'put_next_entry')
      @encrypter.prepare_entry(entry)
      if @unidirectional
        entry.gp_flags |= GP_FLAG_DATA_DESCRIPTOR
      end
      @cdir << entry
      entry.write_local_entry(
        @output_stream,
        suppress_extra_fields: @suppress_extra_fields,
        streaming:             @unidirectional
      )
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

    # Internal wrapper around a write-only target used in unidirectional
    # mode when the target cannot report its own position. It forwards the
    # bytes straight through and keeps a running count of how many have been
    # written (so header offsets are known), and deliberately offers no
    # positioning methods at all.
    class WriteOnlyCountingIO
      attr_reader :pos

      def initialize(target)
        @target = target
        @pos = 0
      end

      alias tell pos

      def write(data)
        bytes = data.to_s
        @target.write(bytes)
        @pos += bytes.bytesize
        bytes.bytesize
      end

      alias << write

      def binmode
        @target.binmode if @target.respond_to?(:binmode)
        self
      end

      def flush
        @target.flush if @target.respond_to?(:flush)
      end
    end
  end
end

# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
