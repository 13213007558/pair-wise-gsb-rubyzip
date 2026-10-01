# frozen_string_literal: true

require 'forwardable'

require_relative 'dirtyable'

module Zip
  class CentralDirectory # :nodoc:
    extend Forwardable
    include Dirtyable

    END_OF_CD_SIG          = 0x06054b50
    ZIP64_END_OF_CD_SIG    = 0x06064b50
    ZIP64_EOCD_LOCATOR_SIG = 0x07064b50

    STATIC_EOCD_SIZE       = 22
    ZIP64_STATIC_EOCD_SIZE = 56
    ZIP64_EOCD_LOC_SIZE    = 20
    MAX_FILE_COMMENT_SIZE  = (1 << 16) - 1
    MAX_END_OF_CD_SIZE     =
      MAX_FILE_COMMENT_SIZE + STATIC_EOCD_SIZE + ZIP64_EOCD_LOC_SIZE

    attr_accessor :comment

    def_delegators :@entry_set,
                   :<<, :delete, :each, :entries, :find_entry, :glob,
                   :include?, :size

    mark_dirty :<<, :comment=, :delete

    def initialize(entries = EntrySet.new, comment = '') # :nodoc:
      super(dirty_on_create: false)
      @entry_set = entries.kind_of?(EntrySet) ? entries : EntrySet.new(entries)
      @comment   = comment
    end

    def read_from_stream(io)
      read_eocds(io)
      read_central_directory_entries(io)
    end

    def write_to_stream(io, suppress_extra_fields: false) # :nodoc:
      cdir_offset = io.tell
      @entry_set.each do |entry|
        entry.write_c_dir_entry(io, suppress_extra_fields: suppress_extra_fields)
      end
      eocd_offset = io.tell
      cdir_size = eocd_offset - cdir_offset
      if Zip.write_zip64_support &&
         (cdir_offset > 0xFFFFFFFF || cdir_size > 0xFFFFFFFF || @entry_set.size > 0xFFFF)
        write_64_e_o_c_d(io, cdir_offset, cdir_size)
        write_64_eocd_locator(io, eocd_offset)
      end
      write_e_o_c_d(io, cdir_offset, cdir_size)
    end

    # Reads the End of Central Directory Record (and the Zip64 equivalent if
    # needs be) and returns the number of entries in the archive. This is a
    # convenience method that avoids reading in all of the entry data to get a
    # very quick entry count.
    def count_entries(io)
      read_eocds(io)
      @size
    end

    def ==(other) # :nodoc:
      return false unless other.kind_of?(CentralDirectory)

      @entry_set.entries.sort == other.entries.sort && comment == other.comment
    end

    private

    def write_e_o_c_d(io, offset, cdir_size) # :nodoc:
      tmp = [
        END_OF_CD_SIG,
        0, # @numberOfThisDisk
        0, # @numberOfDiskWithStartOfCDir
        @entry_set ? [@entry_set.size, 0xFFFF].min : 0,
        @entry_set ? [@entry_set.size, 0xFFFF].min : 0,
        [cdir_size, 0xFFFFFFFF].min,
        [offset, 0xFFFFFFFF].min,
        @comment ? @comment.bytesize : 0
      ]
      io << tmp.pack('VvvvvVVv')
      io << @comment
    end

    def write_64_e_o_c_d(io, offset, cdir_size) # :nodoc:
      tmp = [
        ZIP64_END_OF_CD_SIG,
        44, # size of zip64 end of central directory record (excludes signature and field itself)
        VERSION_MADE_BY,
        VERSION_NEEDED_TO_EXTRACT_ZIP64,
        0, # @numberOfThisDisk
        0, # @numberOfDiskWithStartOfCDir
        @entry_set ? @entry_set.size : 0, # number of entries on this disk
        @entry_set ? @entry_set.size : 0, # number of entries total
        cdir_size, # size of central directory
        offset # offset of start of central directory in its disk
      ]
      io << tmp.pack('VQ<vvVVQ<Q<Q<Q<')
    end

    def write_64_eocd_locator(io, zip64_eocd_offset)
      tmp = [
        ZIP64_EOCD_LOCATOR_SIG,
        0, # number of disk containing the start of zip64 eocd record
        zip64_eocd_offset, # offset of the start of zip64 eocd record in its disk
        1 # total number of disks
      ]
      io << tmp.pack('VVQ<V')
    end

    def unpack_64_e_o_c_d(buffer) # :nodoc:
      _, # ZIP64_END_OF_CD_SIG. We know we have this at this point.
      size_of_zip64_e_o_c_d,
      _version_made_by,
      _version_needed_for_extract,
      @number_of_this_disk,
      @cdir_disk,
      _total_number_of_entries_in_cdir_on_this_disk,
      @size,
      size_in_bytes,
      @cdir_offset = buffer.unpack('VQ<vvVVQ<Q<Q<Q<')

      validate_size!(@size, size_in_bytes)

      zip64_extensible_data_size =
        size_of_zip64_e_o_c_d - ZIP64_STATIC_EOCD_SIZE + 12
      @zip64_extensible_data = if zip64_extensible_data_size.zero?
                                 ''
                               else
                                 buffer.slice(
                                   ZIP64_STATIC_EOCD_SIZE,
                                   zip64_extensible_data_size
                                 )
                               end
    end

    def unpack_64_eocd_locator(buffer) # :nodoc:
      _, # ZIP64_EOCD_LOCATOR_SIG. We know we have this at this point.
      zip64_eocd_disk,
      zip64_eocd_offset,
      total_disks = buffer.unpack('VVQ<V')

      [zip64_eocd_disk, zip64_eocd_offset, total_disks]
    end

    # Unpack the EOCD and return a boolean indicating whether this header is
    # complete without needing Zip64 extensions.
    def unpack_e_o_c_d(buffer) # :nodoc:
      _, # END_OF_CD_SIG. We know we have this at this point.
      @number_of_this_disk,
      @cdir_disk,
      total_number_of_entries_in_cdir_on_this_disk,
      @size,
      size_in_bytes,
      @cdir_offset,
      comment_length = buffer.unpack('VvvvvVVv')

      complete = !([@number_of_this_disk, @cdir_disk,
                    total_number_of_entries_in_cdir_on_this_disk, @size].any?(0xFFFF) ||
                    size_in_bytes == 0xFFFFFFFF || @cdir_offset == 0xFFFFFFFF)

      validate_size!(@size, size_in_bytes) if complete

      @comment = if comment_length.positive?
                   buffer.slice(STATIC_EOCD_SIZE, comment_length)
                 else
                   ''
                 end

      complete
    end

    def read_central_directory_entries(io) # :nodoc:
      # `StringIO` doesn't raise `EINVAL` if you seek beyond the current end,
      # so we need to catch that *and* query `io#eof?` here.
      eof = false
      begin
        seek_to_cdir(io)
      rescue Errno::EINVAL
        eof = true
      end
      raise Error, 'Zip consistency problem while reading central directory entry' if eof || io.eof?

      @entry_set = EntrySet.new
      @size.times do
        entry = Entry.read_c_dir_entry(io)
        break unless entry

        offset = if entry.zip64?
                   entry.extra[:zip64].relative_header_offset
                 else
                   entry.local_header_offset
                 end

        unless offset.nil?
          io_save = io.tell
          seek_to_local_header(io, entry, offset)
          entry.read_extra_field(read_local_extra_field(io), local: true)
          io.seek(io_save, IO::SEEK_SET)
        end

        @entry_set << entry
      end

      check_for_truncated_cdir!(io) if io.respond_to?(:seek_disk)
    end

    # A central directory record that is truncated at the end of the last
    # provided disk shows up as fewer entries than the end of central
    # directory record declared; report where the data ran out.
    def check_for_truncated_cdir!(io) # :nodoc:
      return if @entry_set.size >= @size

      position = io.tell
      raise MultiVolumeError.new(
        "The central directory is truncated: #{@size} entries were " \
        "declared, but the archive ended after #{@entry_set.size} " \
        "(at #{position})",
        disk_number: position.disk_number,
        disk_offset: position.offset
      )
    end

    # Seeks to the start of the central directory. For multi-volume
    # archives the EOCD's offset is relative to the disk on which the
    # central directory starts.
    def seek_to_cdir(io) # :nodoc:
      if io.respond_to?(:seek_disk)
        io.seek_disk(@cdir_disk || 0, @cdir_offset)
      else
        io.seek(@cdir_offset, IO::SEEK_SET)
      end
    end

    # Seeks to an entry's local header. For multi-volume archives the
    # central directory's offset is relative to the disk on which the
    # entry starts.
    def seek_to_local_header(io, entry, offset) # :nodoc:
      if io.respond_to?(:seek_disk)
        io.seek_disk(entry.disk_number_start, offset)
      else
        io.seek(offset, IO::SEEK_SET)
      end
    end

    def read_local_extra_field(io)
      buf = io.read(::Zip::LOCAL_ENTRY_STATIC_HEADER_LENGTH) || ''
      if buf.bytesize != ::Zip::LOCAL_ENTRY_STATIC_HEADER_LENGTH
        raise_truncated_local_header!(io) if io.respond_to?(:seek_disk)
        return ''
      end

      head, _, _, _, _, _, _, _, _, _, n_len, e_len = buf.unpack('VCCvvvvVVVvv')
      return '' unless head == ::Zip::LOCAL_ENTRY_SIGNATURE

      io.seek(n_len, IO::SEEK_CUR) # Skip over the entry name.
      io.read(e_len)
    end

    def raise_truncated_local_header!(io) # :nodoc:
      position = io.tell
      raise MultiVolumeError.new(
        "A local header is truncated: the archive ended at #{position} " \
        'before the whole header could be read',
        disk_number: position.disk_number,
        disk_offset: position.offset
      )
    end

    def read_eocds(io) # :nodoc:
      base_location, data = eocd_data(io)

      eocd_location = data.rindex([END_OF_CD_SIG].pack('V'))
      unless eocd_location
        if io.respond_to?(:disk_count)
          raise MultiVolumeError.new(
            'Zip end of central directory signature not found on the last ' \
            "provided disk (disk #{io.disk_count - 1}); a later disk may be missing",
            disk_number: io.disk_count - 1
          )
        end

        raise Error, 'Zip end of central directory signature not found'
      end

      # Parse the EOCD and return if it is complete without Zip64 extensions.
      unless unpack_e_o_c_d(data.slice(eocd_location..-1))
        # Need to read in the Zip64 EOCD locator and then the Zip64 EOCD.
        zip64_eocd_locator = data.rindex([ZIP64_EOCD_LOCATOR_SIG].pack('V'), eocd_location)
        unless zip64_eocd_locator
          raise Error, 'Zip64 end of central directory locator signature expected but not found'
        end

        zip64_eocd_disk, zip64_eocd_offset, @total_disks = unpack_64_eocd_locator(
          data.slice(zip64_eocd_locator..eocd_location)
        )

        # Do we already have the Zip64 EOCD in the data we've read?
        zip64_eocd_location = data.rindex([ZIP64_END_OF_CD_SIG].pack('V'), zip64_eocd_locator)

        zip64_eocd_data =
          if zip64_eocd_location
            # Yes.
            data.slice(zip64_eocd_location..zip64_eocd_locator)
          elsif io.respond_to?(:seek_disk)
            # No. On a multi-volume archive the locator's offset is relative
            # to the disk holding the Zip64 EOCD.
            io.seek_disk(zip64_eocd_disk, zip64_eocd_offset)
            read_zip64_e_o_c_d_record(io)
          else
            # No. Read its location from the locator and then read it in.
            unless zip64_eocd_offset
              raise Error, 'Zip64 end of central directory signature not found'
            end

            io.seek(zip64_eocd_offset, IO::SEEK_SET)
            io.read(base_location + zip64_eocd_locator - zip64_eocd_offset)
          end

        # Finally, unpack the Zip64 EOCD.
        unpack_64_e_o_c_d(zip64_eocd_data)
      end

      validate_disks!(io) if io.respond_to?(:disk_count)
    end

    # Reads a complete Zip64 end of central directory record from the
    # current position of +io+.
    def read_zip64_e_o_c_d_record(io) # :nodoc:
      header = io.read(12)
      unless header && header.bytesize == 12 &&
             header.unpack1('V') == ZIP64_END_OF_CD_SIG
        raise Error, 'Zip64 end of central directory signature not found'
      end

      # The record is the 12 bytes already read plus the recorded size of
      # the rest of the record (the fixed part is 44 bytes, then any
      # extensible data).
      remaining = header[4, 8].unpack1('Q<')
      raise Error, 'Zip64 end of central directory record is truncated' if remaining < 44

      header + io.read(remaining)
    end

    # For multi-volume archives, checks that the disks referenced by the
    # (Zip64) end of central directory records match the disks the caller
    # actually provided.
    def validate_disks!(io) # :nodoc:
      if @total_disks && @total_disks != io.disk_count
        raise MultiVolumeError.new(
          "The archive spans #{@total_disks} disk(s) according to its Zip64 " \
          "locator, but #{io.disk_count} disk(s) were provided",
          disk_number: @total_disks - 1
        )
      end

      if @number_of_this_disk != io.disk_count - 1
        raise MultiVolumeError.new(
          "The archive's central directory ends on disk #{@number_of_this_disk}, " \
          "but #{io.disk_count} disk(s) were provided (disks 0-#{io.disk_count - 1}). " \
          'A disk is missing, or the disks were provided in the wrong order',
          disk_number: @number_of_this_disk
        )
      end

      return unless @cdir_disk > @number_of_this_disk

      raise MultiVolumeError.new(
        "The central directory starts on disk #{@cdir_disk}, but the archive " \
        "only has disks 0-#{@number_of_this_disk}",
        disk_number: @cdir_disk
      )
    end

    def eocd_data(io)
      return multi_volume_eocd_data(io) if io.respond_to?(:seek_disk)

      begin
        io.seek(-MAX_END_OF_CD_SIZE, IO::SEEK_END)
      rescue Errno::EINVAL
        io.seek(0, IO::SEEK_SET)
      end

      [io.tell, io.read]
    end

    # Reads back from the end of a multi-volume archive, one disk at a
    # time, until the whole of the end of central directory record (plus
    # the Zip64 locator that may precede it) is held, so that only the
    # trailing disks of the archive are ever read.
    def multi_volume_eocd_data(io) # :nodoc:
      data = +''.b
      base_location = nil
      disk = io.disk_count - 1
      loop do
        break if disk.negative? || data.bytesize >= MAX_END_OF_CD_SIZE

        size = io.disk_size(disk)
        offset = [size - (MAX_END_OF_CD_SIZE - data.bytesize), 0].max
        io.seek_disk(disk, offset)
        data = io.read(size - offset) + data
        base_location = ::Zip::MultiVolumeIo::Position.new(disk, offset)
        break if complete_eocd_in?(data)

        disk -= 1
      end
      [base_location, data]
    end

    # Does +data+ hold a complete end of central directory record, together
    # with the Zip64 locator if the record indicates one is needed?
    def complete_eocd_in?(data) # :nodoc:
      location = data.rindex([END_OF_CD_SIG].pack('V'))
      return false unless location
      return false unless location + STATIC_EOCD_SIZE <= data.bytesize

      comment_length = data[location + 20, 2].unpack1('v')
      return false unless location + STATIC_EOCD_SIZE + comment_length <= data.bytesize

      fields = data[location + 4, 18].unpack('vvvvVV')
      zip64 = fields[0..3].any?(0xFFFF) ||
              fields[4] == 0xFFFFFFFF || fields[5] == 0xFFFFFFFF
      !zip64 || location >= ZIP64_EOCD_LOC_SIZE
    end

    def validate_size!(size, size_in_bytes)
      return if size * CDIR_ENTRY_STATIC_HEADER_LENGTH <= size_in_bytes

      error = EntryNumberMismatchError.new(size, size_in_bytes)
      raise error if Zip.validate_declared_number_of_entries

      warn error.message
    end
  end
end

# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
