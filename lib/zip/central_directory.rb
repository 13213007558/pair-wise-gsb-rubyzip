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
      @volume_io = false
    end

    def read_from_stream(io)
      @volume_io = io.respond_to?(:zip_volume_io?)
      @volume_io ? read_eocds_from_volumes(io) : read_eocds(io)
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
      @number_of_disk_with_start_of_cdir,
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
      zip64_eocd_disk, zip64_eocd_offset, total_disks = buffer.unpack('VVQ<V')

      [zip64_eocd_disk, zip64_eocd_offset, total_disks]
    end

    # Unpack the EOCD and return a boolean indicating whether this header is
    # complete without needing Zip64 extensions.
    def unpack_e_o_c_d(buffer) # :nodoc:
      _, # END_OF_CD_SIG. We know we have this at this point.
      @number_of_this_disk,
      @number_of_disk_with_start_of_cdir,
      total_number_of_entries_in_cdir_on_this_disk,
      @size,
      size_in_bytes,
      @cdir_offset,
      comment_length = buffer.unpack('VvvvvVVv')

      complete = !([@number_of_this_disk, @number_of_disk_with_start_of_cdir,
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
        if @volume_io
          io.seek([@number_of_disk_with_start_of_cdir, @cdir_offset], IO::SEEK_SET)
        else
          io.seek(@cdir_offset, IO::SEEK_SET)
        end
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

        # Reading the local headers up front would force every disk to be
        # opened, even for entries that are never accessed. For a
        # multi-volume archive the local header is read lazily when the
        # entry is opened instead.
        unless offset.nil? || @volume_io
          io_save = io.tell
          io.seek(offset, IO::SEEK_SET)
          entry.read_extra_field(read_local_extra_field(io), local: true)
          io.seek(io_save, IO::SEEK_SET)
        end

        @entry_set << entry
      end
    end

    def read_local_extra_field(io)
      buf = io.read(::Zip::LOCAL_ENTRY_STATIC_HEADER_LENGTH) || ''
      return '' unless buf.bytesize == ::Zip::LOCAL_ENTRY_STATIC_HEADER_LENGTH

      head, _, _, _, _, _, _, _, _, _, n_len, e_len = buf.unpack('VCCvvvvVVVvv')
      return '' unless head == ::Zip::LOCAL_ENTRY_SIGNATURE

      io.seek(n_len, IO::SEEK_CUR) # Skip over the entry name.
      io.read(e_len)
    end

    def read_eocds(io) # :nodoc:
      base_location, data = eocd_data(io)

      eocd_location = data.rindex([END_OF_CD_SIG].pack('V'))
      raise Error, 'Zip end of central directory signature not found' unless eocd_location

      # Parse the EOCD and return if it is complete without Zip64 extensions.
      return if unpack_e_o_c_d(data.slice(eocd_location..-1))

      # Need to read in the Zip64 EOCD locator and then the Zip64 EOCD.
      zip64_eocd_locator = data.rindex([ZIP64_EOCD_LOCATOR_SIG].pack('V'), eocd_location)
      unless zip64_eocd_locator
        raise Error, 'Zip64 end of central directory locator signature expected but not found'
      end

      # Do we already have the Zip64 EOCD in the data we've read?
      zip64_eocd_location = data.rindex([ZIP64_END_OF_CD_SIG].pack('V'), zip64_eocd_locator)

      zip64_eocd_data =
        if zip64_eocd_location
          # Yes.
          data.slice(zip64_eocd_location..zip64_eocd_locator)
        else
          # No. Read its location from the locator and then read it in.
          _, zip64_eocd_location, = unpack_64_eocd_locator(
            data.slice(zip64_eocd_locator..eocd_location)
          )
          unless zip64_eocd_location
            raise Error, 'Zip64 end of central directory signature not found'
          end

          io.seek(zip64_eocd_location, IO::SEEK_SET)
          io.read(base_location + zip64_eocd_locator - zip64_eocd_location)
        end

      # Finally, unpack the Zip64 EOCD.
      unpack_64_e_o_c_d(zip64_eocd_data)
    end

    # Reads the EOCD / Zip64 EOCD of a multi-volume archive. The EOCD and
    # Zip64 locator live on the last disk; the Zip64 EOCD is located via the
    # (disk, offset) pair in the locator. All offsets are relative to the
    # disk the record lives on. Only the last disk is opened by this method.
    def read_eocds_from_volumes(io)
      data = io.read_last_disk_tail
      last_disk = io.tell[0]

      eocd_location = data.rindex([END_OF_CD_SIG].pack('V'))
      unless eocd_location
        # The EOCD itself may start on the previous disk and straddle the
        # final disk boundary. Pull the minimum tail of the previous disk
        # needed to contain it (and the possible Zip64 records before it).
        previous_tail = io.read_previous_disk_tail(MAX_END_OF_CD_SIZE)
        data = previous_tail + data
        eocd_location = data.rindex([END_OF_CD_SIG].pack('V'))
        raise Error, 'Zip end of central directory signature not found' unless eocd_location
      end

      complete = unpack_e_o_c_d(data.slice(eocd_location..-1))

      locator_total_disks = read_zip64_eocd_from_volumes(io, data, eocd_location) unless complete

      validate_volume_numbers!(io, last_disk, locator_total_disks)
    end

    # Returns the total number of disks recorded by the Zip64 EOCD locator,
    # or nil if there is no Zip64 record.
    def read_zip64_eocd_from_volumes(io, data, eocd_location)
      locator_location = data.rindex([ZIP64_EOCD_LOCATOR_SIG].pack('V'), eocd_location)
      unless locator_location
        raise Error, 'Zip64 end of central directory locator signature expected but not found'
      end

      zip64_disk, zip64_offset, total_disks = unpack_64_eocd_locator(
        data.slice(locator_location..eocd_location)
      )

      io.seek([zip64_disk, zip64_offset], IO::SEEK_SET)
      header = io.read(ZIP64_STATIC_EOCD_SIZE)
      unless header.unpack1('V') == ZIP64_END_OF_CD_SIG
        raise Error, 'Zip64 end of central directory signature not found'
      end

      size_of_record = header.unpack1('x4Q<')
      extensible_size = size_of_record - (ZIP64_STATIC_EOCD_SIZE - 12)
      rest = extensible_size.positive? ? io.read(extensible_size) : +''
      unpack_64_e_o_c_d(header + rest)

      total_disks
    end

    # Verifies the disk numbers stored in the archive against the disks that
    # have actually been provided.
    def validate_volume_numbers!(io, last_disk, locator_total_disks = nil)
      provided = io.volume_set&.disk_count

      if provided && last_disk != provided - 1
        raise VolumeOrderError.new(
          disk_number: @number_of_this_disk,
          reason: "the end of central directory is on disk #{@number_of_this_disk} " \
                  "but #{provided} disks were provided (last disk is #{provided - 1})"
        )
      end

      if provided && locator_total_disks && locator_total_disks != provided
        raise VolumeOrderError.new(
          disk_number: last_disk,
          reason: "the archive declares #{locator_total_disks} disks but " \
                  "#{provided} were provided"
        )
      end

      if @number_of_this_disk && @number_of_this_disk != last_disk
        raise VolumeOrderError.new(
          disk_number: @number_of_this_disk,
          reason: "number of this disk is #{@number_of_this_disk} but the " \
                  "end of central directory was found on disk #{last_disk}"
        )
      end

      if provided && !@number_of_disk_with_start_of_cdir.nil? &&
          (@number_of_disk_with_start_of_cdir.negative? ||
           @number_of_disk_with_start_of_cdir >= provided)
        raise VolumeOrderError.new(
          disk_number: @number_of_disk_with_start_of_cdir,
          reason: 'the central directory starts on a disk that was not provided'
        )
      end
    end

    def eocd_data(io)
      begin
        io.seek(-MAX_END_OF_CD_SIZE, IO::SEEK_END)
      rescue Errno::EINVAL
        io.seek(0, IO::SEEK_SET)
      end

      [io.tell, io.read]
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
