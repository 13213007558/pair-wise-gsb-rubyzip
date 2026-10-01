# frozen_string_literal: true

module Zip
  # The superclass for all rubyzip error types. Simply rescue this one if
  # you don't need to know what sort of error has been raised.
  class Error < StandardError; end

  # Error raised if an unsupported compression method is used.
  class CompressionMethodError < Error
    # The compression method that has caused this error.
    attr_reader :compression_method

    # Create a new CompressionMethodError with the specified incorrect
    # compression method.
    def initialize(method)
      super()
      @compression_method = method
    end

    # The message returned by this error.
    def message
      "Unsupported compression method: #{COMPRESSION_METHODS[@compression_method]}."
    end
  end

  # Error raised if there is a problem while decompressing an archive entry.
  class DecompressionError < Error
    # The error from the underlying Zlib library that caused this error.
    attr_reader :zlib_error

    # Create a new DecompressionError with the specified underlying Zlib
    # error.
    def initialize(zlib_error)
      super()
      @zlib_error = zlib_error
    end

    # The message returned by this error.
    def message
      "Zlib error ('#{@zlib_error.message}') while inflating."
    end
  end

  # Error raised when trying to extract an archive entry over an
  # existing file.
  class DestinationExistsError < Error
    # Create a new DestinationExistsError with the clashing destination.
    def initialize(destination)
      super()
      @destination = destination
    end

    # The message returned by this error.
    def message
      "Cannot create file or directory '#{@destination}'. " \
        'A file already exists with that name.'
    end
  end

  # Error raised when trying to add an entry to an archive where the
  # entry name already exists.
  class EntryExistsError < Error
    # Create a new EntryExistsError with the specified source and name.
    def initialize(source, name)
      super()
      @source = source
      @name = name
    end

    # The message returned by this error.
    def message
      "'#{@source}' failed. Entry #{@name} already exists."
    end
  end

  # Error raised when an entry name is invalid.
  class EntryNameError < Error
    # Create a new EntryNameError with the specified name.
    def initialize(name = nil)
      super()
      @name = name
    end

    # The message returned by this error.
    def message
      if @name.nil?
        'Illegal entry name. Names must have fewer than 65,536 characters.'
      else
        "Illegal entry name '#{@name}'. Names must not start with '/'."
      end
    end
  end

  # Error raised if an entry is larger on extraction than it is advertised
  # to be.
  class EntrySizeError < Error
    # The entry that has caused this error.
    attr_reader :entry

    # Create a new EntrySizeError with the specified entry.
    def initialize(entry)
      super()
      @entry = entry
    end

    # The message returned by this error.
    def message
      "Entry '#{@entry.name}' should be #{@entry.size}B, but is larger when inflated."
    end
  end

  class EntryNumberMismatchError < Error
    # Create a new EntryNumberMismatchError with the specified size and size in bytes.
    def initialize(size, size_in_bytes)
      super()
      @size = size
      @size_in_bytes = size_in_bytes
    end

    # The message returned by this error.
    def message
      "Zip consistency problem: an impossibly high number of entries (#{@size}) " \
        'is declared in this file, compared to the size of the central directory ' \
        "(#{@size_in_bytes} bytes)."
    end
  end

  # Error raised if a split archive is read. Rubyzip does not support reading
  # split archives.
  class SplitArchiveError < Error
    # The message returned by this error.
    def message
      'Rubyzip cannot extract from split archives at this time.'
    end
  end

  # Error raised when there is a problem reading a multi-volume (split or
  # spanned) archive: a required volume is missing, the volumes provided do
  # not match the archive, or a record is truncated at a volume boundary.
  class MultiVolumeError < Error
    # The number of the disk (volume) on which the problem was encountered,
    # if known. Disks are numbered from 0.
    attr_reader :disk_number

    # The offset within that disk at which the problem was encountered, if
    # known.
    attr_reader :disk_offset

    # Create a new MultiVolumeError. +disk_number+ and +disk_offset+ locate
    # the problem within the archive's volumes.
    def initialize(message, disk_number: nil, disk_offset: nil)
      super(message)
      @disk_number = disk_number
      @disk_offset = disk_offset
    end
  end

  # Error raised when a multi-volume archive references a disk (volume) that
  # the caller has not provided.
  class MissingDiskError < MultiVolumeError
    # Create a new MissingDiskError for +disk_number+, optionally with the
    # offset within that disk at which data was needed and the number of
    # disks that were provided.
    def initialize(disk_number, disk_offset: nil, provided_count: nil)
      message = +"Archive requires disk #{disk_number}"
      message << " (at offset #{disk_offset})" if disk_offset
      message << ", but only #{provided_count} disk(s) were provided" if provided_count
      super(message, disk_number: disk_number, disk_offset: disk_offset)
    end
  end

  # Error raised if there is not enough metadata for the entry to be streamed.
  class StreamingError < Error
    # The entry that has caused this error.
    attr_reader :entry

    # Create a new StreamingError with the specified entry.
    def initialize(entry)
      super()
      @entry = entry
    end

    # The message returned by this error.
    def message
      "The local header of this entry ('#{@entry.name}') does not contain " \
        'the correct metadata for `Zip::InputStream` to be able to ' \
        'uncompress it. Please use `Zip::File` instead of `Zip::InputStream`.'
    end
  end
end
