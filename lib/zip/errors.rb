# frozen_string_literal: true

module Zip
  # The superclass for all rubyzip error types. Simply rescue this one if
  # you don't need to know what sort of error has been raised.
  class Error < StandardError; end

  # The superclass for errors raised while reading an archive that spans
  # multiple disks (a multi-volume or split archive). Every error of this
  # type reports the +disk_number+ (0-based) and, where it is known, the
  # +offset+ within that disk at which the problem was detected.
  class VolumeError < Error
    # The 0-based number of the disk the error relates to, or nil.
    attr_reader :disk_number

    # The byte offset within the disk, or nil.
    attr_reader :offset

    # Create a new VolumeError for the given disk number and offset.
    def initialize(disk_number: nil, offset: nil, message: nil, **)
      super(message)
      @disk_number = disk_number
      @offset = offset
      @custom_message = message
    end

    # The message returned by this error.
    def message
      location = "disk #{@disk_number.inspect}"
      location << " at offset #{@offset}" unless @offset.nil?
      "#{super} (#{location})".sub(/^ \(/, '(')
    end
  end

  # Error raised when a disk (volume) that the archive refers to cannot be
  # opened. With a +Zip::VolumeSet+ backed by an opener block this means the
  # opener returned nil (or raised).
  class MissingVolumeError < VolumeError
    # Create a new MissingVolumeError for the given disk number.
    def initialize(disk_number: nil, offset: nil, message: nil)
      super
    end

    # The message returned by this error.
    def message
      return super if @custom_message

      "Archive references disk #{disk_number}, which could not be opened. " \
        "(expected an opened, seekable IO; got nil or an error)"
    end
  end

  # Error raised when the disk numbers recorded in the archive do not match
  # the disks that have been provided: for example, the end of central
  # directory claims to live on a different disk from the last available
  # disk, the total disk count is wrong, or an entry points at a disk
  # outside the archive.
  class VolumeOrderError < VolumeError
    # Create a new VolumeOrderError.
    def initialize(disk_number: nil, offset: nil, reason: nil)
      @reason = reason
      super(disk_number: disk_number, offset: offset)
    end

    # The message returned by this error.
    def message
      reason = @reason || 'the disk numbering in the archive is inconsistent '
        'with the disks provided'
      "Volume order error: #{reason} (disk #{disk_number.inspect}" \
        "#{offset.nil? ? '' : ", offset #{offset}"})"
    end
  end

  # Error raised when a record (local header, compressed data or central
  # directory record) starts on a disk but runs past the end of that disk
  # and the next disk is missing, or otherwise ends inside the archive
  # without the following disk being present.
  class VolumeTruncationError < VolumeError
    # Create a new VolumeTruncationError.
    def initialize(disk_number: nil, offset: nil, what: 'archive data', message: nil)
      @what = what
      super
    end

    # The message returned by this error.
    def message
      "Unexpected end of disk #{disk_number} at offset #{offset} while " \
        "reading #{@what}: the record continues on the next disk but that " \
        'disk is missing or truncated.'
    end
  end

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
