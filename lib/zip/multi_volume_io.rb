# frozen_string_literal: true

module Zip
  # MultiVolumeIO presents the separate volumes (disks) of a split or
  # spanned zip archive - the `.z01`, `.z02`, ... `.zip` files produced by
  # tools such as Info-ZIP's `zip -s` - as a single continuous, seekable,
  # read-only, IO-like object. This allows a multi-volume archive to be
  # read through Zip::File.open_multivolume (or Zip::File.open_buffer)
  # without first concatenating the volumes into one large file.
  #
  # Volumes are supplied by the caller, keyed by disk number (an Integer,
  # starting at 0 for the first volume). Each volume must be a seekable
  # IO-like object (responding to `read` and `seek`), such as a ::File or
  # StringIO opened in binary mode:
  #
  #   volumes = {
  #     0 => ::File.open('archive.z01', 'rb'),
  #     1 => ::File.open('archive.z02', 'rb'),
  #     2 => ::File.open('archive.zip', 'rb')
  #   }
  #   Zip::File.open_multivolume(volumes) do |zip|
  #     zip.each { |entry| puts entry.name }
  #   end
  #
  # Ownership of the volume IOs stays with the caller: they are never
  # closed by this class (or by Zip::File), not even when #close is
  # called - #close only marks this virtual IO itself as closed. The
  # caller is responsible for closing the volume IOs when it is done with
  # them.
  #
  # The offsets stored in a split archive (in the central directory, the
  # EOCD record and the Zip64 records) are absolute, counted from the
  # start of the first disk, so this class simply concatenates the volumes
  # in disk number order. Anything at or beyond a disk that has not been
  # provided cannot be addressed: such reads and seeks raise
  # MissingVolumeError. Offsets beyond the end of the provided data raise
  # VolumeOffsetError, and adding two volumes for the same disk number
  # raises DuplicateVolumeError.
  class MultiVolumeIO
    # Create a new MultiVolumeIO. `volumes`, if given, maps disk numbers
    # (Integers, starting at 0) to seekable IO objects. Further volumes
    # can be added with #add_volume.
    def initialize(volumes = nil)
      @volumes  = {}
      @segments = nil
      @pos      = 0
      @closed   = false
      volumes&.each { |disk_number, io| add_volume(disk_number, io) }
    end

    def initialize_copy(other) # :nodoc:
      super
      @volumes = @volumes.dup
    end

    # Add a volume for `disk_number`. `io` must be a seekable IO-like
    # object (responding to `read` and `seek`) and remains owned by the
    # caller. Raises DuplicateVolumeError if a volume has already been
    # added for this disk number.
    def add_volume(disk_number, io)
      disk_number = Integer(disk_number)
      if disk_number.negative?
        raise ArgumentError, "disk number must not be negative: #{disk_number}"
      end
      raise DuplicateVolumeError, disk_number if @volumes.key?(disk_number)
      unless io.respond_to?(:read) && io.respond_to?(:seek)
        raise ArgumentError, "volume IO must respond to read and seek: #{io.inspect}"
      end

      @volumes[disk_number] = io
      @segments = nil
      self
    end

    # The volume IO for `disk_number`, or nil if none has been added.
    def [](disk_number)
      @volumes[disk_number]
    end

    # True if a volume has been added for `disk_number`.
    def volume?(disk_number)
      @volumes.key?(disk_number)
    end

    # The disk numbers of the volumes that have been added, in order.
    def disk_numbers
      @volumes.keys.sort
    end

    # The number of volumes that have been added.
    def volume_count
      @volumes.size
    end

    # The lowest disk number, within the range spanned by the provided
    # disk numbers, for which no volume has been added - or 0 if no
    # volumes have been added at all. Returns nil if the provided volumes
    # form an unbroken sequence starting at disk 0 (which says nothing
    # about whether the archive continues past the last provided disk).
    def first_missing_disk
      max = @volumes.keys.max
      return 0 if max.nil?

      (0..max).find { |disk_number| !@volumes.key?(disk_number) }
    end

    # The disk number on which `offset` (absolute, counted from the start
    # of the first disk) falls, or nil if it is beyond the addressable
    # data.
    def disk_number_for_offset(offset)
      segment = segment_for(offset)
      segment && segment[0]
    end

    # The total size, in bytes, of the addressable data. Only an unbroken
    # sequence of volumes starting at disk 0 can be addressed - anything
    # beyond a missing disk is unreachable - so this is the sum of the
    # sizes of that sequence.
    def size
      segment = segments.last
      segment ? segment[1] + segment[2] : 0
    end

    # Seeks to `offset` (absolute, counted from the start of the first
    # disk) according to `whence`, as IO#seek does. Seeking onto a disk
    # that has not been provided raises MissingVolumeError; seeking beyond
    # the end of the provided data raises VolumeOffsetError; seeking to a
    # negative position raises Errno::EINVAL, as IO#seek does.
    def seek(offset, whence = ::IO::SEEK_SET)
      check_open
      target =
        case whence
        when ::IO::SEEK_SET then offset
        when ::IO::SEEK_CUR then @pos + offset
        when ::IO::SEEK_END then size + offset
        else
          raise ArgumentError, "unknown seek whence: #{whence}"
        end
      raise Errno::EINVAL, "Invalid argument - seek to #{target}" if target.negative?

      check_offset!(target) if target > size
      @pos = target
      0
    end

    # The current position, as an absolute offset from the start of the
    # first disk.
    def tell
      check_open
      @pos
    end
    alias pos tell

    def pos=(position) # :nodoc:
      seek(position, ::IO::SEEK_SET)
    end

    # Seeks back to the start of the first disk.
    def rewind
      seek(0, ::IO::SEEK_SET)
    end

    # True if the current position is at the end of the addressable data.
    def eof?
      check_open
      @pos >= size
    end
    alias eof eof?

    # Reads `length` bytes (or all remaining bytes, if `length` is nil),
    # transparently crossing volume boundaries, as IO#read does. Returns
    # nil if there is no more data and `length` was given. Reading from a
    # position whose data is on a disk that has not been provided raises
    # MissingVolumeError.
    def read(length = nil, outbuf = nil)
      check_open
      raise ArgumentError, "negative length #{length}" if length&.negative?

      data =
        if length.nil?
          read_bytes(size - @pos)
        elsif length.zero? || @pos < size
          read_bytes([length, size - @pos].min)
        else
          check_missing_volume!
          nil
        end

      if outbuf && data
        outbuf.replace(data)
      else
        data
      end
    end

    # A no-op, for IO compatibility - the volume IOs are expected to
    # already be in binary mode.
    def binmode
      self
    end

    # Marks this virtual IO as closed. The volume IOs are NOT closed:
    # ownership of them remains with the caller.
    def close
      @closed = true
      nil
    end

    def closed?
      @closed
    end

    private

    def check_open
      raise IOError, 'closed stream' if @closed
    end

    def check_offset!(offset)
      missing = first_missing_disk
      raise MissingVolumeError, missing if missing

      raise VolumeOffsetError, offset
    end

    def check_missing_volume!
      missing = first_missing_disk
      raise MissingVolumeError, missing if missing
    end

    # The addressable extents of the volumes, as [disk_number, start,
    # length] triples, for the unbroken sequence of disks starting at
    # disk 0.
    def segments
      @segments ||= begin
        segs = []
        start = 0
        disk_number = 0
        while (io = @volumes[disk_number])
          length = volume_size(io)
          segs << [disk_number, start, length]
          start += length
          disk_number += 1
        end
        segs
      end
    end

    def segment_for(offset)
      segments.find { |_, start, length| offset >= start && offset < start + length }
    end

    def volume_size(io)
      return io.size if io.respond_to?(:size)

      io.seek(0, ::IO::SEEK_END)
      io.tell
    end

    # Reads exactly `length` bytes, starting at the current position,
    # splicing data across volume boundaries as needed. The caller must
    # ensure that the requested range is addressable.
    def read_bytes(length)
      data = (+'').b
      remaining = length
      while remaining.positive?
        segment = segment_for(@pos)
        raise VolumeOffsetError, @pos unless segment

        disk_number, start, seg_length = segment
        offset = @pos - start
        want = [remaining, seg_length - offset].min
        data << read_from_volume(disk_number, offset, want)
        @pos += want
        remaining -= want
      end
      data
    end

    def read_from_volume(disk_number, offset, length)
      io = @volumes[disk_number]
      io.seek(offset, ::IO::SEEK_SET)
      chunk = io.read(length)
      unless chunk && chunk.bytesize == length
        raise ::Zip::Error,
              "Volume (disk) #{disk_number} is truncated: could not read " \
              "#{length} bytes at offset #{offset}."
      end

      chunk
    end
  end
end
