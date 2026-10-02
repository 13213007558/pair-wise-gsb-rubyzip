# frozen_string_literal: true

module Zip
  # MultipartReader presents the volumes of a split (multi-disk) zip
  # archive as a single flat, seekable, read-only stream, without
  # concatenating them in memory or on disk. It is the bridge between a
  # set of caller-supplied volume IOs and the rest of rubyzip, which
  # expects one seekable stream.
  #
  # Volumes are supplied as seekable IO-like objects (anything responding
  # to +seek+ and +read+; +size+ is used when available, otherwise the
  # size is found by seeking), keyed by their zero-based disk number. In
  # a PKZIP-style split archive the +.z01+ file is disk 0, +.z02+ is disk
  # 1, and so on, with the final +.zip+ file being the last disk:
  #
  #   reader = Zip::MultipartReader.new(
  #     0 => File.open('archive.z01', 'rb'),
  #     1 => File.open('archive.z02', 'rb'),
  #     2 => File.open('archive.zip', 'rb')
  #   )
  #
  # An Array of IOs in disk order is also accepted.
  #
  # Offsets stored in the archive's structures (the end of central
  # directory record, the zip64 locator and each central directory
  # entry) are relative to the start of the disk on which the structure
  # begins; #volume_offset translates such a (disk, offset) pair into a
  # flat offset in the concatenated archive.
  #
  # Ownership of the supplied IO objects stays with the caller: they are
  # never closed by this class (not even by #close) and they are never
  # written to. Volumes are repositioned before every read, so the caller
  # may use the same IO objects for other purposes between reads.
  class MultipartReader
    # Create a reader over +volumes+: a Hash of disk number => IO, an
    # Array of IOs in disk order, or nil if #add_volume will be used to
    # register the volumes instead.
    def initialize(volumes = nil)
      @volumes  = {}
      @prepared = false
      @pos      = 0
      @closed   = false

      case volumes
      when nil
        nil
      when Array
        if volumes.first.kind_of?(Array) # [disk_number, io] pairs.
          volumes.each { |disk, io| add_volume(disk, io) }
        else                             # IOs in disk order.
          volumes.each_with_index { |io, disk| add_volume(disk, io) }
        end
      else
        volumes.each { |disk, io| add_volume(disk, io) }
      end
    end

    # Register the IO for disk +disk_number+. Raises
    # DuplicateVolumeError if a volume has already been registered for
    # that disk number.
    def add_volume(disk_number, io)
      disk = Integer(disk_number)
      raise ArgumentError, 'disk numbers must not be negative' if disk.negative?
      raise DuplicateVolumeError, disk if @volumes.key?(disk)

      unless io.respond_to?(:seek) && io.respond_to?(:read)
        raise ArgumentError,
              "the volume IO for disk #{disk} must respond to seek and read"
      end

      @volumes[disk] = io
      @prepared = false
      self
    end

    # The number of volumes that have been registered.
    def volume_count
      @volumes.size
    end

    # Translate a per-disk offset (as found in the end of central
    # directory record, the zip64 end of central directory locator and
    # central directory entries) into a flat offset in the concatenated
    # archive. Raises MissingVolumeError if no volume was provided for
    # +disk_number+.
    def volume_offset(disk_number, offset_in_disk)
      prepare!
      base = @bases[disk_number]
      raise MissingVolumeError.new(disk_number, volume_count) if base.nil?

      base + offset_in_disk
    end

    # The total size of the concatenated archive, in bytes.
    def size
      prepare!
      @size
    end

    # Seeks to +offset+ (relative to +whence+) in the concatenated
    # archive. Like IO and StringIO, seeking before the start of the
    # stream raises Errno::EINVAL. Seeking beyond the end of the last
    # volume raises VolumeOffsetError.
    def seek(offset, whence = IO::SEEK_SET)
      check_open!
      prepare!

      target =
        case whence
        when IO::SEEK_SET then offset
        when IO::SEEK_CUR then @pos + offset
        when IO::SEEK_END then @size + offset
        else raise ArgumentError, "unknown seek whence: #{whence}"
        end

      raise Errno::EINVAL, 'seek to a negative position' if target.negative?
      raise VolumeOffsetError.new(target, @size) if target > @size

      @pos = target
      0
    end

    def tell
      @pos
    end
    alias pos tell

    def pos=(new_pos)
      seek(new_pos, IO::SEEK_SET)
    end

    def rewind
      seek(0, IO::SEEK_SET)
    end

    def eof?
      @pos >= size
    end
    alias eof eof?

    # Reads from the concatenated archive, transparently crossing volume
    # boundaries. Follows IO#read conventions: with no +length+ it reads
    # to the end of the archive; with a +length+ it returns nil if
    # already at the end, otherwise up to +length+ bytes.
    def read(length = nil, outbuf = nil)
      check_open!
      prepare!

      data =
        if length.nil?
          read_bytes(@size - @pos)
        else
          raise ArgumentError, "negative length #{length} given" if length.negative?
          return nil if length.positive? && @pos >= @size

          read_bytes([length, @size - @pos].min)
        end

      if outbuf
        outbuf.replace(data)
      else
        data
      end
    end

    # Marks this reader as closed. The caller's volume IOs are NOT
    # closed: ownership of them stays with the caller.
    def close
      @closed = true
      nil
    end

    def closed?
      @closed
    end

    def binmode
      self
    end

    private

    def initialize_copy(other)
      super
      @volumes = @volumes.dup
      @sizes   = @sizes.dup if @sizes
      @bases   = @bases.dup if @bases
    end

    def check_open!
      raise IOError, 'closed stream' if @closed
    end

    # Measure the volumes and check that the disk numbers form a
    # contiguous run starting at disk 0.
    def prepare!
      return if @prepared
      raise Error, 'no volumes have been provided' if @volumes.empty?

      @sizes = {}
      @bases = []
      total  = 0
      @volumes.keys.sort.each_with_index do |disk, expected|
        raise MissingVolumeError.new(expected, volume_count) unless disk == expected

        @bases << total
        @sizes[disk] = volume_size(@volumes[disk])
        total += @sizes[disk]
      end
      @size    = total
      @prepared = true
    end

    def volume_size(io)
      return io.size if io.respond_to?(:size)

      io.seek(0, IO::SEEK_END)
      io.tell
    end

    def read_bytes(count)
      return ''.b if count <= 0

      disk      = disk_for(@pos)
      result    = +''.b
      remaining = count
      while remaining.positive?
        io      = @volumes[disk]
        in_disk = @pos - @bases[disk]
        chunk   = [remaining, @sizes[disk] - in_disk].min
        io.seek(in_disk, IO::SEEK_SET)
        data = io.read(chunk)
        break if data.nil? || data.empty?

        result << data
        @pos      += data.bytesize
        remaining -= data.bytesize
        break if data.bytesize < chunk # Short read: a volume shrank?

        disk += 1
        break unless @volumes.key?(disk)
      end
      result
    end

    def disk_for(pos)
      disk = @bases.size - 1
      disk -= 1 while disk.positive? && @bases[disk] > pos
      disk
    end
  end
end
