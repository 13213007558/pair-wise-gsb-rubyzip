# frozen_string_literal: true

module Zip
  # MultiVolumeIo presents the disks (volumes) of a split or spanned zip
  # archive as a single logical, seekable read stream, without
  # concatenating the volumes into one file or buffer first.
  #
  # Disks are numbered from 0, matching the "number of this disk" scheme of
  # the zip format. Each disk contributes its bytes, in disk order, to the
  # logical stream, and records (local headers, entry data, central
  # directory entries, ...) may cross disk boundaries.
  #
  # Disks can be supplied eagerly, as a hash of disk number to IO:
  #
  #   io = Zip::MultiVolumeIo.new(0 => File.open('archive.z01', 'rb'),
  #                               1 => File.open('archive.zip', 'rb'))
  #
  # or lazily, with an opener block that is called the first time each disk
  # is actually needed, so that reading a single entry only touches the
  # disks that entry (and the central directory) live on:
  #
  #   io = Zip::MultiVolumeIo.new(2) do |disk_number|
  #     File.open(format('archive.z%02d', disk_number + 1), 'rb')
  #   end
  #
  # The disk IOs must be seekable: they have to respond to +seek+ and
  # +read+, and to +size+ (or support seeking to the end so the size can be
  # determined).
  #
  # Ownership: MultiVolumeIo never closes the IO objects it is given or
  # obtains from the opener block, not even when #close is called. The
  # caller retains ownership of every disk IO and is responsible for
  # closing them.
  class MultiVolumeIo
    # A position within a multi-volume archive: a disk number together with
    # an offset within that disk. Positions are returned by
    # MultiVolumeIo#tell and can be passed back to MultiVolumeIo#seek. They
    # are immutable value objects.
    class Position
      include Comparable

      # The disk (volume) number, numbered from 0.
      attr_reader :disk_number

      # The offset in bytes within the disk.
      attr_reader :offset

      def initialize(disk_number, offset)
        @disk_number = disk_number
        @offset = offset
        freeze
      end

      # Returns a new Position +bytes+ further into the same disk. The
      # result may point beyond the end of the disk; MultiVolumeIo#seek
      # normalises such positions onto the following disk(s).
      def +(bytes)
        Position.new(disk_number, offset + bytes)
      end

      def <=>(other)
        return nil unless other.kind_of?(Position)

        [disk_number, offset] <=> [other.disk_number, other.offset]
      end

      def zero?
        disk_number.zero? && offset.zero?
      end

      def to_s
        "disk #{disk_number}, offset #{offset}"
      end

      def inspect
        "#<#{self.class.name}: #{self}>"
      end
    end

    # The number of disks that make up the archive.
    attr_reader :disk_count

    # Pass either a hash of disk number to IO, or the number of disks
    # together with an opener block.
    def initialize(disks, &opener)
      if disks.kind_of?(Hash)
        raise ArgumentError, 'pass either a hash of disks, or a disk count with a block' if opener

        check_disk_hash!(disks)
        @disks = disks
        @disk_count = disks.size
      elsif disks.kind_of?(Integer) && disks.positive? && opener
        @disks = nil
        @disk_count = disks
        @opener = opener
      else
        raise ArgumentError,
              'pass either a hash of disks, or a disk count with an opener block'
      end

      @ios = {}
      @sizes = {}
      @position = Position.new(0, 0)
      @closed = false
    end

    def initialize_copy(other)
      super
      # Each copy resolves (and caches) the disk IOs itself, so that copies
      # have independent positions. With the hash form the same IO objects
      # are shared between copies, as with IO#dup.
      @ios = {}
      @sizes = @sizes.dup
    end

    # Seeks to +offset+ bytes within disk +disk_number+. If the offset is
    # beyond the end of that disk, the position rolls over onto the
    # following disk(s). Returns 0, like IO#seek.
    def seek_disk(disk_number, offset = 0)
      check_open!
      @position = normalize(disk_number, offset)
      0
    end

    # Seeks to +position+. With a Position, seeks to that disk and offset.
    # With an Integer and IO::SEEK_SET, seeks to that absolute offset in
    # the logical (concatenated) stream. IO::SEEK_CUR and IO::SEEK_END take
    # a relative byte count, as with IO#seek. Returns 0, like IO#seek.
    def seek(position, whence = IO::SEEK_SET)
      check_open!
      @position =
        case whence
        when IO::SEEK_SET
          if position.kind_of?(Position)
            normalize(position.disk_number, position.offset)
          else
            normalize(0, position)
          end
        when IO::SEEK_CUR
          normalize(@position.disk_number, @position.offset + position)
        when IO::SEEK_END
          normalize(last_disk_number, disk_size(last_disk_number) + position)
        else
          raise ArgumentError, "unknown seek whence: #{whence}"
        end
      0
    end

    # Returns the current position, as a Position value object (a disk
    # number plus an offset within that disk). Pass it back to #seek to
    # return to this position.
    def tell
      @position
    end
    alias pos tell

    # Reads +length+ bytes from the logical stream, crossing disk
    # boundaries as needed, and returns them as a binary string. With no
    # argument, reads to the end of the archive. Like IO#read, returns nil
    # when called at the end of the stream, and fewer than +length+ bytes
    # if the end of the last disk is reached first.
    def read(length = nil, outbuf = nil)
      check_open!
      raise ArgumentError, 'negative length' if length&.negative?

      data =
        if length.nil?
          read_to_end
        elsif length.zero?
          +''.b
        elsif eof?
          return nil
        else
          read_across_disks(length)
        end

      data.force_encoding(Encoding::BINARY)
      outbuf&.replace(data)
      outbuf || data
    end

    # Returns true when the position is at the end of the last disk.
    def eof?
      @position.disk_number >= last_disk_number &&
        @position.offset >= disk_size(last_disk_number)
    end

    # Alias for compatibility with Zip::File.open_buffer.
    alias eof eof?

    # Returns the size in bytes of disk +disk_number+. Raises
    # Zip::MissingDiskError for disks the caller did not provide.
    def disk_size(disk_number)
      @sizes.fetch(disk_number) do
        @sizes[disk_number] = measure_disk(disk_io(disk_number))
      end
    end

    # Returns the total size in bytes of the logical stream. Note that this
    # has to determine the size of every disk, so it may open every volume.
    def size
      (0..last_disk_number).sum { |disk_number| disk_size(disk_number) }
    end

    # Marks this stream closed. The disk IOs are *not* closed: they remain
    # the caller's responsibility (see the class documentation).
    def close
      @closed = true
      nil
    end

    def closed?
      @closed
    end

    private

    def check_disk_hash!(disks)
      unless disks.kind_of?(Hash) && !disks.empty? &&
             disks.keys.sort == (0...disks.size).to_a
        raise ArgumentError,
              'disks must be a hash of IOs keyed by consecutive disk numbers, starting at 0'
      end
    end

    def check_open!
      raise IOError, 'closed stream' if @closed
    end

    def last_disk_number
      @disk_count - 1
    end

    # Resolves the IO for +disk_number+, calling the opener block the first
    # time each disk is needed. Raises Zip::MissingDiskError for disks the
    # caller did not provide.
    def disk_io(disk_number)
      unless disk_number.kind_of?(Integer) && disk_number.between?(0, @disk_count - 1)
        raise MissingDiskError.new(disk_number, provided_count: @disk_count)
      end

      @ios.fetch(disk_number) do
        io = @opener ? @opener.call(disk_number) : @disks[disk_number]
        raise MissingDiskError.new(disk_number, provided_count: @disk_count) if io.nil?

        unless io.respond_to?(:read) && io.respond_to?(:seek)
          raise ArgumentError, "disk #{disk_number} IO must respond to read and seek"
        end

        @ios[disk_number] = io
      end
    end

    def measure_disk(io)
      size = io.size if io.respond_to?(:size)
      return size if size

      current = io.pos
      io.seek(0, IO::SEEK_END)
      size = io.pos
      io.seek(current, IO::SEEK_SET)
      size
    end

    # Converts a (possibly out of range) disk/offset pair into a valid
    # Position, rolling forwards onto the next disk(s) when the offset is
    # past the end of a disk, and backwards onto the previous disk(s) when
    # it is negative.
    def normalize(disk_number, offset)
      if offset.negative?
        while offset.negative?
          disk_number -= 1
          raise Errno::EINVAL, 'negative seek position' if disk_number.negative?

          offset += disk_size(disk_number)
        end
      else
        while offset >= disk_size(disk_number) && disk_number < last_disk_number
          offset -= disk_size(disk_number)
          disk_number += 1
        end
      end
      Position.new(disk_number, offset)
    end

    def read_to_end
      result = +''.b
      result << read_chunk until eof?
      result
    end

    def read_across_disks(length)
      result = +''.b
      result << read_chunk(length - result.bytesize) while result.bytesize < length && !eof?
      result
    end

    # Reads up to +max+ bytes (or to the end of the archive, when +max+ is
    # nil) from the current position, advancing the position. Never crosses
    # past the end of the last disk.
    def read_chunk(max = nil)
      return +''.b if eof?

      disk = @position.disk_number
      offset = @position.offset
      remaining_on_disk = disk_size(disk) - offset
      if remaining_on_disk <= 0
        @position = Position.new(disk + 1, 0)
        return read_chunk(max)
      end

      wanted = max ? [max, remaining_on_disk].min : remaining_on_disk
      io = disk_io(disk)
      io.seek(offset)
      chunk = io.read(wanted)
      got = chunk ? chunk.bytesize : 0
      if got < wanted
        raise MultiVolumeError.new(
          "Archive is truncated: disk #{disk} ended #{wanted - got} byte(s) " \
          "early at offset #{offset + got}",
          disk_number: disk,
          disk_offset: offset + got
        )
      end

      @position = Position.new(disk, offset + got)
      chunk.encoding == Encoding::BINARY ? chunk : chunk.b
    end
  end
end
