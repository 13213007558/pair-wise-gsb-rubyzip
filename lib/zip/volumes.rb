# frozen_string_literal: true

module Zip
  # A +Zip::VolumeSet+ describes an archive that is stored on more than one
  # disk (a split or multi-volume archive). Zip offsets in such an archive
  # are always relative to the start of the disk they live on, so the disks
  # must not simply be concatenated into one big file. Instead, a
  # +VolumeSet+ serves seekable IO objects to the reader on demand, keyed by
  # 0-based disk number.
  #
  # A +VolumeSet+ can be created in two ways:
  #
  # 1. From an enumerable of already-opened, seekable IO objects. The
  #    objects remain owned by the caller and are *never* closed by
  #    rubyzip:
  #
  #    ```
  #    volumes = ['part.z01', 'part.zip'].map { |n| File.open(n, 'rb') }
  #    begin
  #      Zip::File.open_volume_set(volumes) { |z| puts z.read('x.txt') }
  #    ensure
  #      volumes.each(&:close)
  #    end
  #    ```
  #
  # 2. Lazily, from an opener callable. It is called with the 0-based disk
  #    number *only when that disk is actually needed*, and must return an
  #    opened, seekable IO, or nil if the disk is unavailable. IO objects
  #    obtained this way are closed again (with +#close+) when the volume
  #    set is closed; pass a custom +closer+ to change that. With a block,
  #    {Zip::File.open_volume_set} closes the set automatically:
  #
  #    ```
  #    Zip::File.open_volume_set(
  #      disk_count: 3,
  #      opener: ->(disk_number) {
  #        File.open(format('part.z%02d', disk_number + 1), 'rb')
  #      }
  #    ) do |zip|
  #      puts zip.read('x.txt')
  #    end
  #    ```
  class VolumeSet
    # The total number of disks in the archive. The opener may be called
    # with any value from 0 up to +disk_count - 1+.
    attr_reader :disk_count

    # Creates a volume set from already-opened seekable IO objects. The IO
    # objects are not closed by this volume set; closing them is the
    # caller's responsibility.
    def self.from_ios(ios)
      new(ios)
    end

    # Creates a volume set that opens disks lazily via +opener+.
    #
    # @param disk_count [Integer] total number of disks.
    # @param opener [#call] called with a 0-based disk number when that
    #   disk is first needed; must return an opened seekable IO, or nil.
    # @param closer [#call] called with each opened IO on {#close}.
    #   Defaults to +->(io) { io.close }+.
    def self.open(disk_count, opener, closer: nil)
      new(nil, disk_count, opener, closer: closer)
    end

    # @!visibility private
    def initialize(ios = nil, disk_count = nil, opener = nil, closer: nil)
      if ios
        @ios = ios.to_a
        @disk_count = @ios.size
        @opener = nil
        @closer = nil
      else
        raise ArgumentError, 'disk_count must be positive' unless disk_count&.positive?

        @ios = Array.new(disk_count)
        @disk_count = disk_count
        @opener = opener
        @closer = closer || proc { |io| io.close }
      end
    end

    # Returns an opened seekable IO for +disk_number+, opening it lazily if
    # necessary.
    # @raise [Zip::MissingVolumeError] if the disk is unavailable.
    def io_for(disk_number)
      unless disk_number.is_a?(Integer) && disk_number >= 0 && disk_number < @disk_count
        raise MissingVolumeError.new(disk_number: disk_number)
      end

      return @ios[disk_number] unless @ios[disk_number].nil?

      open_volume(disk_number)
    end

    # Size in bytes of the given disk, opening it if necessary.
    # @!visibility private
    def disk_size(disk_number)
      io_for(disk_number).size
    end

    # Returns a new reader positioned at the given disk-local offset.
    # @!visibility private
    def reader(disk_number = @disk_count - 1, offset = 0)
      VolumeIO.new(self, disk_number, offset)
    end

    # Closes disks opened via an opener using the configured closer. IO
    # objects passed to the constructor are never closed.
    def close
      return unless @opener

      @ios.each { |io| @closer.call(io) if io }
      @ios = Array.new(@disk_count)
    end

    private

    def open_volume(disk_number)
      io = nil
      begin
        io = @opener.call(disk_number)
      rescue StandardError => e
        raise MissingVolumeError.new(
          disk_number: disk_number,
          message: "opener raised #{e.class}: #{e.message}"
        )
      end

      unless io
        raise MissingVolumeError.new(disk_number: disk_number)
      end

      @ios[disk_number] = io
    end
  end

  # An IO-like view over a {VolumeSet} that transparently crosses disk
  # boundaries. Positions are +[disk_number, offset_within_disk]+ pairs;
  # offsets stored in a zip archive are relative to the start of the disk
  # the record lives on, and this class never concatenates the disks.
  #
  # A +VolumeIO+ never closes the IO objects of its volume set.
  # @!visibility private
  class VolumeIO
    # The current [disk_number, offset_within_disk] pair.
    attr_reader :position
    # The backing volume set.
    attr_reader :volume_set

    def initialize(volume_set, disk_number, offset = 0)
      @volume_set = volume_set
      @position = [disk_number, check_offset(disk_number, offset)]
      @data_remaining = nil
    end

    def initialize_copy(other)
      @position = other.position.dup
      @data_remaining = other.instance_variable_get(:@data_remaining)
      super
    end

    # Seeks to a position. With +IO::SEEK_SET+ +amount+ must be an explicit
    # +[disk_number, offset_within_disk]+ pair (zip offsets are relative to
    # the start of the disk the record lives on). +IO::SEEK_CUR+ moves
    # +amount+ bytes relative to the current position and stays on the
    # current disk; +IO::SEEK_END+ moves relative to the end of the final
    # disk.
    def seek(amount, whence = IO::SEEK_SET)
      case whence
      when IO::SEEK_SET
        unless amount.is_a?(Array) && amount.length == 2
          raise ArgumentError,
                'multi-volume SEEK_SET requires a [disk_number, offset] pair'
        end

        disk, offset = amount
        @position = [disk, check_offset(disk, offset)]
        @data_remaining = nil
      when IO::SEEK_CUR
        disk, offset = @position
        target = offset + amount.to_i
        raise VolumeOrderError.new(disk_number: disk) if target.negative?

        @position = [disk, check_offset(disk, target)]
      when IO::SEEK_END
        disk = @volume_set.disk_count - 1
        target = @volume_set.disk_size(disk) + amount.to_i
        @position = [disk, check_offset(disk, target)]
        @data_remaining = nil
      else
        raise ArgumentError, "invalid whence #{whence}"
      end
      0
    end

    # Returns the current [disk_number, offset_within_disk] pair.
    def tell
      @position
    end
    alias pos tell

    # Reads up to +length+ bytes, continuing onto later disks as needed.
    # Raises {Zip::VolumeTruncationError} if a record runs past the end of
    # a disk while more bytes were expected before the entry-data bound.
    def read(length = nil, outbuf = nil)
      result = +''.b
      remaining_request = length

      until finished_reading?(remaining_request, result.bytesize)
        disk, offset = @position
        disk_size = @volume_set.disk_size(disk)
        available = disk_size - offset
        if @data_remaining
          available = [available, @data_remaining].min
        end
        want = if remaining_request.nil?
                 available
               else
                 [available, remaining_request - result.bytesize].min
               end
        break if want <= 0

        io = @volume_set.io_for(disk)
        io.seek(offset, IO::SEEK_SET)
        chunk = io.read(want) || +''.b
        short_read = chunk.bytesize < want
        result << chunk
        @data_remaining -= chunk.bytesize if @data_remaining
        offset += chunk.bytesize
        if short_read && record_still_incomplete?(remaining_request, result.bytesize)
          raise VolumeTruncationError.new(
            disk_number: disk, offset: offset,
            what: "archive data (needed #{want} bytes, " \
                  "got #{chunk.bytesize})"
          )
        end

        if offset >= disk_size && disk < @volume_set.disk_count - 1
          disk += 1
          offset = 0
        end
        @position = [disk, offset]
      end

      verify_read_length!(remaining_request, result.bytesize)

      outbuf&.replace(result)
      return nil if remaining_request.nil? && result.empty?

      result
    end

    # True at the end of the archive, or once the bounded entry data has
    # been fully consumed.
    def eof?
      at_data_bound? || (@data_remaining.nil? && position_at_end_of_set?)
    end
    alias eof eof?

    # Bounds reading of an entry's compressed data to exactly +bytes+ bytes
    # counted from the current position, crossing disk boundaries as needed.
    # An entry ending exactly on a boundary therefore never reads the next
    # entry or opens an unnecessary disk; a disk that ends before all the
    # bytes have been read surfaces as a truncation.
    def bound_data!(bytes)
      @data_remaining = bytes
      self
    end

    # @return [String] the whole content of the final disk (it is the only
    # disk that needs to be opened to locate the end-of-central-directory
    # record). The reader is positioned at the start of the final disk.
    def read_last_disk_tail
      last = @volume_set.disk_count - 1
      io = @volume_set.io_for(last)
      io.seek(0, IO::SEEK_SET)
      @position = [last, 0]
      io.read || +''
    end

    # Returns up to +bytes+ bytes immediately preceding the start of the
    # final disk, i.e. the tail of the previous disk. Used only when the
    # EOCD signature straddles the final disk boundary.
    def read_previous_disk_tail(bytes)
      previous = @volume_set.disk_count - 2
      return +''.b if previous.negative?

      size = @volume_set.disk_size(previous)
      start = [0, size - bytes].max
      io = @volume_set.io_for(previous)
      io.seek(start, IO::SEEK_SET)
      io.read(size - start) || +''.b
    end

    # The volume set owns the underlying IO objects, so this is a no-op.
    def close
      nil
    end

    # Marker used to detect a multi-volume reader without checking class.
    def zip_volume_io?
      true
    end

    private

    def check_offset(disk_number, offset)
      if offset.negative?
        raise VolumeOrderError.new(
          disk_number: disk_number, offset: offset,
          reason: 'negative offset within disk'
        )
      end

      return offset if offset <= @volume_set.disk_size(disk_number)

      raise VolumeTruncationError.new(
        disk_number: disk_number, offset: offset,
        what: 'the archive'
      )
    end

    def finished_reading?(requested_length, read_bytes)
      return true if at_data_bound?
      return true if requested_length && read_bytes >= requested_length
      return true if @data_remaining.nil? && position_at_end_of_set?

      false
    end

    def at_data_bound?
      @data_remaining && @data_remaining <= 0
    end

    # True when a record read has been short-changed on a disk while the
    # record is not complete yet. This is always a truncation: record reads
    # (local headers, central directory entries) know their exact length,
    # and bounded entry-data reads are incomplete while bytes remain.
    def record_still_incomplete?(requested_length, read_bytes)
      return false if read_bytes >= requested_length

      true
    end

    def position_at_end_of_set?
      disk, offset = @position
      disk == @volume_set.disk_count - 1 &&
        offset >= @volume_set.disk_size(disk)
    end

    # Fixed-length reads must always be satisfied (headers, etc.). When entry
    # data is bounded, a short read is acceptable only once the whole bounded
    # data has been consumed; ending the archive (or hitting a disk that is
    # shorter than declared) with data still outstanding is a truncation.
    def verify_read_length!(requested_length, read_bytes)
      return unless requested_length
      return if read_bytes >= requested_length
      return if at_data_bound?

      raise truncation_error(requested_length, read_bytes)
    end

    def truncation_error(expected, got)
      disk, offset = @position
      VolumeTruncationError.new(
        disk_number: disk, offset: offset,
        what: "archive data (needed #{expected} bytes, got #{got})"
      )
    end
  end
end
