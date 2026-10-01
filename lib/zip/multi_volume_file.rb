# frozen_string_literal: true

require_relative 'multi_volume_io'

module Zip
  # Zip::MultiVolumeFile reads split or spanned zip archives whose data is
  # stored across several disks (volumes), without first concatenating the
  # volumes into a single file or buffer.
  #
  # It is a read-only counterpart to Zip::File: the central directory is
  # read across volume boundaries, and entries can be listed, read,
  # streamed and extracted, but the archive cannot be modified. All
  # offsets in the archive's central directory are interpreted relative to
  # the disk on which the referenced record starts, as the zip format
  # specifies for split and spanned archives.
  #
  # Volumes are supplied through a Zip::MultiVolumeIo, or directly as a
  # hash of disk number to seekable IO. Disk numbers start at 0 and follow
  # the "number of this disk" scheme of the zip format, so the volumes of
  # an archive split into +archive.z01+, +archive.z02+, ..., +archive.zip+
  # are disks 0, 1, ... in order:
  #
  #   disks = { 0 => File.open('archive.z01', 'rb'),
  #             1 => File.open('archive.zip', 'rb') }
  #   begin
  #     Zip::MultiVolumeFile.open(disks) do |zip|
  #       puts zip.read('hello.txt')
  #     end
  #   ensure
  #     disks.each_value(&:close)
  #   end
  #
  # To open volumes lazily, so that reading an entry only opens the volumes
  # that entry (and the central directory) actually live on, build the
  # Zip::MultiVolumeIo with an opener block:
  #
  #   io = Zip::MultiVolumeIo.new(2) do |disk_number|
  #     File.open(format('archive.z%02d', disk_number + 1), 'rb')
  #   end
  #   Zip::MultiVolumeFile.open(io) { |zip| ... }
  #
  # Ownership: Zip::MultiVolumeFile never closes the volume IOs it is
  # given, whether they are passed directly or produced by the opener
  # block; closing them remains the caller's responsibility.
  class MultiVolumeFile < File
    # Methods that would modify the archive are not supported: multi-volume
    # archives are read-only.
    READ_ONLY_METHODS = %i[
      add add_stored add_recursive remove rename replace mkdir
      get_output_stream comment=
    ].freeze

    # Opens a multi-volume archive for reading. +disks+ is either a
    # Zip::MultiVolumeIo or a hash of disk number (from 0) to seekable IO.
    # If a block is passed the archive is yielded to it and closed
    # afterwards, just as with Zip::File.open.
    def self.open(disks)
      zf = new(disks)
      return zf unless block_given?

      begin
        yield zf
      ensure
        zf.close
      end
    end

    # The Zip::File constructor is deliberately bypassed: a multi-volume
    # archive is read from a Zip::MultiVolumeIo, not from a single path.
    def initialize(disks) # rubocop:disable Lint/MissingSuper
      @multi_io = disks.kind_of?(::Zip::MultiVolumeIo) ? disks : ::Zip::MultiVolumeIo.new(disks)
      @name = @multi_io
      @create = false
      @cdir = ::Zip::CentralDirectory.new
      @cdir.read_from_stream(@multi_io)

      @restore_ownership     = DEFAULT_RESTORE_OPTIONS[:restore_ownership]
      @restore_permissions   = DEFAULT_RESTORE_OPTIONS[:restore_permissions]
      @restore_times         = DEFAULT_RESTORE_OPTIONS[:restore_times]
      @compression_level     = ::Zip.default_compression
      @suppress_extra_fields = false
    end

    # Block every method that would modify the archive.
    READ_ONLY_METHODS.each do |method_name|
      define_method(method_name) do |*|
        raise ::Zip::Error, 'Zip::MultiVolumeFile archives are read-only'
      end
    end
  end
end
