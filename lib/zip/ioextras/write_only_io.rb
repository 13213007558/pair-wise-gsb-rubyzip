# frozen_string_literal: true

module Zip
  module IOExtras
    # A write-only, forward-only wrapper around an IO-like destination that
    # only has to accept bytes (via +<<+ or +write+). It tracks the number of
    # bytes written itself, so the destination does not need to support
    # +tell+ or +seek+. This is what lets {Zip::OutputStream} stream an archive
    # straight to something like an HTTP response body without buffering it.
    #
    # The underlying stream is never closed by this wrapper; +close+ is not
    # even defined.
    class WriteOnlyIO
      # The number of bytes written so far, plus any simulated starting
      # offset (see +start_offset+, which is only intended for testing Zip64
      # boundary behaviour).
      attr_reader :tell

      alias pos tell

      # @param destination [#<<, #write] the stream bytes are written to.
      # @param start_offset [Integer] adds a constant offset to {#tell}. This
      #   exists solely so tests can pretend the archive starts beyond the
      #   32-bit offset limit without having to write 4&nbsp;GiB of data; it
      #   must not be used in real output.
      def initialize(destination, start_offset: 0)
        unless destination.respond_to?(:write) || destination.respond_to?(:<<)
          raise ArgumentError,
                'write-only stream needs a destination that responds to #write or #<<'
        end

        @destination = destination
        @tell = start_offset
      end

      # Passes +data+ straight through to the destination and counts the
      # bytes.
      #
      # Returns +self+, mirroring +IO#<<+.
      def <<(data)
        bytes = data.to_s
        write_to_destination(bytes)
        @tell += bytes.bytesize
        self
      end

      # Passes +data+ straight through to the destination and counts the
      # bytes.
      #
      # Returns the number of bytes written, mirroring +IO#write+.
      def write(data)
        bytes = data.to_s
        write_to_destination(bytes)
        @tell += bytes.bytesize
        bytes.bytesize
      end

      def binmode
        @destination.binmode if @destination.respond_to?(:binmode)
        self
      end

      def flush
        @destination.flush if @destination.respond_to?(:flush)
        self
      end

      private

      def write_to_destination(bytes)
        if @destination.respond_to?(:write)
          @destination.write(bytes)
        else
          @destination << bytes
        end
      end
    end
  end
end

# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
