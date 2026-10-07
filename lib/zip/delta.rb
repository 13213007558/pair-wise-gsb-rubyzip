# frozen_string_literal: true

require 'digest'
require 'tempfile'

module Zip
  # Generates and applies binary deltas between two zip archives.
  #
  # A delta is bound to the SHA-256 identity of its base archive. Reused data
  # is checked by segment digest and by compression, CRC, size, encryption and
  # data-descriptor metadata. The target central directory is always rebuilt.
  class Delta
    MAGIC = 'RUBYZIP1'.b.freeze
    VERSION = 1
    REUSE = 1
    FULL = 2
    DESCRIPTOR_BIT = 0x08
    ENCRYPTION_BIT = 0x01
    DESCRIPTOR_SIGNATURE = 0x08074b50
    ZERO_DIGEST = ("\0" * 32).b.freeze

    class << self
      # Build a delta from +base+ to +target+. Paths and IO objects are both
      # accepted. The delta is returned as a binary StringIO.
      def generate(base, target)
        base_bytes = read_input(base)
        target_bytes = read_input(target)
        base_archive = Delta::Analyzer.analyze(base_bytes)
        target_archive = Delta::Analyzer.analyze(target_bytes)
        records = build_records(base_archive, target_archive)
        Delta::Writer.write(base_bytes, target_archive.comment, records)
      rescue Error => error
        raise error if error.is_a?(DeltaError)

        raise DeltaError, error.message
      end

      # Apply +delta+ to +base+ and write a complete target archive. Paths and
      # IO objects are accepted. Existing output is replaced atomically only
      # after all validation succeeds.
      def apply(base, delta, output)
        base_bytes = read_input(base)
        delta_bytes = read_input(delta)
        result = Delta::Applicator.new(base_bytes, delta_bytes).apply
        write_output(output, result)
        nil
      rescue Error => error
        raise error if error.is_a?(DeltaError)

        raise DeltaError, error.message
      rescue StandardError => error
        raise DeltaError, error.message
      end

      # Return non-sensitive summary information stored in a delta.
      def info(delta)
        data = Delta::Reader.read(read_input(delta))
        {
          base_digest: data.fetch(:base_digest),
          comment: data.fetch(:comment),
          entries: data.fetch(:records).map do |record|
            {
              name: record.fetch(:name),
              operation: record.fetch(:operation),
              source_name: record[:source_name]
            }
          end
        }
      rescue Error => error
        raise error if error.is_a?(DeltaError)

        raise DeltaError, error.message
      end

      private

      def read_input(input)
        if input.respond_to?(:read) && !input.kind_of?(::String)
          input.rewind if input.respond_to?(:rewind)
          return input.read.b
        end

        ::File.binread(input)
      end

      def write_output(output, bytes)
        if output.respond_to?(:write) && !output.kind_of?(::String)
          output.binmode if output.respond_to?(:binmode)
          output.write(bytes)
          output.rewind if output.respond_to?(:rewind)
          return
        end

        directory = ::File.dirname(output)
        ::Tempfile.create(::File.basename(output), directory) do |temporary|
          temporary.binmode.write(bytes)
          temporary.flush
          ::File.rename(temporary.path, output)
        end
      end

      def build_records(base_archive, target_archive)
        target_archive.records.map do |target|
          source = reusable_source(base_archive, target)
          target.merge(
            operation: source ? :reuse : :full,
            source: source,
            plaintext_digest: plaintext_digest(target_archive.bytes, target)
          )
        end
      end

      def reusable_source(base_archive, target)
        target_digest = target.fetch(:segment_digest)
        base_archive.records.find do |candidate|
          candidate.fetch(:segment_digest) == target_digest &&
            segment_identity(candidate) == segment_identity(target)
        end
      end

      def segment_identity(record)
        fields = record.fetch(:fields)
        [
          fields.fetch(:actual_compression),
          fields.fetch(:wire_compression),
          fields.fetch(:crc),
          fields.fetch(:compressed_size),
          fields.fetch(:size),
          fields.fetch(:encrypted),
          fields.fetch(:descriptor_present),
          record.fetch(:descriptor_size),
          fields.fetch(:aes)
        ]
      end

      def plaintext_digest(archive_bytes, record)
        fields = record.fetch(:fields)
        return ZERO_DIGEST if fields.fetch(:encrypted)
        return ZERO_DIGEST unless [Entry::STORED, Entry::DEFLATED].include?(
          fields.fetch(:actual_compression)
        )

        Digest::SHA256.digest(decompressed_segment(archive_bytes, record))
      end

      def decompressed_segment(archive_bytes, record)
        fields = record.fetch(:fields)
        start = record.fetch(:offset) + record.fetch(:local_header_size)
        data = archive_bytes.byteslice(start, fields.fetch(:compressed_size))
        return data if fields.fetch(:actual_compression) == Entry::STORED

        Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(data)
      end
    end
  end
end

require_relative 'delta/analyzer'
require_relative 'delta/codec'
require_relative 'delta/applicator'
