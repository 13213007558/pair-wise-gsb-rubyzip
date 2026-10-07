# frozen_string_literal: true

require 'stringio'

module Zip
  class Delta
    module Codec
      private

      def read_exact!(io, length, description)
        data = io.read(length)
        unless data&.bytesize == length
          raise DeltaError, "Truncated delta while reading #{description}"
        end
        data
      end

      def write_u8(io, value)
        io << [value].pack('C')
      end

      def read_u8(io, description)
        read_exact!(io, 1, description).unpack1('C')
      end

      def write_u16(io, value)
        io << [value].pack('v')
      end

      def read_u16(io, description)
        read_exact!(io, 2, description).unpack1('v')
      end

      def write_u32(io, value)
        io << [value].pack('V')
      end

      def read_u32(io, description)
        read_exact!(io, 4, description).unpack1('V')
      end

      def write_u64(io, value)
        io << [value].pack('Q<')
      end

      def read_u64(io, description)
        read_exact!(io, 8, description).unpack1('Q<')
      end

      def write_counted(io, data)
        write_u64(io, data.bytesize)
        io << data
      end

      def read_counted(io, description, maximum: nil)
        length = read_u64(io, "#{description} length")
        if length > (maximum || 1 << 40)
          raise DeltaError, "Invalid #{description} length in delta"
        end

        read_exact!(io, length, description)
      end

      def write_optional_string(io, value)
        write_counted(io, value || '')
      end

      def read_optional_string(io, description)
        read_counted(io, description, maximum: 0xFFFF).b
      end
    end

    class Writer
      include Codec

      def self.write(base_bytes, comment, records)
        new(base_bytes, comment, records).write
      end

      def initialize(base_bytes, comment, records)
        @base_bytes = base_bytes
        @comment = comment || ''
        @records = records
      end

      def write
        body = StringIO.new
        body.binmode
        body << Delta::MAGIC
        write_u8(body, VERSION)
        write_u8(body, 0)
        body << Digest::SHA256.digest(@base_bytes)
        write_optional_string(body, @comment)
        write_u32(body, @records.size)
        @records.each { |record| write_record(body, record) }
        body << Digest::SHA256.digest(body.string)
        body.rewind
        body
      end

      private

      def write_record(io, record)
        operation = record.fetch(:operation)
        write_u8(io, operation == :full ? FULL : REUSE)
        write_counted(io, record.fetch(:name))
        write_counted(io, record.fetch(:comment))

        source = record[:source]
        if source
          write_counted(io, source.fetch(:name))
          write_u64(io, source.fetch(:offset))
        else
          write_counted(io, '')
          write_u64(io, 0)
        end

        fields = record.fetch(:fields)
        write_u16(io, fields.fetch(:wire_compression))
        write_u16(io, fields.fetch(:actual_compression))
        write_u32(io, fields.fetch(:crc))
        write_u64(io, fields.fetch(:compressed_size))
        write_u64(io, fields.fetch(:size))
        write_u8(io, fields.fetch(:encrypted) ? 1 : 0)
        write_u8(io, fields.fetch(:descriptor_present) ? 1 : 0)
        write_u32(io, record.fetch(:descriptor_size))
        aes = fields.fetch(:aes) || ''
        write_counted(io, aes)
        io << record.fetch(:local_digest)
        io << record.fetch(:central_digest)
        io << record.fetch(:segment_digest)
        io << record.fetch(:plaintext_digest)
        write_counted(io, record.fetch(:local_header))
        write_counted(io, record.fetch(:central))
        return unless operation == :full

        write_counted(io, record.fetch(:segment))
      end
    end

    class Reader
      include Codec

      def self.read(bytes)
        new(bytes).read
      end

      def initialize(bytes)
        @bytes = bytes
      end

      def read
        minimum_record_size = 215
        unless @bytes.bytesize >= MAGIC.bytesize + 2 + 32 + 8 + 4 + 32
          raise DeltaError, 'Truncated delta'
        end
        io = StringIO.new(@bytes)
        io.binmode
        verify_header(io)
        base_digest = read_exact!(io, 32, 'base archive digest')
        comment = read_optional_string(io, 'archive comment')
        count = read_u32(io, 'entry count')
        unless count <= (@bytes.bytesize - io.tell - 32) / minimum_record_size
          raise DeltaError, 'Invalid entry count in delta'
        end
        records = Array.new(count) { read_record(io) }
        checksum = read_exact!(io, 32, 'delta checksum')
        payload_length = @bytes.bytesize - 32
        actual = Digest::SHA256.digest(@bytes.byteslice(0, payload_length))
        unless checksum == actual && io.eof?
          raise DeltaError, 'Delta checksum does not match'
        end

        { base_digest: base_digest, comment: comment, records: records }
      end

      private

      def verify_header(io)
        magic = read_exact!(io, MAGIC.bytesize, 'magic')
        version = read_u8(io, 'version')
        flags = read_u8(io, 'flags')
        unless magic == MAGIC && version == VERSION && flags.zero?
          raise DeltaError, 'Unsupported delta format'
        end
      end

      def read_record(io)
        operation_code = read_u8(io, 'operation')
        operation = case operation_code
                    when REUSE then :reuse
                    when FULL then :full
                    else raise DeltaError, 'Unknown delta operation'
                    end
        name = read_optional_string(io, 'entry name')
        comment = read_optional_string(io, 'entry comment')
        source_name = read_optional_string(io, 'source entry name')
        source_offset = read_u64(io, 'source offset')
        fields = read_fields(io)
        local_digest = read_exact!(io, 32, 'local header digest')
        central_digest = read_exact!(io, 32, 'central directory digest')
        segment_digest = read_exact!(io, 32, 'segment digest')
        plaintext_digest = read_exact!(io, 32, 'plaintext digest')
        local_header = read_counted(io, 'local header')
        central = read_counted(io, 'central directory entry')
        segment = read_counted(io, 'segment') if operation == :full
        validate_operation!(operation, source_name, source_offset)

        {
          name: name,
          comment: comment,
          operation: operation,
          source_name: operation == :reuse ? source_name : nil,
          source_offset: operation == :reuse ? source_offset : nil,
          fields: fields,
          local_digest: local_digest,
          central_digest: central_digest,
          segment_digest: segment_digest,
          plaintext_digest: plaintext_digest,
          descriptor_size: fields.fetch(:descriptor_size),
          local_header: local_header,
          central: central,
          segment: segment
        }
      end

      def read_fields(io)
        wire_compression = read_u16(io, 'wire compression method')
        actual_compression = read_u16(io, 'compression method')
        crc = read_u32(io, 'CRC')
        compressed_size = read_u64(io, 'compressed size')
        size = read_u64(io, 'uncompressed size')
        encrypted_value = read_u8(io, 'encryption state')
        descriptor_value = read_u8(io, 'data descriptor state')
        descriptor_size = read_u32(io, 'data descriptor size')
        aes = read_counted(io, 'AES metadata')
        encrypted = encrypted_value == 1
        descriptor_present = descriptor_value == 1
        unless [0, 1].include?(encrypted_value) &&
               [0, 1].include?(descriptor_value)
          raise DeltaError, 'Invalid encryption or data-descriptor flag in delta'
        end
        expected_descriptor_size = descriptor_present ? 12 : 0
        unless descriptor_size == expected_descriptor_size ||
               (descriptor_present && descriptor_size == 16)
          raise DeltaError, 'Invalid data descriptor size in delta'
        end
        if wire_compression == COMPRESSION_METHOD_AES && aes.bytesize != 7
          raise DeltaError, 'Invalid AES metadata in delta'
        end
        if wire_compression != COMPRESSION_METHOD_AES &&
           actual_compression != wire_compression
          raise DeltaError, 'Compression method mismatch in delta'
        end
        if wire_compression == COMPRESSION_METHOD_AES &&
           actual_compression != aes.byteslice(5, 2)&.unpack1('v')
          raise DeltaError, 'AES compression method mismatch in delta'
        end
        if compressed_size + descriptor_size > 1 << 63
          raise DeltaError, 'Compressed segment size is too large in delta'
        end

        {
          wire_compression: wire_compression,
          actual_compression: actual_compression,
          crc: crc,
          compressed_size: compressed_size,
          size: size,
          encrypted: encrypted,
          descriptor_present: descriptor_present,
          descriptor_size: descriptor_size,
          aes: aes.empty? ? nil : aes
        }
      end

      def validate_operation!(operation, source_name, source_offset)
        if operation == :reuse
          if source_name.empty? || source_offset.nil?
            raise DeltaError, 'Reused delta entry is missing its source'
          end
        elsif !source_name.empty? || !source_offset.zero?
          raise DeltaError, 'Complete delta entry must not name a source'
        end
      end
    end
  end
end
