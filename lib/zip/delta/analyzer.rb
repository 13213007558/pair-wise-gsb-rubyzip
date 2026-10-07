# frozen_string_literal: true

module Zip
  class Delta
    class Analyzer
      attr_reader :bytes, :comment, :records, :central_offset

      def self.analyze(bytes)
        analyzer = new(bytes)
        analyzer.analyze
        analyzer
      end

      def initialize(bytes)
        @bytes = bytes
        @records = []
      end

      def analyze
        cdir = CentralDirectory.new
        cdir.read_from_stream(StringIO.new(bytes))
        @comment = cdir.comment || ''
        @central_offset = cdir.instance_variable_get(:@cdir_offset)
        read_records(cdir.size)
        self
      end

      private

      def read_records(count)
        io = StringIO.new(bytes)
        io.seek(central_offset)
        occupied = []

        count.times do
          record_start = io.tell
          central_static = read_exact(io, CDIR_ENTRY_STATIC_HEADER_LENGTH)
          fields = parse_central_static(central_static)
          name = read_exact(io, fields.fetch(:name_size))
          central_extra = read_exact(io, fields.fetch(:extra_size))
          comment = read_exact(io, fields.fetch(:comment_size))
          central = bytes.byteslice(record_start, io.tell - record_start)
          fields = apply_central_zip64(fields, central_extra)
          fields[:aes] = nil
          fields[:aes] = aes_extra(central_extra) if
            fields.fetch(:wire_compression) == COMPRESSION_METHOD_AES
          fields[:actual_compression] = if fields[:aes]
                                          fields.fetch(:aes).byteslice(5, 2)&.unpack1('v')
                                        else
                                          fields.fetch(:wire_compression)
                                        end
          fields[:encrypted] = (fields.fetch(:gp_flags) & ENCRYPTION_BIT).positive?
          records << read_local_record(
            fields: fields,
            name: name,
            comment: comment,
            central: central,
            occupied: occupied
          )
        end
      end

      def read_local_record(fields:, name:, comment:, central:, occupied:)
        offset = fields.fetch(:offset)
        local_static = bytes.byteslice(offset, LOCAL_ENTRY_STATIC_HEADER_LENGTH)
        unless local_static&.bytesize == LOCAL_ENTRY_STATIC_HEADER_LENGTH
          raise DeltaError, "Truncated local header for #{name.inspect}"
        end

        local_fields = parse_local_static(local_static)
        unless local_fields.delete(:signature) == LOCAL_ENTRY_SIGNATURE
          raise DeltaError, "Invalid local header signature for #{name.inspect}"
        end

        local_name_size = local_fields.delete(:name_size)
        local_extra_size = local_fields.delete(:extra_size)
        local_header_size = LOCAL_ENTRY_STATIC_HEADER_LENGTH + local_name_size + local_extra_size
        local_header_end = offset + local_header_size
        local_name = bytes.byteslice(offset + LOCAL_ENTRY_STATIC_HEADER_LENGTH, local_name_size)
        local_extra = bytes.byteslice(
          offset + LOCAL_ENTRY_STATIC_HEADER_LENGTH + local_name_size,
          local_extra_size
        )
        unless local_name == name && local_extra&.bytesize == local_extra_size
          raise DeltaError, "Invalid local header for #{name.inspect}"
        end

        local_fields = apply_local_zip64(local_fields, local_extra)
        verify_local_fields!(fields, local_fields, name)
        local_header = bytes.byteslice(offset, local_header_size)
        descriptor_size = verify_segment!(fields, local_header_end, name, occupied)
        segment_end = local_header_end + fields.fetch(:compressed_size) + descriptor_size
        segment = bytes.byteslice(local_header_end, segment_end - local_header_end)
        central_digest = Digest::SHA256.digest(central)
        local_digest = Digest::SHA256.digest(local_header)
        segment_digest = Digest::SHA256.digest(segment)
        plaintext_crc = fields.fetch(:aes) ? 0 : fields.fetch(:crc)

        {
          name: name,
          comment: comment,
          offset: offset,
          local_header: local_header,
          local_header_size: local_header_size,
          segment: segment,
          segment_digest: segment_digest,
          descriptor_size: descriptor_size,
          central: central,
          central_digest: central_digest,
          local_digest: local_digest,
          plaintext_crc: plaintext_crc,
          fields: fields
        }
      end

      def verify_local_fields!(central, local, name)
        compare = %i[wire_compression crc compressed_size size]
        descriptor_present = (local.fetch(:gp_flags) & DESCRIPTOR_BIT).positive?
        central[:descriptor_present] = (central.fetch(:gp_flags) & DESCRIPTOR_BIT).positive?
        unless (local.fetch(:gp_flags) & DESCRIPTOR_BIT) ==
               (central.fetch(:gp_flags) & DESCRIPTOR_BIT)
          raise DeltaError, "Data descriptor flag mismatch for #{name.inspect}"
        end

        compare.each do |key|
          next if descriptor_present && %i[crc compressed_size size].include?(key) &&
                  local.fetch(key).zero?
          next if local.fetch(key) == central.fetch(key)

          raise DeltaError, "Local and central #{key} mismatch for #{name.inspect}"
        end
      end

      def verify_segment!(fields, data_start, name, occupied)
        compressed_size = fields.fetch(:compressed_size)
        descriptor_size = descriptor_size(data_start, compressed_size, fields, name)
        segment_end = data_start + compressed_size + descriptor_size
        unless data_start >= 0 && segment_end <= central_offset
          raise DeltaError, "Entry #{name.inspect} crosses a segment boundary"
        end

        if occupied.any? { |start, finish| start < segment_end && finish > data_start }
          raise DeltaError, "Overlapping local entry data for #{name.inspect}"
        end
        occupied << [data_start, segment_end]
        descriptor_size
      end

      def descriptor_size(data_start, compressed_size, fields, name)
        return 0 unless fields.fetch(:descriptor_present)

        start = data_start + compressed_size
        signed = bytes.byteslice(start, 4)&.unpack1('V') == DESCRIPTOR_SIGNATURE
        size = signed ? 16 : 12
        descriptor = bytes.byteslice(start, size)
        unless descriptor&.bytesize == size
          raise DeltaError, "Truncated data descriptor for #{name.inspect}"
        end

        values = descriptor.byteslice(size - 12, 12)
        crc, compressed, uncompressed = values.unpack('VVV')
        unless compressed == compressed_size && uncompressed == fields.fetch(:size)
          raise DeltaError, "Invalid data descriptor sizes for #{name.inspect}"
        end
        unless crc == fields.fetch(:crc) || (fields.fetch(:aes) && crc.zero?)
          raise DeltaError, "Invalid data descriptor CRC for #{name.inspect}"
        end
        size
      end

      def parse_central_static(data)
        signature, made_by, fstype, needed, gp_flags, compression, mod_time,
          mod_date, crc, compressed_size, size, name_size, extra_size,
          comment_size, disk_start, internal_attributes, external_attributes,
          offset = data.unpack('VCCvvvvvVVVvvvvvVV')
        unless signature == CENTRAL_DIRECTORY_ENTRY_SIGNATURE
          raise DeltaError, 'Invalid central directory entry signature'
        end
        raise DeltaError, 'Delta does not support split archives' unless disk_start.zero?
        if name_size > 0xFFFF || extra_size > 0xFFFF || comment_size > 0xFFFF
          raise DeltaError, 'Invalid central directory field length'
        end

        {
          made_by: made_by,
          fstype: fstype,
          needed_to_extract: needed,
          gp_flags: gp_flags,
          wire_compression: compression,
          mod_time: mod_time,
          mod_date: mod_date,
          crc: crc,
          compressed_size: compressed_size,
          size: size,
          name_size: name_size,
          extra_size: extra_size,
          comment_size: comment_size,
          internal_attributes: internal_attributes,
          external_attributes: external_attributes,
          offset: offset
        }
      end

      def parse_local_static(data)
        signature, needed, _fstype, gp_flags, compression, mod_time, mod_date,
          crc, compressed_size, size, name_size, extra_size =
          data.unpack('VCCvvvvVVVvv')
        {
          signature: signature,
          needed_to_extract: needed,
          gp_flags: gp_flags,
          wire_compression: compression,
          mod_time: mod_time,
          mod_date: mod_date,
          crc: crc,
          compressed_size: compressed_size,
          size: size,
          name_size: name_size,
          extra_size: extra_size
        }
      end

      def apply_central_zip64(fields, extra)
        zip64 = extra_field(extra, Zip::ExtraField::Zip64::HEADER_ID)
        return fields unless zip64

        content = zip64.byteslice(4..)
        if fields.fetch(:size) == 0xFFFFFFFF
          value = content.byteslice(0, 8)&.unpack1('Q<')
          raise DeltaError, 'Truncated zip64 extra field' if value.nil?
          fields[:size] = value
          content = content.byteslice(8..)
        end
        if fields.fetch(:compressed_size) == 0xFFFFFFFF
          value = content.byteslice(0, 8)&.unpack1('Q<')
          raise DeltaError, 'Truncated zip64 extra field' if value.nil?
          fields[:compressed_size] = value
          content = content.byteslice(8..)
        end
        if fields.fetch(:offset) == 0xFFFFFFFF
          value = content.byteslice(0, 8)&.unpack1('Q<')
          raise DeltaError, 'Truncated zip64 relative header offset' if value.nil?
          fields[:offset] = value
        end
        fields
      end

      def apply_local_zip64(fields, extra)
        zip64 = extra_field(extra, Zip::ExtraField::Zip64::HEADER_ID)
        return fields unless zip64

        content = zip64.byteslice(4..)
        if fields.fetch(:size) == 0xFFFFFFFF
          value = content.byteslice(0, 8)&.unpack1('Q<')
          raise DeltaError, 'Truncated local zip64 extra field' if value.nil?
          fields[:size] = value
          content = content.byteslice(8..)
        end
        if fields.fetch(:compressed_size) == 0xFFFFFFFF
          value = content.byteslice(0, 8)&.unpack1('Q<')
          raise DeltaError, 'Truncated local zip64 extra field' if value.nil?
          fields[:compressed_size] = value
        end
        fields
      end

      def aes_extra(extra)
        value = extra_field(extra, Zip::ExtraField::AES::HEADER_ID)
        return unless value

        raise DeltaError, 'Invalid AES extra field' if value.bytesize < 11

        value.byteslice(4..)
      end

      def extra_field(extra, header_id)
        offset = 0
        while offset + 4 <= extra.bytesize
          id = extra.byteslice(offset, 2)
          length = extra.byteslice(offset + 2, 2)&.unpack1('v')
          return extra.byteslice(offset, length + 4) if id == header_id
          break if length.nil? || offset + 4 + length > extra.bytesize

          offset += length + 4
        end
        nil
      end

      def read_exact(io, length)
        data = io.read(length)
        unless data&.bytesize == length
          raise DeltaError, 'Unexpected end of central directory entry'
        end
        data
      end
    end
  end
end
