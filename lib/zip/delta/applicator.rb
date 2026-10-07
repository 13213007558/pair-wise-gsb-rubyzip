# frozen_string_literal: true

require 'stringio'

module Zip
  class Delta
    class Applicator
      include Codec

      def initialize(base_bytes, delta_bytes)
        @base_bytes = base_bytes
        @delta_bytes = delta_bytes
      end

      def apply
        @delta = Reader.read(@delta_bytes)
        verify_base!
        @base = Analyzer.analyze(@base_bytes)
        @plans = build_plans
        output = assemble
        verify_output(output)
        output
      end

      private

      def verify_base!
        base_digest = Digest::SHA256.digest(@base_bytes)
        return if base_digest == @delta.fetch(:base_digest)

        raise DeltaError, 'Base archive identity does not match delta'
      end

      def build_plans
        @delta.fetch(:records).map do |record|
          verify_record_digests!(record)
          segment = record.fetch(:operation) == :reuse ?
            reused_segment(record) : full_segment(record)
          record.merge(planned_segment: segment)
        end
      end

      def verify_record_digests!(record)
        checks = {
          local_header: [record.fetch(:local_header), record.fetch(:local_digest)],
          central: [record.fetch(:central), record.fetch(:central_digest)]
        }
        if record.fetch(:operation) == :full
          checks[:segment] = [record.fetch(:segment), record.fetch(:segment_digest)]
        end

        checks.each do |name, values|
          data, digest = values
          next if Digest::SHA256.digest(data) == digest

          raise DeltaError, "Invalid #{name} digest in delta entry #{record.fetch(:name).inspect}"
        end
      end

      def reused_segment(record)
        source = @base.records.find do |candidate|
          candidate.fetch(:name) == record.fetch(:source_name) &&
            candidate.fetch(:offset) == record.fetch(:source_offset)
        end
        unless source
          raise DeltaError,
                "Reused entry #{record.fetch(:name).inspect} is not in the base archive"
        end

        unless source.fetch(:segment_digest) == record.fetch(:segment_digest)
          raise DeltaError, "Reused segment digest mismatch for #{record.fetch(:name).inspect}"
        end
        unless identity(source) == identity(record)
          raise DeltaError, "Reused segment metadata mismatch for #{record.fetch(:name).inspect}"
        end
        source.fetch(:segment)
      end

      def full_segment(record)
        segment = record.fetch(:segment)
        expected_length = record.fetch(:fields).fetch(:compressed_size) +
                          record.fetch(:descriptor_size)
        unless segment.bytesize == expected_length
          raise DeltaError, "Embedded segment has wrong length for #{record.fetch(:name).inspect}"
        end
        segment
      end

      def identity(record)
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

      def assemble
        io = StringIO.new
        io.binmode
        central_entries = @plans.map do |plan|
          offset = io.tell
          io.write(plan.fetch(:local_header))
          io.write(plan.fetch(:planned_segment))
          patch_central_offset(plan.fetch(:central), offset)
        end

        central_offset = io.tell
        central_entries.each { |entry| io.write(entry) }
        write_end_of_central_directory(io, central_offset, central_entries)
        io.string
      end

      def patch_central_offset(central, new_offset)
        patched = central.dup
        static = patched.byteslice(0, CDIR_ENTRY_STATIC_HEADER_LENGTH)
        _signature, _made_by, _fstype, _needed, _gp_flags, _compression,
          _mod_time, _mod_date, _crc, _compressed_size, _size, name_size,
          extra_size, _comment_size, disk_start, _internal,
          _external, old_offset = static.unpack('VCCvvvvvVVVvvvvvVV')
        extra_start = CDIR_ENTRY_STATIC_HEADER_LENGTH + name_size
        extra = patched.byteslice(extra_start, extra_size).dup
        extra = update_zip64_relative_offset(
          extra,
          old_offset == 0xFFFFFFFF,
          new_offset,
          disk_start == 0xFFFF
        )
        static = static.dup
        static.byteslice(30, 2).replace([extra.bytesize].pack('v'))
        if new_offset > 0xFFFFFFFF
          needed = static.byteslice(7, 1).unpack1('C')
          static.setbyte(7, [needed, VERSION_NEEDED_TO_EXTRACT_ZIP64].max)
        end
        static.setbyte(42, new_offset & 0xff)
        static.setbyte(43, (new_offset >> 8) & 0xff)
        static.setbyte(44, (new_offset >> 16) & 0xff)
        static.setbyte(45, (new_offset >> 24) & 0xff)
        static.byteslice(0, 42) +
          [new_offset <= 0xFFFFFFFF ? new_offset : 0xFFFFFFFF].pack('V') +
          patched.byteslice(46, extra_start - 46) +
          extra +
          patched.byteslice(extra_start + extra_size..)
      end

      def update_zip64_relative_offset(extra, old_offset_zip64, new_offset, disk_zip64)
        offset = 0
        while offset + 4 <= extra.bytesize
          header_id = extra.byteslice(offset, 2)
          length = extra.byteslice(offset + 2, 2)&.unpack1('v')
          break if length.nil? || offset + 4 + length > extra.bytesize

          if header_id == Zip::ExtraField::Zip64::HEADER_ID
            return rebuild_zip64_extra(
              extra.byteslice(offset + 4, length),
              offset,
              length,
              extra,
              old_offset_zip64,
              new_offset,
              disk_zip64
            )
          end
          offset += length + 4
        end
        return extra unless new_offset > 0xFFFFFFFF

        extra + Zip::ExtraField::Zip64::HEADER_ID + [8].pack('v') + [new_offset].pack('Q<')
      end

      def rebuild_zip64_extra(content, offset, length, extra, old, new_offset, disk_zip64)
        values = +''.b
        position = 0
        seen_relative = false
        if static_size_zip64?(extra, offset, :original)
          values << content.byteslice(position, 8)
          position += 8
        end
        if static_size_zip64?(extra, offset, :compressed)
          values << content.byteslice(position, 8)
          position += 8
        end
        if old || new_offset > 0xFFFFFFFF
          values << [new_offset].pack('Q<')
          seen_relative = true
          position += 8 if old
        end
        if disk_zip64
          values << content.byteslice(position, 4)
          position += 4
        end
        unless position == content.bytesize || seen_relative
          values << content.byteslice(position..)
        end
        extra.byteslice(0, offset) + Zip::ExtraField::Zip64::HEADER_ID +
          [values.bytesize].pack('v') + values +
          (extra.byteslice(offset + 4 + length..) || '')
      end

      def static_size_zip64?(central, zip64_offset, key)
        static = central.byteslice(0, CDIR_ENTRY_STATIC_HEADER_LENGTH)
        offset = key == :original ? 24 : 20
        field = static.byteslice(offset, 4)&.unpack1('V')
        return false if field.nil?

        field == 0xFFFFFFFF
      end

      def write_end_of_central_directory(io, central_offset, entries)
        central_size = io.tell - central_offset
        count = entries.size
        if central_offset > 0xFFFFFFFF || central_size > 0xFFFFFFFF || count > 0xFFFF
          io << [CentralDirectory::ZIP64_END_OF_CD_SIG, 44, VERSION_MADE_BY,
                 VERSION_NEEDED_TO_EXTRACT_ZIP64, 0, 0, count, count,
                 central_size, central_offset].pack('VQ<vvVVQ<Q<Q<Q<')
          io << [CentralDirectory::ZIP64_EOCD_LOCATOR_SIG, 0, io.tell, 1].pack('VVQ<V')
        end
        io << [CentralDirectory::END_OF_CD_SIG, 0, 0,
               [count, 0xFFFF].min, [count, 0xFFFF].min,
               [central_size, 0xFFFFFFFF].min,
               [central_offset, 0xFFFFFFFF].min,
               @delta.fetch(:comment).bytesize].pack('VvvvvVVv')
        io << @delta.fetch(:comment)
      end

      def verify_output(bytes)
        archive = Analyzer.analyze(bytes)
        unless archive.comment == @delta.fetch(:comment) && archive.records.size == @plans.size
          raise DeltaError, 'Generated target archive metadata is invalid'
        end

        archive.records.zip(@plans).each do |actual, plan|
          verify_entry(actual, plan)
        end
      end

      def verify_entry(actual, plan)
        expected = plan.fetch(:fields)
        actual_fields = actual.fetch(:fields)
        %i[name comment].each do |key|
          next if actual.fetch(key) == plan.fetch(key)

          raise DeltaError, "Generated target #{key} mismatch"
        end
        %i[
          wire_compression actual_compression crc compressed_size size
          encrypted descriptor_present aes
        ].each do |key|
          next if actual_fields.fetch(key) == expected.fetch(key)

          raise DeltaError, "Generated target metadata mismatch for #{plan.fetch(:name).inspect}"
        end
        unless actual.fetch(:descriptor_size) == plan.fetch(:descriptor_size) &&
               actual.fetch(:segment_digest) == plan.fetch(:segment_digest) &&
               actual.fetch(:local_digest) == plan.fetch(:local_digest)
          raise DeltaError, "Generated target segment mismatch for #{plan.fetch(:name).inspect}"
        end
        verify_plaintext(actual, plan)
      end

      def verify_plaintext(actual, plan)
        return if actual.fetch(:fields).fetch(:encrypted)
        return unless [Entry::STORED, Entry::DEFLATED].include?(
          actual.fetch(:fields).fetch(:actual_compression)
        )

        data = actual.fetch(:segment).byteslice(0, actual.fetch(:fields).fetch(:compressed_size))
        data = Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(data) if
          actual.fetch(:fields).fetch(:actual_compression) == Entry::DEFLATED
        unless Digest::SHA256.digest(data) == plan.fetch(:plaintext_digest)
          raise DeltaError, "Generated target content mismatch for #{plan.fetch(:name).inspect}"
        end
        unless Zlib.crc32(data) == actual.fetch(:plaintext_crc)
          raise DeltaError, "Generated target CRC mismatch for #{plan.fetch(:name).inspect}"
        end
      end
    end
  end
end
