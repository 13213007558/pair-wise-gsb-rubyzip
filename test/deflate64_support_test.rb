# frozen_string_literal: true

require_relative 'test_helper'

class Deflate64SupportTest < Minitest::Test
  FIXTURE = 'test/data/zipWithDeflate64Compression.zip'

  WINDOW = Array.new(65_536) { |i| ((i * 73) + 17) & 0xFF }.pack('C*').freeze

  EXPECTED = {
    'stored.txt' => "Hello, Deflate64!\n",
    'stored_multi.txt' => "first chunk\nsecond chunk\n",
    'fixed_long.txt' => 'abcdefghghghghghghghZZZZ',
    'dynamic.txt' => 'CCCC',
    'dynamic_285.txt' => 'X' * 259,
    'fixed_window.txt' => WINDOW + WINDOW.byteslice(0, 3)
  }.freeze

  def test_fixture_entries_use_method_9
    Zip::File.open(FIXTURE) do |zip|
      EXPECTED.each_key do |name|
        entry = zip.get_entry(name)
        assert_equal(Zip::COMPRESSION_METHOD_DEFLATE_64,
                     entry.compression_method,
                     "#{name} should use compression method 9")
      end
    end
  end

  def test_reads_all_fixture_entries_via_input_stream
    Zip::InputStream.open(FIXTURE) do |zis|
      while (entry = zis.get_next_entry)
        expected = EXPECTED.fetch(entry.name)
        assert_equal(expected, zis.read,
                     "#{entry.name} content mismatch (entry CRC is checked " \
                     'during streaming)')
      end
    end
  end

  def test_reads_all_fixture_entries_via_zip_file
    Zip::File.open(FIXTURE) do |zip|
      EXPECTED.each do |name, expected|
        assert_equal(expected, zip.read(name), "#{name} content mismatch")
      end
    end
  end

  def test_window_back_reference_spans_full_64kib
    window_bytes = Array.new(65_536) { |i| ((i * 73) + 17) & 0xFF }.pack('C*')
    expected = window_bytes + window_bytes.byteslice(0, 3)
    Zip::File.open(FIXTURE) do |zip|
      assert_equal(expected, zip.read('fixed_window.txt'))
    end
  end

  def test_method_9_is_registered
    assert_equal(Zip::Deflate64Decompressor,
                 Zip::Decompressor.find_by_compression_method(9))
  end
end
