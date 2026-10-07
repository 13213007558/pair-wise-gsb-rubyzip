# frozen_string_literal: true

require_relative 'test_helper'
require_relative 'helpers/decompressor_tests'

class ImploderTest < Minitest::Test
  include DecompressorTests

  IMPLODED_FILE = 'test/data/file1.txt.implodedData'

  EXPECTED_TEXT = <<~TEXT * 40
    The quick brown fox jumps over the lazy dog. Pack my box with five dozen liquor jugs.
    How vexingly quick daft zebras jump! Sphinx of black quartz, judge my vow. Zip zap zoom.
    abcabcabc abcabcabc abcabcabc 1234567890 1234567890 1234567890 !@#$%^&*() !@#$%^&*()
  TEXT

  def setup
    super
    @file = File.new(IMPLODED_FILE, 'rb')
    @decompressor = ::Zip::Imploder.new(@file, File.size(TEST_FILE))
  end

  def teardown
    @file.close
    ::Zip.reset!
  end

  # Reads every fixture entry through the high-level Zip::File API and checks
  # the round-trip against the known plaintext.
  {
    'implode_4k_2tree' => '4K dictionary, 2 trees',
    'implode_4k_3tree' => '4K dictionary, 3 trees',
    'implode_8k_2tree' => '8K dictionary, 2 trees',
    'implode_8k_3tree' => '8K dictionary, 3 trees'
  }.each do |name, description|
    define_method("test_reads_#{name}") do
      Zip::File.open("test/data/#{name}.zip") do |zip_file|
        entry = zip_file.find_entry('sample.txt')
        assert_equal(EXPECTED_TEXT.b, entry.get_input_stream.read, "failed to decode #{description}")
      end
    end
  end

  def test_reads_each_entry_of_a_multi_entry_archive
    Zip::File.open('test/data/implode_8k_3tree_multi.zip') do |zip_file|
      assert_equal('hello hello hello world world', zip_file.find_entry('first.txt').get_input_stream.read)
      assert_equal(EXPECTED_TEXT.b, zip_file.find_entry('second.txt').get_input_stream.read)
    end
  end

  def test_reads_via_zip_input_stream
    Zip::InputStream.open('test/data/implode_8k_3tree.zip') do |zis|
      zis.get_next_entry
      assert_equal(EXPECTED_TEXT.b, zis.read)
    end
  end

  def test_corrupt_tree_raises_and_names_entry
    error = assert_raises(::Zip::DecompressionError) do
      Zip::File.open('test/data/implode_corrupt_tree.zip') do |zip_file|
        zip_file.find_entry('broken.txt').get_input_stream.read
      end
    end
    assert_match(/broken.txt/, error.message)
  end

  def test_back_reference_too_far_raises_and_names_entry
    error = assert_raises(::Zip::DecompressionError) do
      Zip::File.open('test/data/implode_bad_distance.zip') do |zip_file|
        zip_file.find_entry('toofar.txt').get_input_stream.read
      end
    end
    assert_match(/toofar.txt/, error.message)
  end

  def test_truncated_input_raises_and_names_entry
    error = assert_raises(::Zip::DecompressionError) do
      Zip::File.open('test/data/implode_truncated.zip') do |zip_file|
        zip_file.find_entry('cutoff.txt').get_input_stream.read
      end
    end
    assert_match(/cutoff.txt/, error.message)
  end

  def test_error_carries_the_entry
    Zip::File.open('test/data/implode_corrupt_tree.zip') do |zip_file|
      entry = zip_file.find_entry('broken.txt')
      error = assert_raises(::Zip::DecompressionError) { entry.get_input_stream.read }
      assert_equal('broken.txt', error.entry.name)
    end
  end

  def test_error_is_attributed_to_the_failing_entry_only
    Zip::File.open('test/data/implode_multi_bad_second.zip') do |zip_file|
      assert_equal('first entry is fine. ' * 10, zip_file.find_entry('good.txt').get_input_stream.read)

      error = assert_raises(::Zip::DecompressionError) do
        zip_file.find_entry('bad.txt').get_input_stream.read
      end
      assert_match(/bad.txt/, error.message)
      assert_equal('bad.txt', error.entry.name)
    end
  end
end
