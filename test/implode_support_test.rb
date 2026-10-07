# frozen_string_literal: true

require 'minitest/autorun'
require 'stringio'
require_relative '../lib/zip'

class ImplodeSupportTest < Minitest::Test
  FIXTURE_PATH = 'test/data/implode_fixtures.zip'

  FIXTURE_CONTENT = {
    'fourk_raw.txt' => 'ABCDEFGH',
    'fourk_tree.txt' => 'ABC',
    'eightk_raw.txt' => 'ABCDEFGH',
    'eightk_tree.txt' => 'ABC'
  }.freeze

  FIXTURE_MODES = [
    ['fourk_raw.txt', 4096, false],
    ['fourk_tree.txt', 4096, true],
    ['eightk_raw.txt', 8192, false],
    ['eightk_tree.txt', 8192, true]
  ].freeze

  def test_implode_methods_are_registered
    decompressor = Zip::Decompressor.find_by_compression_method(6)
    assert_same(Zip::ImplodeReader, decompressor)
  end

  def test_reads_4k_and_8k_dictionaries_with_and_without_literal_tree
    FIXTURE_MODES.each do |name, window_size, literal_tree|
      Zip::File.open(FIXTURE_PATH) do |zip|
        io = zip.get_input_stream(name)
        assert_equal(window_size, decompressor_window_size(io))
        assert_equal(literal_tree, decompressor_literal_tree?(io))
        assert_equal(FIXTURE_CONTENT[name].b, io.read)
      end
    end
  end

  def test_incremental_reads_do_not_return_partial_output_after_an_error
    Zip::InputStream.open('test/data/implode_premature_end.zip') do |io|
      entry = io.get_next_entry
      error = assert_raises(Zip::DecompressionError) { io.read }
      assert_includes error.message, entry.name
    end
  end

  def test_corrupt_tree_is_attributed_to_the_entry
    Zip::InputStream.open('test/data/implode_bad_tree.zip') do |io|
      entry = io.get_next_entry
      error = assert_raises(Zip::DecompressionError) { io.read }
      assert_includes error.message, entry.name
    end
  end

  def test_back_reference_distance_outside_window_is_rejected
    Zip::InputStream.open('test/data/implode_bad_distance.zip') do |io|
      entry = io.get_next_entry
      error = assert_raises(Zip::DecompressionError) { io.read }
      assert_includes(error.message, entry.name)
    end
  end

  private

  def decompressor_window_size(io)
    io.instance_variable_get(:@decompressor).instance_variable_get(:@window_size)
  end

  def decompressor_literal_tree?(io)
    io.instance_variable_get(:@decompressor).instance_variable_get(:@literal_tree)
  end
end
