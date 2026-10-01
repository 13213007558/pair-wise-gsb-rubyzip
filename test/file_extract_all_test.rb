# frozen_string_literal: true

require_relative 'test_helper'

class ZipFileExtractAllTest < Minitest::Test
  SRC_DIR = 'test/data/generated/extract_all_src'
  ZIP_PATH = 'test/data/generated/extract_all.zip'
  DEST_DIR = 'test/data/generated/extract_all_dest'
  NO_DIRS_ZIP = 'test/data/generated/extract_all_no_dirs.zip'
  SYMLINK_ZIP = 'test/data/path_traversal/jwilk/dirsymlink.zip'

  def setup
    FileUtils.rm_rf(SRC_DIR)
    FileUtils.rm_rf(DEST_DIR)
    FileUtils.rm_f(ZIP_PATH)
    FileUtils.rm_f(NO_DIRS_ZIP)

    FileUtils.mkdir_p(::File.join(SRC_DIR, 'subdir'))
    FileUtils.mkdir_p(::File.join(SRC_DIR, 'empty_subdir'))
    ::File.write(::File.join(SRC_DIR, 'top.txt'), 'top level file')
    ::File.write(::File.join(SRC_DIR, 'subdir', 'nested.txt'), 'nested file')

    Zip::File.open(ZIP_PATH, create: true) { |zf| zf.add_recursive(SRC_DIR) }
  end

  def teardown
    Zip.reset!
  end

  def test_extract_all_round_trips_a_tree
    Zip::File.open(ZIP_PATH) { |zf| zf.extract_all(DEST_DIR) }

    assert_equal 'top level file', ::File.read(::File.join(DEST_DIR, 'top.txt'))
    assert_equal 'nested file', ::File.read(::File.join(DEST_DIR, 'subdir', 'nested.txt'))
    assert ::File.directory?(::File.join(DEST_DIR, 'empty_subdir'))
  end

  def test_extract_all_class_method
    Zip::File.extract_all(ZIP_PATH, DEST_DIR)

    assert_equal 'top level file', ::File.read(::File.join(DEST_DIR, 'top.txt'))
    assert_equal 'nested file', ::File.read(::File.join(DEST_DIR, 'subdir', 'nested.txt'))
    assert ::File.directory?(::File.join(DEST_DIR, 'empty_subdir'))
  end

  def test_extract_all_creates_missing_intermediate_directories
    # A hand-built archive with only file entries and nested paths - no
    # explicit directory entries at all.
    Zip::OutputStream.open(NO_DIRS_ZIP) do |out|
      out.put_next_entry('a/b/c/deep.txt')
      out.write 'deep content'
    end

    Zip::File.open(NO_DIRS_ZIP) { |zf| zf.extract_all(DEST_DIR) }

    assert_equal 'deep content', ::File.read(::File.join(DEST_DIR, 'a', 'b', 'c', 'deep.txt'))
  end

  def test_extract_all_skips_symlinks
    out = assert_output('', /WARNING: skipped symlink '.*tmp'/) do
      Zip::File.open(SYMLINK_ZIP) { |zf| zf.extract_all(DEST_DIR) }
    end
    refute_nil out

    refute ::File.symlink?(::File.join(DEST_DIR, 'tmp'))
    assert ::File.directory?(::File.join(DEST_DIR, 'tmp'))
    assert ::File.exist?(::File.join(DEST_DIR, 'tmp', 'moo'))
  end

  def test_extract_all_exists_raises_by_default
    FileUtils.mkdir_p(DEST_DIR)
    ::File.write(::File.join(DEST_DIR, 'top.txt'), 'pre-existing')

    assert_raises(Zip::DestinationExistsError) do
      Zip::File.open(ZIP_PATH) { |zf| zf.extract_all(DEST_DIR) }
    end
  end

  def test_extract_all_exists_overwrite_via_block
    FileUtils.mkdir_p(DEST_DIR)
    ::File.write(::File.join(DEST_DIR, 'top.txt'), 'pre-existing')

    called = false
    Zip::File.open(ZIP_PATH) do |zf|
      zf.extract_all(DEST_DIR) do
        called = true
        true
      end
    end

    assert called
    assert_equal 'top level file', ::File.read(::File.join(DEST_DIR, 'top.txt'))
  end

  def test_extract_plan_lists_targets_before_execution
    Zip::File.open(ZIP_PATH) do |zf|
      plan = zf.extract_plan(DEST_DIR)

      assert_predicate plan, :valid?
      assert_equal %w[empty_subdir subdir subdir/nested.txt top.txt], plan.target_names
      assert_equal(
        {
          'top.txt' => [:create, :none],
          'subdir/nested.txt' => [:create, :none],
          'subdir' => [:create, :none],
          'empty_subdir' => [:create, :none]
        },
        plan.targets.to_h do |target|
          [target.name, [target.action, target.existing]]
        end
      )
      plan.execute

      assert_equal 'top level file', ::File.read(::File.join(DEST_DIR, 'top.txt'))
      assert_equal 'nested file', ::File.read(::File.join(DEST_DIR, 'subdir', 'nested.txt'))
    end
  end

  def test_extract_plan_records_overwrite_decisions
    FileUtils.mkdir_p(DEST_DIR)
    ::File.write(::File.join(DEST_DIR, 'top.txt'), 'pre-existing')

    Zip::File.open(ZIP_PATH) do |zf|
      plan = zf.extract_plan(DEST_DIR) { true }
      target = plan.targets.find { |candidate| candidate.name == 'top.txt' }

      assert_predicate plan, :valid?
      assert_equal :overwrite, target.action
      assert_equal :file, target.existing
      plan.execute
      assert_equal 'top level file', ::File.read(::File.join(DEST_DIR, 'top.txt'))
    end
  end

  def test_extract_plan_rejects_existing_file_without_overwrite_permission
    FileUtils.mkdir_p(DEST_DIR)
    ::File.write(::File.join(DEST_DIR, 'top.txt'), 'pre-existing')

    Zip::File.open(ZIP_PATH) do |zf|
      plan = zf.extract_plan(DEST_DIR)

      refute_predicate plan, :valid?
      assert_equal [:destination_exists], plan.conflicts.map(&:reason).uniq
      assert_raises(Zip::ExtractionPlanError) { plan.execute }
    end

    assert_equal 'pre-existing', ::File.read(::File.join(DEST_DIR, 'top.txt'))
  end

  def test_extract_plan_rejects_path_traversal_before_writing
    FileUtils.rm_f(ZIP_PATH)
    Zip::OutputStream.open(ZIP_PATH) do |out|
      out.put_next_entry('../escape.txt')
      out.write 'escape'
      out.put_next_entry('safe.txt')
      out.write 'safe'
    end

    Zip::File.open(ZIP_PATH) do |zf|
      plan = zf.extract_plan(DEST_DIR)

      refute_predicate plan, :valid?
      assert_includes plan.conflicts.map(&:reason), :unsafe_path
      plan.execute rescue nil
    end

    refute File.directory?(DEST_DIR)
    refute File.exist?(::File.join(File.dirname(DEST_DIR), 'escape.txt'))
  end

  def test_extract_plan_rejects_absolute_and_windows_path_traversal
    Zip::OutputStream.open(ZIP_PATH) do |out|
      out.put_next_entry('..\\windows_escape.txt')
      out.write 'windows'
    end

    Zip::File.open(ZIP_PATH) do |zf|
      plan = zf.extract_plan(DEST_DIR)
      windows_reasons = plan.conflicts.map(&:reason)

      refute_predicate plan, :valid?
      assert_equal [:unsafe_path], windows_reasons
    end

    Zip::File.open('test/data/path_traversal/tuzovakaoff/absolutepath.zip') do |zf|
      plan = zf.extract_plan(DEST_DIR)

      refute_predicate plan, :valid?
      assert_equal [:unsafe_path], plan.conflicts.map(&:reason).uniq
    end

    refute File.directory?(DEST_DIR)
  end

  def test_extract_plan_rejects_case_folding_conflicts
    Zip::OutputStream.open(ZIP_PATH) do |out|
      out.put_next_entry('Data/file.txt')
      out.write 'first'
      out.put_next_entry('data/other.txt')
      out.write 'second'
    end

    Zip::File.open(ZIP_PATH) do |zf|
      plan = zf.extract_plan(DEST_DIR)

      refute_predicate plan, :valid?
      assert_includes plan.conflicts.map(&:reason), :case_conflict
      assert_raises(Zip::ExtractionPlanError) { plan.execute }
    end
  end

  def test_extract_plan_rejects_file_and_directory_conflicts
    Zip::OutputStream.open(ZIP_PATH) do |out|
      out.put_next_entry('conflict')
      out.write 'file'
      out.put_next_entry('conflict/file.txt')
      out.write 'child'
    end

    Zip::File.open(ZIP_PATH) do |zf|
      plan = zf.extract_plan(DEST_DIR)

      refute_predicate plan, :valid?
      assert_includes plan.conflicts.map(&:reason), :file_directory_conflict
    end
  end

  def test_extract_plan_rejects_existing_file_and_symlink_ancestors
    FileUtils.mkdir_p(DEST_DIR)
    ::File.write(::File.join(DEST_DIR, 'file_ancestor'), 'blocker')
    outside = ::File.join(Dir.tmpdir, "rubyzip-symlink-#{Process.pid}")
    FileUtils.mkdir_p(outside)
    ::File.symlink(outside, ::File.join(DEST_DIR, 'link_ancestor'))

    Zip::OutputStream.open(ZIP_PATH) do |out|
      out.put_next_entry('file_ancestor/child.txt')
      out.write 'child'
      out.put_next_entry('link_ancestor/child.txt')
      out.write 'child'
    end

    Zip::File.open(ZIP_PATH) do |zf|
      plan = zf.extract_plan(DEST_DIR)
      reasons = plan.conflicts.map(&:reason)

      assert_includes reasons, :existing_file_ancestor
      assert_includes reasons, :existing_symlink_ancestor
    end
  ensure
    FileUtils.rm_rf(outside)
  end

  def test_extract_plan_can_reject_symlink_entries
    # Build a real symlink entry from a temporary source tree.
    Dir.mktmpdir do |tmp|
      source = ::File.join(tmp, 'link')
      ::File.symlink('../target', source)
      FileUtils.rm_f(ZIP_PATH)
      Zip::File.open(ZIP_PATH, create: true) { |zf| zf.add('link', source) }

      Zip::File.open(ZIP_PATH) do |zf|
        skipped = zf.extract_plan(DEST_DIR)
        assert_predicate skipped, :valid?
        assert_equal :skip, skipped.targets.find(&:entry).action

        strict = zf.extract_plan(DEST_DIR, symlinks: :raise)
        refute_predicate strict, :valid?
        assert_includes strict.conflicts.map(&:reason), :symlink_not_allowed
      end
    end
  end

  def test_extract_plan_does_not_replace_existing_symlink_used_by_archive_directory
    FileUtils.mkdir_p(DEST_DIR)
    outside = ::File.join(Dir.tmpdir, "rubyzip-symlink-dir-#{Process.pid}")
    FileUtils.mkdir_p(outside)
    ::File.symlink(outside, ::File.join(DEST_DIR, 'tmp'))

    begin
      Zip::File.open('test/data/path_traversal/jwilk/dirsymlink.zip') do |zf|
        plan = zf.extract_plan(DEST_DIR)
        reasons = plan.conflicts.map(&:reason)

        refute_predicate plan, :valid?
        assert_includes reasons, :existing_symlink_ancestor
      end

      assert ::File.symlink?(::File.join(DEST_DIR, 'tmp'))
      refute ::File.exist?(::File.join(DEST_DIR, 'tmp', 'moo'))
    ensure
      FileUtils.rm_rf(outside)
    end
  end

  def test_extract_all_rolls_back_when_last_entry_fails
    FileUtils.mkdir_p(::File.join(DEST_DIR, 'existing_dir'))
    ::File.write(::File.join(DEST_DIR, 'keep.txt'), 'keep')
    ::File.write(::File.join(DEST_DIR, 'existing_dir', 'note.txt'), 'note')
    before = directory_snapshot(DEST_DIR)

    create_archive_with_corrupt_last_entry

    error = assert_raises(Zip::DecompressionError) do
      Zip::File.open(ZIP_PATH) { |zf| zf.extract_all(DEST_DIR) }
    end
    refute_nil error

    assert_equal before, directory_snapshot(DEST_DIR)
    refute File.exist?(::File.join(DEST_DIR, 'first.txt'))
    refute File.directory?(::File.join(DEST_DIR, 'nested'))
    assert_empty Dir.children(DEST_DIR).grep(/\A\.rubyzip-extract/)
  end

  private

  def directory_snapshot(path)
    Dir.glob(::File.join(path, '**', '*'), File::FNM_DOTMATCH).sort.each_with_object({}) do |child, snapshot|
      next if ['.', '..'].include?(::File.basename(child))

      snapshot[child.delete_prefix(File.absolute_path(path) + ::File::SEPARATOR)] =
        { type: File.lstat(child).ftype, content: File.file?(child) ? File.binread(child) : nil }
    end
  end

  def create_archive_with_corrupt_last_entry
    Zip::OutputStream.open(ZIP_PATH) do |out|
      out.put_next_entry('first.txt')
      out.write 'first'
      out.put_next_entry('nested/last.txt')
      out.write('last content ' * 50)
    end

    offset = nil
    Zip::File.open(ZIP_PATH) do |zf|
      entry = zf.get_entry('nested/last.txt')
      offset = entry.local_header_offset + 30 + entry.name.bytesize + entry.extra.local_size
    end

    data = File.binread(ZIP_PATH)
    data[offset] = (data[offset].ord ^ 0xff).chr
    File.binwrite(ZIP_PATH, data)
  end
end
