# frozen_string_literal: true

require_relative 'test_helper'
require 'tmpdir'

class ExtractPlanTest < Minitest::Test
  def setup
    @tmp = Dir.mktmpdir('rubyzip-extract-plan-test')
    @zip_path = ::File.join(@tmp, 'test.zip')
    @dest = ::File.join(@tmp, 'dest')
  end

  def teardown
    ::FileUtils.remove_entry(@tmp)
    ::Zip.reset!
  end

  private

  def make_zip(entries)
    ::Zip::OutputStream.open(@zip_path) do |out|
      entries.each do |name, content|
        out.put_next_entry(name)
        out.write(content) if content
      end
    end
  end

  # Creates a zip containing a symlink entry. +target+ must resolve to an
  # existing path at creation time (rubyzip refuses unreadable sources), so
  # +existing_at_creation+ may be used to place a file at the resolved path.
  def make_zip_with_symlink(name, target, existing_at_creation: nil)
    work = ::File.join(@tmp, 'work', ::File.dirname(name))
    ::FileUtils.mkdir_p(work)
    ::File.write(existing_at_creation, 'outside') if existing_at_creation
    ::File.symlink(target, ::File.join(work, ::File.basename(name)))
    ::Zip::File.open(@zip_path, create: true) { |zf| zf.add(name, ::File.join(work, ::File.basename(name))) }
  end

  # Flips the last byte of the last entry's compressed data, so that
  # inflating it fails (the deflate stream's adler32 checksum no longer
  # matches).
  def corrupt_last_entry
    entry = nil
    ::Zip::File.open(@zip_path) { |zf| entry = zf.entries.last }
    data = ::File.binread(@zip_path)
    name_len, extra_len = data.byteslice(entry.local_header_offset + 26, 4).unpack('vv')
    pos = entry.local_header_offset + 30 + name_len + extra_len + entry.compressed_size - 1
    data.setbyte(pos, data.getbyte(pos) ^ 0xFF)
    ::File.binwrite(@zip_path, data)
  end

  def dest_path(name)
    ::File.join(@dest, name)
  end

  def lexist?(path)
    ::File.exist?(path) || ::File.symlink?(path)
  end

  public

  def test_plan_lists_all_targets_and_actions
    make_zip('dir/' => nil, 'dir/b.txt' => 'b', 'a.txt' => 'a')

    ::Zip::File.open(@zip_path) do |zf|
      plan = zf.extract_plan(@dest)
      assert plan.ok?
      assert_empty plan.conflicts
      assert_equal %w[dir/ dir/b.txt a.txt], plan.items.map(&:name)
      assert_equal %i[create create create], plan.items.map(&:action)
      assert_equal dest_path('a.txt'), plan.items[2].dest_path
      assert_equal ::File.expand_path(@dest), plan.destination_directory

      plan.execute!
    end

    assert_equal 'a', ::File.read(dest_path('a.txt'))
    assert_equal 'b', ::File.read(dest_path('dir/b.txt'))
  end

  def test_existing_file_is_a_conflict_until_resolved
    make_zip('a.txt' => 'new')
    ::FileUtils.mkdir_p(@dest)
    ::File.write(dest_path('a.txt'), 'old')

    ::Zip::File.open(@zip_path) do |zf|
      plan = zf.extract_plan(@dest)
      refute plan.ok?
      assert_equal %i[exists], plan.conflicts.map(&:kind)
      assert_equal :conflict, plan.items.first.action
      assert plan.items.first.will_overwrite?

      assert_raises(::Zip::ExtractPlanError) { plan.execute! }
      assert_equal 'old', ::File.read(dest_path('a.txt'))

      plan.resolve('a.txt', :overwrite)
      assert plan.ok?
      assert_equal :overwrite, plan.items.first.action
      plan.execute!
      assert_equal 'new', ::File.read(dest_path('a.txt'))
    end
  end

  def test_skip_resolution_keeps_existing_file
    make_zip('a.txt' => 'new', 'b.txt' => 'b')
    ::FileUtils.mkdir_p(@dest)
    ::File.write(dest_path('a.txt'), 'old')

    ::Zip::File.open(@zip_path) do |zf|
      plan = zf.extract_plan(@dest)
      plan.resolve('a.txt', :skip)
      assert plan.ok?
      plan.execute!
    end

    assert_equal 'old', ::File.read(dest_path('a.txt'))
    assert_equal 'b', ::File.read(dest_path('b.txt'))
  end

  def test_overwrite_option_pre_resolves_conflicts
    make_zip('a.txt' => 'new')
    ::FileUtils.mkdir_p(@dest)
    ::File.write(dest_path('a.txt'), 'old')

    ::Zip::File.open(@zip_path) do |zf|
      plan = zf.extract_plan(@dest, overwrite: true)
      assert plan.ok?
      assert_equal :overwrite, plan.items.first.action
      plan.execute!
    end

    assert_equal 'new', ::File.read(dest_path('a.txt'))
  end

  def test_path_traversal_entries_are_flagged_and_only_skippable
    make_zip('../evil.txt' => 'evil', 'ok.txt' => 'ok')

    ::Zip::File.open(@zip_path) do |zf|
      plan = zf.extract_plan(@dest)
      refute plan.ok?
      assert_equal %i[path_traversal], plan.conflicts.map(&:kind)

      assert_raises(::Zip::ExtractPlanError) { plan.resolve('../evil.txt', :overwrite) }

      plan.skip_conflicts!
      assert plan.ok?
      plan.execute!
    end

    assert_equal 'ok', ::File.read(dest_path('ok.txt'))
    refute ::File.exist?(::File.join(@tmp, 'evil.txt'))
  end

  def test_case_fold_conflict_between_directories
    make_zip('Docs/a.txt' => '1', 'docs/b.txt' => '2')

    ::Zip::File.open(@zip_path) do |zf|
      plan = zf.extract_plan(@dest, case_sensitive: false)
      refute plan.ok?
      assert_includes plan.conflicts.map(&:kind), :case_conflict

      plan.skip_conflicts!
      plan.execute!
    end

    assert_equal '1', ::File.read(dest_path('Docs/a.txt'))
    refute ::File.exist?(dest_path('Docs/b.txt'))
    refute ::File.exist?(dest_path('docs/b.txt'))
  end

  def test_case_fold_conflict_on_same_target
    make_zip('Foo.txt' => '1', 'foo.txt' => '2')

    ::Zip::File.open(@zip_path) do |zf|
      plan = zf.extract_plan(@dest, case_sensitive: false)
      assert_includes plan.conflicts.map(&:kind), :case_conflict
    end
  end

  def test_case_fold_conflicts_ignored_when_case_sensitive
    make_zip('Docs/a.txt' => '1', 'docs/b.txt' => '2')

    ::Zip::File.open(@zip_path) do |zf|
      plan = zf.extract_plan(@dest, case_sensitive: true)
      assert plan.ok?
    end
  end

  def test_file_directory_conflict_within_archive
    make_zip('foo' => 'file', 'foo/bar.txt' => 'bar')

    ::Zip::File.open(@zip_path) do |zf|
      plan = zf.extract_plan(@dest)
      refute plan.ok?
      assert_equal %i[type_conflict], plan.conflicts.map(&:kind)
      assert_equal %i[skip], plan.items.first.allowed_resolutions

      plan.skip_conflicts!
      plan.execute!
    end

    assert ::File.directory?(dest_path('foo'))
    assert_equal 'bar', ::File.read(dest_path('foo/bar.txt'))
  end

  def test_file_directory_conflict_against_disk
    make_zip('foo' => 'file')
    ::FileUtils.mkdir_p(dest_path('foo'))

    ::Zip::File.open(@zip_path) do |zf|
      plan = zf.extract_plan(@dest)
      assert_equal %i[type_conflict], plan.conflicts.map(&:kind)
      assert_raises(::Zip::ExtractPlanError) { plan.resolve('foo', :overwrite) }
    end
  end

  def test_symlinks_are_skipped_by_default
    make_zip_with_symlink('safe-link', 'target.txt')

    ::Zip::File.open(@zip_path) do |zf|
      plan = zf.extract_plan(@dest)
      assert plan.ok?
      assert_equal :skip, plan.items.first.action
      plan.execute!
    end

    refute lexist?(dest_path('safe-link'))
  end

  def test_symlink_error_policy_reports_conflicts
    make_zip_with_symlink('safe-link', 'target.txt')

    ::Zip::File.open(@zip_path) do |zf|
      plan = zf.extract_plan(@dest, symlinks: :error)
      refute plan.ok?
      assert_equal %i[symlink], plan.conflicts.map(&:kind)

      plan.skip_conflicts!
      plan.execute!
    end

    refute lexist?(dest_path('safe-link'))
  end

  def test_symlink_allow_policy_extracts_safe_links
    make_zip_with_symlink('safe-link', 'target.txt')

    ::Zip::File.open(@zip_path) do |zf|
      plan = zf.extract_plan(@dest, symlinks: :allow)
      assert plan.ok?
      plan.execute!
    end

    assert ::File.symlink?(dest_path('safe-link'))
    assert_equal 'target.txt', ::File.readlink(dest_path('safe-link'))
  end

  def test_symlink_allow_policy_flags_escaping_targets
    outside = ::File.join(@tmp, 'outside.txt')
    make_zip_with_symlink('deep/evil-link', '../../outside.txt', existing_at_creation: outside)

    ::Zip::File.open(@zip_path) do |zf|
      plan = zf.extract_plan(@dest, symlinks: :allow)
      refute plan.ok?
      assert_equal %i[path_traversal], plan.conflicts.map(&:kind)

      plan.skip_conflicts!
      plan.execute!
    end

    refute lexist?(dest_path('deep/evil-link'))
  end

  def test_unknown_symlink_policy_raises
    make_zip('a.txt' => 'a')

    ::Zip::File.open(@zip_path) do |zf|
      assert_raises(ArgumentError) { zf.extract_plan(@dest, symlinks: :bogus) }
    end
  end

  def test_execute_rolls_back_everything_when_last_entry_fails
    make_zip('sub/a.txt' => 'aaa', 'b.txt' => 'bbb', 'c.txt' => 'ccc')
    corrupt_last_entry
    ::FileUtils.mkdir_p(@dest)
    ::File.write(dest_path('keep.txt'), 'keep')
    before = ::Dir.children(@dest).sort

    ::Zip::File.open(@zip_path) do |zf|
      plan = zf.extract_plan(@dest)
      assert plan.ok?
      assert_raises(::Zip::Error) { plan.execute! }
    end

    assert_equal before, ::Dir.children(@dest).sort
    assert_equal 'keep', ::File.read(dest_path('keep.txt'))
  end

  def test_execute_restores_overwritten_files_on_failure
    make_zip('keep.txt' => 'new content', 'c.txt' => 'ccc')
    corrupt_last_entry
    ::FileUtils.mkdir_p(@dest)
    ::File.write(dest_path('keep.txt'), 'old content')

    ::Zip::File.open(@zip_path) do |zf|
      plan = zf.extract_plan(@dest, overwrite: true)
      assert plan.ok?
      assert_raises(::Zip::Error) { plan.execute! }
    end

    assert_equal 'old content', ::File.read(dest_path('keep.txt'))
    refute ::File.exist?(dest_path('c.txt'))
  end

  def test_execute_rechecks_path_conditions_and_rolls_back
    make_zip('sub/a.txt' => 'a', 'b.txt' => 'b')
    outside = ::File.join(@tmp, 'outside')
    ::FileUtils.mkdir_p(dest_path('sub'))
    ::FileUtils.mkdir_p(outside)

    ::Zip::File.open(@zip_path) do |zf|
      plan = zf.extract_plan(@dest)
      assert plan.ok?

      # Swap in a symlink after planning: 'sub' now points outside the
      # destination, which the plan could not have known about.
      ::FileUtils.rm_rf(dest_path('sub'))
      ::File.symlink(outside, dest_path('sub'))

      assert_raises(::Zip::ExtractPlanError) { plan.execute! }
    end

    refute ::File.exist?(::File.join(outside, 'a.txt'))
    refute ::File.exist?(dest_path('b.txt'))
    assert ::File.symlink?(dest_path('sub'))
  end

  def test_execute_rechecks_new_files_appearing_on_disk
    make_zip('a.txt' => 'a', 'b.txt' => 'b')

    ::Zip::File.open(@zip_path) do |zf|
      plan = zf.extract_plan(@dest)
      assert plan.ok?

      ::FileUtils.mkdir_p(@dest)
      ::File.write(dest_path('b.txt'), 'surprise')

      assert_raises(::Zip::ExtractPlanError) { plan.execute! }
    end

    assert_equal 'surprise', ::File.read(dest_path('b.txt'))
    refute ::File.exist?(dest_path('a.txt'))
  end

  def test_summary_lists_targets_and_conflicts
    make_zip('../evil.txt' => 'x', 'ok.txt' => 'ok')

    ::Zip::File.open(@zip_path) do |zf|
      plan = zf.extract_plan(@dest)
      summary = plan.summary
      assert_match 'ok.txt', summary
      assert_match 'path_traversal', summary
    end
  end
end
