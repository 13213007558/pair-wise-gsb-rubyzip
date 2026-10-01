# frozen_string_literal: true

require 'tmpdir'

module Zip
  # Zip::ExtractPlan performs two-phase extraction of a Zip::File, intended
  # for batch imports where writing half an archive into a target directory
  # before discovering a problem is not acceptable.
  #
  # Phase one (planning) inspects every entry and records, without touching
  # the filesystem:
  #
  # - every target path that would be written;
  # - the overwrite decision for targets that already exist on disk;
  # - every conflict: path traversal attempts, entries whose names collide
  #   under case folding, file-vs-directory clashes (both within the archive
  #   and against the disk), and symlink entries (per the symlink policy).
  #
  # Phase two (execution) only runs once every conflict has been resolved
  # (see #resolve, #skip_conflicts! and #overwrite_all!). It re-verifies the
  # path conditions established during planning before each write and, if
  # anything fails, rolls back everything written by this run, restoring any
  # pre-existing files it overwrote.
  #
  # Example:
  #
  #   Zip::File.open('import.zip') do |zf|
  #     plan = zf.extract_plan('dest')
  #     puts plan.summary
  #     plan.skip_conflicts! # or plan.resolve('name', :overwrite), etc.
  #     plan.execute! if plan.ok?
  #   end
  #
  # The Zip::File must remain open while the plan is executed.
  class ExtractPlan
    # Valid policies for the +symlinks+ option.
    SYMLINK_POLICIES = %i[skip error allow].freeze

    # A problem discovered while planning. Conflicts must be resolved before
    # the plan can be executed.
    class Conflict
      # The planned item this conflict belongs to.
      attr_reader :item

      # One of :path_traversal, :case_conflict, :type_conflict, :exists or
      # :symlink.
      attr_reader :kind

      # A human-readable description of the problem.
      attr_reader :message

      def initialize(item, kind, message) # :nodoc:
        @item = item
        @kind = kind
        @message = message
      end

      def to_s
        "#{@item.name}: #{@message}"
      end
    end

    # A single planned extraction step: one archive entry mapped to its
    # target path, with any conflicts and the chosen resolution attached.
    class Item
      # The Zip::Entry this item extracts.
      attr_reader :entry

      # The entry name, as stored in the archive.
      attr_reader :name

      # The absolute path this entry would be written to.
      attr_reader :dest_path

      # :file, :directory or :symlink.
      attr_reader :kind

      # The Conflict objects found for this item.
      attr_reader :conflicts

      # The chosen resolution: nil (undecided), :skip or :overwrite.
      attr_reader :resolution

      # Why this item was skipped, if it was skipped automatically.
      attr_reader :note

      # The link target, for symlink items under the :allow policy.
      attr_accessor :symlink_target

      attr_writer :will_overwrite, :will_reuse # :nodoc:

      def initialize(entry, dest_path) # :nodoc:
        @entry = entry
        @name = entry.name
        @dest_path = dest_path
        @kind = entry.ftype
        @conflicts = []
        @resolution = nil
        @note = nil
        @skipped = false
        @will_overwrite = false
        @will_reuse = false
      end

      def add_conflict(kind, message) # :nodoc:
        @conflicts << Conflict.new(self, kind, message)
      end

      def skip!(note = nil) # :nodoc:
        @skipped = true
        @note = note
      end

      # True if this item will not be written, by policy or by resolution.
      def skipped?
        @skipped || @resolution == :skip
      end

      # True if this item would overwrite an existing file on disk.
      def will_overwrite?
        @will_overwrite
      end

      # True if this item is a directory that already exists on disk.
      def will_reuse?
        @will_reuse
      end

      # True if this item has conflicts without a chosen resolution.
      def unresolved?
        @conflicts.any? && @resolution.nil?
      end

      # The resolutions that may be applied to this item. :skip is always
      # available; :overwrite only when every conflict is an overwrite
      # decision (:exists or :case_conflict).
      def allowed_resolutions
        return [] if @conflicts.empty?
        return [:skip] if (@conflicts.map(&:kind) - %i[exists case_conflict]).any?

        %i[skip overwrite]
      end

      def resolve!(resolution) # :nodoc:
        unless allowed_resolutions.include?(resolution)
          raise ::Zip::ExtractPlanError,
                "cannot resolve '#{@name}' with :#{resolution}"
        end

        @resolution = resolution
      end

      # What ExtractPlan#execute! will do with this item: :create,
      # :overwrite, :reuse (an existing directory), :skip, or :conflict
      # (unresolved).
      def action
        return :skip if skipped?
        return :conflict if unresolved?
        return :reuse if @will_reuse
        return :overwrite if @resolution == :overwrite

        :create
      end
    end

    # The planned items, directories first, then other entries in archive
    # order.
    attr_reader :items

    # Builds a plan for extracting every entry of +zip_file+ (a Zip::File)
    # into +destination_directory+. Nothing is written to the filesystem.
    #
    # Options:
    #
    # - +overwrite+: when true, targets that already exist on disk are
    #   pre-resolved with :overwrite. When false (the default) they are
    #   reported as :exists conflicts.
    # - +symlinks+: :skip (the default, matching Zip::File#extract_all),
    #   :error (report every symlink entry as a conflict), or :allow
    #   (extract symlinks whose targets stay inside the destination).
    # - +case_sensitive+: whether the destination filesystem is
    #   case-sensitive. Defaults to auto-detection. When false, entries
    #   whose paths collide under case folding are reported as
    #   :case_conflict conflicts.
    def initialize(zip_file, destination_directory = '.', overwrite: false,
                   symlinks: :skip, case_sensitive: nil)
      unless SYMLINK_POLICIES.include?(symlinks)
        raise ArgumentError, "unknown symlink policy #{symlinks.inspect}"
      end

      @dest_dir = ::File.expand_path(destination_directory || '.')
      if ::File.exist?(@dest_dir) && !::File.directory?(@dest_dir)
        raise ::Zip::ExtractPlanError, "destination '#{@dest_dir}' is not a directory"
      end

      @zip_file = zip_file
      @symlink_policy = symlinks
      @case_sensitive = case_sensitive.nil? ? detect_case_sensitivity : case_sensitive
      @items = []
      build(overwrite)
    end

    # The absolute path of the directory entries will be extracted into.
    def destination_directory
      @dest_dir
    end

    # Every conflict found during planning, resolved or not.
    def conflicts
      @items.flat_map(&:conflicts)
    end

    # The conflicts that still need a resolution before #execute! can run.
    def unresolved_conflicts
      @items.select(&:unresolved?).flat_map(&:conflicts)
    end

    # True when no conflict is left unresolved and the plan can be executed.
    def ok?
      @items.none?(&:unresolved?)
    end

    # Resolves the conflicts on one item. +item_ref+ may be an Item, an
    # entry name, or a Zip::Entry. +resolution+ is :skip or :overwrite;
    # which of these is accepted depends on the conflicts (see
    # Item#allowed_resolutions).
    def resolve(item_ref, resolution)
      item = find_item(item_ref)
      raise ::Zip::ExtractPlanError, "no planned item for #{item_ref.inspect}" unless item

      item.resolve!(resolution)
      self
    end

    # Resolves every unresolved conflict by skipping the offending entry.
    def skip_conflicts!
      @items.select(&:unresolved?).each { |item| item.resolve!(:skip) }
      self
    end

    # Resolves every unresolved conflict that permits it with :overwrite.
    # Conflicts that can only be skipped (path traversal, type clashes,
    # symlink policy violations) are left unresolved.
    def overwrite_all!
      @items.select(&:unresolved?).each do |item|
        item.resolve!(:overwrite) if item.allowed_resolutions.include?(:overwrite)
      end
      self
    end

    # A human-readable listing of every planned target with its action,
    # resolution and conflicts.
    def summary
      @items.map do |item|
        parts = ["[#{item.action}] #{item.name} -> #{item.dest_path}"]
        parts << "(#{item.note})" if item.note
        parts << "resolved: #{item.resolution}" if item.resolution
        item.conflicts.each { |conflict| parts << "! #{conflict.kind}: #{conflict.message}" }
        parts.join(' ')
      end.join("\n")
    end

    # Extracts every planned item. Raises Zip::ExtractPlanError if any
    # conflict is unresolved. Path conditions established during planning
    # are re-verified before each write; on any failure everything written
    # by this run is rolled back and pre-existing files are restored.
    def execute!
      unless ok?
        names = @items.select(&:unresolved?).map(&:name)
        raise ::Zip::ExtractPlanError, "unresolved conflicts for: #{names.join(', ')}"
      end

      @undo = []
      @backup_dir = nil
      begin
        @backup_dir = ::Dir.mktmpdir('rubyzip-extract-plan')
        mkdir_p_tracked(@dest_dir)
        dest_real = ::File.realpath(@dest_dir)
        @items.each do |item|
          execute_item(item, dest_real) unless item.action == :skip
        end
        self
      rescue StandardError
        rollback!
        raise
      end
    ensure
      ::FileUtils.remove_entry(@backup_dir) if @backup_dir && ::File.exist?(@backup_dir)
    end

    private

    def build(overwrite)
      dirs, others = @zip_file.entries.partition(&:directory?)
      (dirs + others).each { |entry| @items << plan_item(entry, overwrite) }
      detect_internal_type_conflicts
      detect_case_conflicts unless @case_sensitive
    end

    def plan_item(entry, overwrite)
      dest_path = ::File.expand_path(::File.join(@dest_dir, entry.name))
      item = Item.new(entry, dest_path)

      if !within_dest?(dest_path)
        item.add_conflict(:path_traversal, 'entry path escapes the destination directory')
      elsif entry.symlink?
        plan_symlink(item, overwrite)
      else
        plan_regular(item, overwrite)
      end
      item
    end

    def plan_symlink(item, overwrite)
      case @symlink_policy
      when :skip
        item.skip!('symlink skipped by policy')
      when :error
        item.add_conflict(:symlink, 'symlink entries are not extracted by default')
      when :allow
        target = item.entry.get_input_stream { |is| is.read }
        item.symlink_target = target
        if within_dest?(::File.expand_path(target, ::File.dirname(item.dest_path)))
          plan_exists(item, overwrite)
        else
          item.add_conflict(:path_traversal,
                            "symlink target '#{target}' escapes the destination directory")
        end
      end
    end

    def plan_regular(item, overwrite)
      if item.kind == :directory
        plan_directory(item)
      else
        plan_exists(item, overwrite)
      end
    end

    def plan_directory(item)
      if ::File.exist?(item.dest_path) && !::File.directory?(item.dest_path)
        item.add_conflict(:type_conflict, 'a non-directory already exists at this path')
      elsif ::File.directory?(item.dest_path)
        item.will_reuse = true
      end
    end

    def plan_exists(item, overwrite)
      if ::File.directory?(item.dest_path)
        item.add_conflict(:type_conflict, 'a directory already exists at this path')
        return
      end

      existing = lexist?(item.dest_path)
      folded = case_fold_match(item.dest_path) if !existing && !@case_sensitive
      return unless existing || folded

      item.will_overwrite = true
      message = existing ? 'a file already exists at this path'
                         : "only differs in case from existing '#{folded}'"
      item.add_conflict(:exists, message)
      item.resolve!(:overwrite) if overwrite
    end

    # Flags file/symlink entries whose path another entry needs to be a
    # directory (e.g. a file 'foo' alongside 'foo/bar.txt' or 'foo/').
    def detect_internal_type_conflicts
      needed_dirs = {}
      @items.each do |item|
        next if item.skipped?

        dir = item.kind == :directory ? item.dest_path : ::File.dirname(item.dest_path)
        while within_dest?(dir) && dir != @dest_dir
          needed_dirs[dir] ||= item
          dir = ::File.dirname(dir)
        end
      end

      @items.each do |item|
        next if item.skipped? || item.kind == :directory

        other = needed_dirs[item.dest_path]
        next unless other

        item.add_conflict(:type_conflict,
                          "'#{other.name}' requires a directory at this path")
      end
    end

    # Flags entries whose paths collide with another entry's path when
    # compared case-insensitively (e.g. 'Docs/a.txt' and 'docs/b.txt').
    def detect_case_conflicts
      seen_targets = {}
      seen_dirs = {}
      @items.each do |item|
        next if item.skipped? || !within_dest?(item.dest_path)

        detect_target_case_conflict(item, seen_targets, seen_dirs)
        seen_targets[item.dest_path.downcase] ||= item

        dir = item.kind == :directory ? item.dest_path : ::File.dirname(item.dest_path)
        while within_dest?(dir) && dir != @dest_dir
          key = dir.downcase
          actual = seen_dirs[key]
          break if actual == dir

          if actual
            item.add_conflict(:case_conflict,
                              "directory '#{dir}' differs only in case from '#{actual}'")
            break
          end
          seen_dirs[key] = dir
          dir = ::File.dirname(dir)
        end
      end
    end

    def detect_target_case_conflict(item, seen_targets, seen_dirs)
      key = item.dest_path.downcase
      if (other = seen_targets[key])
        item.add_conflict(:case_conflict, "targets the same path as '#{other.name}'")
      elsif item.kind != :directory && (actual = seen_dirs[key]) && actual != item.dest_path
        item.add_conflict(:case_conflict, "differs only in case from directory '#{actual}'")
      end
    end

    # Finds a sibling of +path+ whose name only differs in case, if any.
    def case_fold_match(path)
      parent = ::File.dirname(path)
      return nil unless ::File.directory?(parent)

      base = ::File.basename(path)
      ::Dir.children(parent).find do |child|
        child != base && child.downcase == base.downcase
      end
    end

    def detect_case_sensitivity
      dir = @dest_dir
      dir = ::File.dirname(dir) until ::File.directory?(dir) || ::File.dirname(dir) == dir
      return true unless ::File.directory?(dir)

      probe = ::File.join(dir, ".rubyzip-case-probe-#{Process.pid}")
      swapped = ::File.join(dir, ::File.basename(probe).swapcase)
      ::File.write(probe, '')
      !::File.exist?(swapped)
    ensure
      ::File.delete(probe) if probe && ::File.exist?(probe)
    end

    def find_item(ref)
      return ref if ref.is_a?(Item)

      name = ref.respond_to?(:name) ? ref.name : ref.to_s
      @items.find { |item| item.name == name }
    end

    def execute_item(item, dest_real)
      verify_path!(item.dest_path, dest_real)

      case item.kind
      when :directory then execute_directory(item)
      when :file then execute_file(item)
      when :symlink then execute_symlink(item)
      end
    end

    def execute_directory(item)
      dest = item.dest_path
      return if ::File.directory?(dest) && !::File.symlink?(dest)

      if lexist?(dest)
        raise ::Zip::ExtractPlanError, "cannot create directory '#{dest}': path is in use"
      end

      mkdir_p_tracked(dest)
      item.entry.set_extra_attributes_on_path(dest)
    end

    def execute_file(item)
      dest = item.dest_path
      mkdir_p_tracked(::File.dirname(dest))
      prepare_target!(item, dest)
      item.entry.extract(item.name, destination_directory: @dest_dir,
                         create_parent_directories: false) { true }
    end

    def execute_symlink(item)
      dest = item.dest_path
      target = item.symlink_target
      unless within_dest?(::File.expand_path(target, ::File.dirname(dest)))
        raise ::Zip::ExtractPlanError, "symlink target '#{target}' escapes '#{@dest_dir}'"
      end

      mkdir_p_tracked(::File.dirname(dest))
      prepare_target!(item, dest)
      ::FileUtils.rm_f(dest)
      ::File.symlink(target, dest)
    end

    # Re-verifies, immediately before writing, what the plan established: a
    # :create target must still not exist, and an :overwrite target must
    # still be a replaceable file. Backs up or registers undo accordingly.
    def prepare_target!(item, dest)
      if lexist?(dest)
        verify_overwritable!(item, dest)
        backup!(dest)
      else
        @undo << -> { ::FileUtils.rm_f(dest) }
      end
    end

    def verify_overwritable!(item, dest)
      unless item.resolution == :overwrite
        raise ::Zip::ExtractPlanError, "'#{dest}' appeared on disk since the plan was made"
      end
      return if ::File.file?(dest) && !::File.symlink?(dest)
      return if item.kind == :symlink && ::File.symlink?(dest)

      raise ::Zip::ExtractPlanError, "'#{dest}' is no longer a regular file"
    end

    def backup!(path)
      if ::File.symlink?(path)
        target = ::File.readlink(path)
        @undo << lambda {
          ::FileUtils.rm_f(path)
          ::File.symlink(target, path)
        }
      else
        backup = ::File.join(@backup_dir, "backup-#{@undo.length}")
        ::FileUtils.cp(path, backup, preserve: true)
        @undo << lambda {
          ::FileUtils.rm_f(path)
          ::FileUtils.cp(backup, path, preserve: true)
        }
      end
    end

    # Re-checks at execution time that +path+ is inside the destination,
    # resolving any symlinks in the nearest existing ancestor.
    def verify_path!(path, dest_real)
      unless within_dest?(path)
        raise ::Zip::ExtractPlanError, "entry path '#{path}' escapes '#{@dest_dir}'"
      end

      ancestor = path
      ancestor = ::File.dirname(ancestor) until lexist?(ancestor) ||
                                               ::File.dirname(ancestor) == ancestor
      return if within_real?(::File.realpath(ancestor), dest_real)

      raise ::Zip::ExtractPlanError,
            "path '#{path}' escapes '#{@dest_dir}' via a symbolic link"
    end

    def within_real?(real, dest_real)
      real == dest_real || real.start_with?(dest_real + ::File::SEPARATOR)
    end

    def mkdir_p_tracked(dir)
      return if ::File.directory?(dir) && !::File.symlink?(dir)

      if lexist?(dir)
        raise ::Zip::ExtractPlanError, "cannot create directory '#{dir}': path is in use"
      end

      parent = ::File.dirname(dir)
      mkdir_p_tracked(parent) if parent != dir
      ::Dir.mkdir(dir)
      @undo << lambda {
        ::Dir.rmdir(dir) if ::File.directory?(dir) && !::File.symlink?(dir) && ::Dir.empty?(dir)
      }
    end

    def rollback!
      @undo.reverse_each do |undo|
        undo.call
      rescue StandardError => e
        warn "WARNING: rollback step failed: #{e.message}"
      end
    end

    def within_dest?(path)
      path == @dest_dir || path.start_with?(@dest_dir + ::File::SEPARATOR)
    end

    # Like File.exist?, but also true for dangling symbolic links.
    def lexist?(path)
      ::File.exist?(path) || ::File.symlink?(path)
    end
  end
end
