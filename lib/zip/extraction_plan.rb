# frozen_string_literal: true

require 'tmpdir'

module Zip
  class ExtractionPlan
    Target = Struct.new(:name, :path, :entry, :type, :action, :existing, keyword_init: true)
    Conflict = Struct.new(:reason, :target_name, :path, :message, keyword_init: true)

    attr_reader :destination, :targets, :conflicts, :symlinks

    def initialize(entries, destination, symlinks: :skip, &on_conflict)
      @destination = ::File.absolute_path(destination)
      @symlinks = symlinks
      @on_conflict = on_conflict
      @targets = []
      @targets_by_name = {}
      @conflicts = []
      @archive_paths = {}
      @folded_paths = {}

      raise ArgumentError, "unsupported symlink policy #{@symlinks.inspect}" unless
        %i[skip raise].include?(@symlinks)

      build(entries)
    end

    def valid?
      conflicts.empty?
    end

    def target_names
      targets.map(&:name)
    end

    def execute
      raise ExtractionPlanError, conflicts unless valid?

      root_existed_before = ::File.exist?(destination) || ::File.symlink?(destination)
      created_root_chain = []
      verify_root!
      create_destination_if_needed { |path| created_root_chain << path }

      transaction = nil
      begin
        transaction = Transaction.new(destination)
        stage_files(transaction)

        targets.each do |target|
          verify_target!(target)
          verify_ancestors!(target)
          execute_target(target, transaction)
        end
        transaction.commit
      rescue StandardError
        transaction&.rollback
        raise
      ensure
        transaction&.cleanup
        remove_created_root_chain(created_root_chain, root_existed_before)
      end

      self
    end

    private

    def build(entries)
      entries.each { |entry| add_entry(entry) }
      finalize_target_order!
    end

    def add_entry(entry)
      name = normalized_name(entry.name)
      if name.nil?
        add_conflict(
          :unsafe_path, entry.name, destination,
          'entry escapes the destination directory'
        )
        return
      end

      if entry.symlink?
        if @symlinks == :raise
          add_conflict(
            :symlink_not_allowed, name, target_path(name),
            'symlink entries are not allowed'
          )
        elsif @archive_paths.key?(name) || @targets_by_name[name]&.entry
          add_conflict(:duplicate_entry, name, target_path(name),
                       'archive contains a symlink and another entry at this path')
        else
          add_target(name, entry, :symlink, :skip, :none)
        end
        return
      end

      ensure_ancestor_directories(name, entry)
      add_archive_path(name, entry.directory? ? :directory : :file, entry)
    end

    def normalized_name(raw_name)
      name = raw_name.to_s
      return nil if name.empty? || name.include?("\0")

      return nil if name.start_with?('/')

      name = name.gsub('\\', '/')
      clean_path = Pathname.new(name).cleanpath
      return nil if clean_path.absolute? || clean_path.each_filename.any? { |part| part == '..' }
      path = target_path(clean_path.to_s)
      return nil if path == destination || !path.start_with?(destination + ::File::SEPARATOR)

      clean_path.to_s
    end

    def target_path(name)
      ::File.expand_path(::File.join(destination, name))
    end

    def ensure_ancestor_directories(name, entry)
      dirname = Pathname.new(name).dirname
      return if dirname.to_s == '.'

      parts = []
      dirname.each_filename do |part|
        parts << part
        ancestor_name = ::File.join(*parts)
        ancestor = add_target(ancestor_name, nil, :directory, nil, :none)
        if ancestor.type == :file
          add_conflict(:file_directory_conflict, ancestor_name, ancestor.path,
                       'archive contains both a file and directory at this path')
        elsif ancestor.type == :symlink
          ancestor.type = :directory
          inspect_existing_final_target(ancestor)
          if ancestor.existing == :symlink
            ancestor.action = :conflict
            add_conflict(:existing_symlink_ancestor, ancestor_name, ancestor.path,
                         'existing path is a symlink')
          end
        end
      end
    end

    def add_archive_path(name, type, entry)
      existing_type = @archive_paths[name]

      if incompatible_types?(existing_type, type)
        add_conflict(:file_directory_conflict, name, target_path(name),
                     'archive contains both a file and directory at this path')
      elsif duplicate_entries?(existing_type, type)
        add_conflict(:duplicate_entry, name, target_path(name),
                     'archive contains duplicate entries at this path')
      end

      add_target(name, entry, type, nil, :none)
      @archive_paths[name] ||= type
    end

    def incompatible_types?(first, second)
      first && second && first != second
    end

    def duplicate_entries?(first, second)
      first == :file && second == :file
    end

    def add_target(name, entry, type, action, existing)
      target = @targets_by_name[name]
      if target
        target.entry ||= entry
        target.type = type if entry
        add_case_conflict(name)
        return target
      end

      target = Target.new(
        name: name,
        path: target_path(name),
        entry: entry,
        type: type,
        action: action,
        existing: existing
      )
      add_case_conflict(name)
      inspect_existing_target(target)
      @targets_by_name[name] = target
      @targets << target
      target
    end

    def inspect_existing_target(target)
      inspect_existing_final_target(target)
      add_filesystem_case_conflicts(target)
    end

    def inspect_existing_final_target(target)
      return if target.type == :symlink
      return unless ::File.exist?(target.path) || ::File.symlink?(target.path)

      target.existing = if ::File.symlink?(target.path)
                          :symlink
                        elsif ::File.directory?(target.path)
                          :directory
                        else
                          :file
                        end
      decide_existing_target(target)
    end

    def decide_existing_target(target)
      if target.type == :directory && target.entry.nil?
        decide_existing_implicit_directory(target)
        return
      end

      case [target.type, target.existing]
      in [:directory, :directory]
        target.action = :merge
      in [:file, :file] | [:file, :symlink] | [:directory, :symlink]
        target.action = allow_overwrite?(target) ? :overwrite : :conflict
        unless target.action == :overwrite
          @conflicts << Conflict.new(
            reason: :destination_exists,
            target_name: target.name,
            path: target.path,
            message: 'destination already exists'
          )
        end
      in [:file, :directory]
        target.action = :conflict
        add_conflict(:file_directory_conflict, target.name, target.path,
                     'destination is an existing directory')
      in [:directory, :file]
        target.action = :conflict
        add_conflict(:file_directory_conflict, target.name, target.path,
                     'destination is an existing file')
      else
        target.action = :conflict
      end
    end

    def decide_existing_implicit_directory(target)
      target.action = case target.existing
                      when :directory
                        :merge
                      when :symlink
                        :conflict
                      else
                        :conflict
                      end
      return unless ::File.exist?(target.path) || ::File.symlink?(target.path)
      add_conflict(:existing_symlink_ancestor, target.name, target.path,
                   'existing path is a symlink') if target.existing == :symlink
      add_conflict(:existing_file_ancestor, target.name, target.path,
                   'existing path is not a directory') unless target.existing == :directory
    end

    def allow_overwrite?(target)
      !!@on_conflict&.call(target.entry, target.path)
    end

    def add_filesystem_case_conflicts(target)
      parent = ::File.dirname(target.path)
      return unless ::File.directory?(parent)

      basename = ::File.basename(target.path)
      ::Dir.children(parent).each do |child|
        next unless child.casecmp?(basename) && child != basename

        add_conflict(:case_conflict, target.name, target.path,
                     'destination contains a path that differs only by case')
      end
    end

    def add_case_conflict(name)
      conflicting_name = @folded_paths.keys.find { |candidate| candidate.casecmp?(name) }
      if conflicting_name && conflicting_name != name
        add_conflict(:case_conflict, name, target_path(name),
                     'archive entries or destinations differ only by case')
      else
        @folded_paths[name] ||= true
      end
    end

    def add_conflict(reason, target_name, path, message, conflict_name = target_name)
      @conflicts << Conflict.new(
        reason: reason,
        target_name: conflict_name,
        path: path,
        message: message
      )
    end

    def finalize_target_order!
      directories, files = targets.partition { |target| target.type == :directory }
      symlinks, files = files.partition { |target| target.type == :symlink }
      @targets = directories.sort_by(&:name) + files.sort_by(&:name) + symlinks.sort_by(&:name)
      @targets.each { |target| target.action ||= :create }
    end

    def verify_root!
      return unless ::File.symlink?(destination) ||
                    (::File.exist?(destination) && !::File.directory?(destination))

      raise ExtractionPlanError, [
        Conflict.new(reason: :invalid_destination, target_name: '', path: destination,
                     message: 'destination must be a directory')
      ]
    end

    def verify_target!(target)
      raise Errno::ENOENT, destination unless ::File.directory?(destination)

      current = current_type(target.path)
      expected = case target.action
                 when :create then :none
                 when :skip then %i[none file symlink directory]
                 when :merge then :directory
                 when :overwrite then %i[file symlink]
                 end
      expected = Array(expected)
      return if expected.include?(current)

      raise Error, "destination changed before extraction: #{target.name}"
    end

    def verify_ancestors!(target)
      ancestor = Pathname.new(target.path).dirname
      while ancestor.to_s.length >= destination.length
        next_ancestor = ancestor.dirname
        if archive_symlink_direct_parent?(target, ancestor)
          return
        end

        unless ::File.directory?(ancestor.to_s) && !::File.symlink?(ancestor.to_s)
          raise Error, "destination ancestor changed before extraction: #{target.name}"
        end
        break if ancestor.to_s == destination

        ancestor = next_ancestor
      end
    end

    def archive_symlink_direct_parent?(target, ancestor)
      relative_ancestor = ancestor.to_s.delete_prefix(destination + ::File::SEPARATOR)
      return false unless ::File.dirname(target.name) == relative_ancestor

      @targets_by_name[relative_ancestor]&.entry&.symlink?
    end

    def remove_created_root_chain(paths, root_existed)
      return if root_existed

      paths.reverse_each { |path| ::Dir.rmdir(path) }
    rescue Errno::ENOTEMPTY, Errno::ENOENT
      nil
    end

    def create_destination_if_needed
      Pathname.new(destination).descend do |path|
        path = path.to_s
        next if ::File.directory?(path) && !::File.symlink?(path)
        raise Error, "destination path is not a directory: #{path}" if
          ::File.symlink?(path) || ::File.exist?(path)

        ::Dir.mkdir(path)
        yield(path)
      end
    end

    def current_type(path)
      return :none unless ::File.exist?(path) || ::File.symlink?(path)
      return :symlink if ::File.symlink?(path)
      return :directory if ::File.directory?(path)

      :file
    end

    def execute_target(target, transaction)
      case target.type
      when :directory
        execute_directory(target, transaction)
      when :file
        execute_file(target, transaction)
      when :symlink
        warn "WARNING: skipped symlink '#{target.entry&.name || target.name}' during extract_all."
      end
    end

    def execute_directory(target, transaction)
      case target.action
      when :create
        if target.entry&.symlink?
          warn "WARNING: skipped symlink '#{target.entry.name}' during extract_all."
          return
        end
        transaction.create_directory(target)
      when :merge
        nil
      when :overwrite
        transaction.replace_existing_with_directory(target)
      when :skip
        warn "WARNING: skipped symlink '#{target.name}' during extract_all."
      end
    end

    def execute_file(target, transaction)
      staged_path = ::File.join(transaction.staging_root, target.name)
      if target.action == :overwrite
        transaction.replace_existing_with_file(target, staged_path)
      else
        transaction.create_parent_directories(target)
        transaction.install_new_file(target, staged_path)
      end
    end

    def stage_files(transaction)
      targets.each do |target|
        next unless target.type == :file

        staged_path = transaction.stage_file(target)
        ::FileUtils.mkdir_p(::File.dirname(staged_path))
        target.entry.extract(target.name, destination_directory: transaction.staging_root)
      end
    end

    class Transaction
      attr_reader :staging_root

      def initialize(destination)
        @destination = destination
        @staging_root = ::Dir.mktmpdir('.rubyzip-extract-stage', destination)
        @backup_root = ::File.join(@staging_root, 'backup')
        @installed = []
        @replaced = []
        @created_directories = []
        ::FileUtils.mkdir_p(@backup_root)
      end

      def stage_file(target)
        ::File.join(staging_root, target.name)
      end

      def create_directory(target)
        ::Dir.mkdir(target.path)
        @created_directories << target
      rescue Errno::EEXIST
        raise unless ::File.directory?(target.path)
      end

      def create_parent_directories(target)
        parent = Pathname.new(target.path).dirname
        parts = []
        missing = []

        parent.each_filename do |part|
          parts << part
          next unless parts.length > destination_parts.length

          path = ::File.join(@destination, *parts[destination_parts.length..])
          next if ::File.directory?(path) && !::File.symlink?(path)

          if ::File.symlink?(path) || (::File.exist?(path) && !::File.directory?(path))
            raise Error, "destination ancestor changed before extraction: #{target.name}"
          end

          missing << path
        end

        missing.each { |path| ::Dir.mkdir(path) }
      end

      def replace_existing_with_directory(target)
        backup_path = backup_for(target.name)
        ::File.rename(target.path, backup_path)
        ::Dir.mkdir(target.path)
        @replaced << [target, backup_path, :directory]
      end

      def replace_existing_with_file(target, staged_path)
        backup_path = backup_for(target.name)
        ::File.rename(target.path, backup_path)
        ::File.rename(staged_path, target.path)
        @replaced << [target, backup_path, :file]
      end

      def install_new_file(target, staged_path)
        ::File.rename(staged_path, target.path)
        @installed << target
      end

      def commit
        @created_directories.each do |target|
          target.entry&.set_extra_attributes_on_path(target.path)
        end
        @replaced.each do |target, _backup, type|
          target.entry.set_extra_attributes_on_path(target.path) if type == :directory
        end
      end

      def rollback
        @installed.reverse_each do |target|
          ::FileUtils.rm_f(target.path) if ::File.file?(target.path)
        end

        @replaced.reverse_each do |target, backup_path, replacement_type|
          if replacement_type == :directory
            if ::File.directory?(target.path) && !::File.symlink?(target.path)
              ::Dir.rmdir(target.path)
            end
          elsif ::File.file?(target.path) && !::File.symlink?(target.path)
            ::FileUtils.rm_f(target.path)
          end
          if ::File.exist?(backup_path) || ::File.symlink?(backup_path)
            ::File.rename(backup_path, target.path)
          end
        end

        @created_directories.reverse_each do |target|
          ::Dir.rmdir(target.path) if ::File.directory?(target.path)
        end
      rescue StandardError
        nil
      end

      def cleanup
        ::FileUtils.rm_rf(staging_root)
      end

      private

      def destination_parts
        Pathname.new(@destination).each_filename.to_a
      end

      def backup_for(name)
        path = ::File.join(@backup_root, name)
        ::FileUtils.mkdir_p(::File.dirname(path))
        path
      end
    end
  end
end
