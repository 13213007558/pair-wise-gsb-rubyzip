# frozen_string_literal: true

module Zip
  class EntrySet # :nodoc:all
    include Enumerable

    attr_reader :entry_set
    protected   :entry_set

    def initialize(an_enumerable = [])
      super()
      @entry_set = {}
      an_enumerable.each { |o| push(o) }
    end

    def include?(entry)
      @entry_set.include?(to_key(entry))
    end

    # Returns the single entry matching `entry` (or `nil` if there isn't
    # one) when `Zip.allow_duplicate_entry_names` is off. When it's on,
    # returns an Array of every entry matching `entry` (empty if there are
    # none).
    def find_entry(entry)
      bucket = @entry_set[to_key(entry)]
      bucket ||= find_by_display_name(entry) unless entry.kind_of?(::Zip::Entry)
      return bucket&.first unless ::Zip.allow_duplicate_entry_names

      # Return a copy, not the live bucket, so callers iterating the result
      # (e.g. to delete entries one by one) aren't mutating storage they're
      # currently iterating over.
      bucket ? bucket.dup : []
    end

    def <<(entry)
      return unless entry

      key = to_key(entry)
      if ::Zip.allow_duplicate_entry_names
        (@entry_set[key] ||= []) << entry
      else
        @entry_set[key] = [entry]
      end
    end

    alias push <<

    def size
      @entry_set.each_value.sum(&:size)
    end

    alias length size

    def delete(entry)
      key = to_key(entry)
      bucket = @entry_set[key]
      return nil unless bucket

      # A bucket can only hold more than one entry when duplicates are
      # allowed, so only then is there any ambiguity about *which* one to
      # remove worth resolving by identity/equality. Off, preserve the
      # original by-name-only semantics exactly: whatever is in the
      # (at most one-element) bucket gets removed, regardless of whether it
      # matches `entry` itself - the argument doesn't have to be the exact
      # stored object, just something that resolves to the same key.
      idx =
        if ::Zip.allow_duplicate_entry_names
          bucket.index { |e| e.equal?(entry) } || bucket.index(entry)
        else
          0
        end
      return nil unless idx

      removed = bucket.delete_at(idx)
      @entry_set.delete(key) if bucket.empty?
      removed
    end

    def each(&block)
      entries.each(&block)
    end

    def entries
      sorted_entries.values.flatten(1)
    end

    # deep clone
    def dup
      # Use raw insertion order (@entry_set.values), not the
      # Zip.sort_entries-dependent #entries, so the copy's internal storage
      # order doesn't end up depending on the sort flag's value at the
      # moment of duping.
      EntrySet.new(@entry_set.values.flatten(1).map(&:dup))
    end

    def ==(other)
      return false unless other.kind_of?(EntrySet)

      @entry_set.values == other.entry_set.values
    end

    def parent(entry)
      parent_name = entry.parent_as_string
      bucket = @entry_set[to_key(parent_name)] || find_by_display_name(parent_name)
      return bucket&.first unless ::Zip.allow_duplicate_entry_names

      bucket ? bucket.dup : []
    end

    def glob(pattern, flags = ::File::FNM_PATHNAME | ::File::FNM_DOTMATCH | ::File::FNM_EXTGLOB)
      entries.filter_map do |entry|
        next nil unless ::File.fnmatch(pattern, entry.name.chomp('/'), flags)

        yield(entry) if block_given?
        entry
      end
    end

    protected

    def sorted_entries
      ::Zip.sort_entries ? @entry_set.sort.to_h : @entry_set
    end

    private

    def to_key(entry)
      # Entries read from an archive are keyed by their raw name bytes, so
      # that two entries whose names differ on disk but normalise to the
      # same Unicode display name don't overwrite each other here.
      k = entry.kind_of?(::Zip::Entry) && entry.raw_name ? entry.raw_name : entry.to_s
      k = k.chomp('/')
      k.downcase! if ::Zip.case_insensitive_match
      k
    end

    # Fallback for name-based lookups that don't match any raw name key:
    # compare against the entries' Unicode display names, so that e.g. an
    # entry stored with CP437 name bytes can still be found by its
    # transcoded name.
    def find_by_display_name(name)
      key = name.to_s.chomp('/')
      key = key.downcase if ::Zip.case_insensitive_match
      matches = entries.select do |entry|
        display = entry.name.chomp('/')
        display = display.downcase if ::Zip.case_insensitive_match
        display == key
      end
      matches.empty? ? nil : matches
    end
  end
end

# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
