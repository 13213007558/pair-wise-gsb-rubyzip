# frozen_string_literal: true

require 'etc'

module Zip
  # Compresses one entry as independently compressed chunks and concatenates
  # those chunks into a single raw deflate stream. Chunks other than the last
  # are flushed with Zlib::FULL_FLUSH, so they reset the dictionary and end on
  # a byte boundary. Only the final chunk is finished with Zlib::FINISH.
  class ParallelDeflater < Compressor # :nodoc:all
    DEFAULT_CHUNK_SIZE = 1 << 20

    class Future # :nodoc:all
      def initialize(job, mutex, condition)
        @job = job
        @mutex = mutex
        @condition = condition
        @complete = false
        @canceled = false
      end

      def run
        return if canceled?

        result = @job.call
        @mutex.synchronize do
          @result = result unless @canceled
          @error = nil
          @complete = true
          @condition.broadcast
        end
      rescue StandardError => e
        @mutex.synchronize do
          @error = e unless @canceled
          @complete = true
          @condition.broadcast
        end
      end

      def cancel
        @mutex.synchronize do
          @canceled = true
          @complete = true
          @condition.broadcast
        end
      end

      def canceled?
        @mutex.synchronize { @canceled }
      end

      def value
        @mutex.synchronize do
          @condition.wait(@mutex) until @complete
          return if @canceled

          raise @error if @error

          @result
        end
      end
    end

    class SerialExecutor # :nodoc:all
      class Future # :nodoc:all
        def initialize(job)
          @job = job
        end

        def value
          @job.call
        end
      end

      def post(&job)
        Future.new(job)
      end

      def shutdown
        nil
      end
    end

    class ThreadPoolExecutor # :nodoc:all
      STOP = Object.new.freeze

      def initialize(workers)
        raise ArgumentError, 'workers must be greater than zero' if workers < 1

        @queue = Queue.new
        @mutex = Mutex.new
        @condition = ConditionVariable.new
        @workers = Array.new(workers) { Thread.new(&method(:worker)) }
        @shutdown = false
      end

      def post(&job)
        future = Future.new(job, @mutex, @condition)
        @mutex.synchronize do
          raise Error, 'executor has shut down' if @shutdown

          @queue << future
        end
        future
      end

      def cancel(futures)
        @mutex.synchronize do
          futures.each do |future|
            future.cancel if future.respond_to?(:cancel)
          end
        end
      end

      def shutdown
        @mutex.synchronize do
          return if @shutdown

          @shutdown = true
          @workers.size.times { @queue << STOP }
        end
        @workers.each(&:join)
      end

      private

      def worker
        while (job = @queue.pop) != STOP
          if job.respond_to?(:canceled?) && job.canceled?
            next
          end

          job.run
        end
      end
    end

    def initialize(
      output_stream,
      level = Zip.default_compression,
      encrypter = NullEncrypter.new,
      chunk_size: DEFAULT_CHUNK_SIZE,
      max_workers: default_worker_count,
      executor: nil,
      max_pending_chunks: nil
    )
      super()
      raise ArgumentError, 'chunk_size must be greater than zero' if chunk_size < 1
      raise ArgumentError, 'max_workers must be greater than zero' if max_workers < 1
      unless max_pending_chunks.nil? || max_pending_chunks.positive?
        raise ArgumentError, 'max_pending_chunks must be greater than zero'
      end

      @output_stream = output_stream
      @level = level
      @encrypter = encrypter
      @chunk_size = chunk_size
      @max_pending_chunks = max_pending_chunks || max_workers
      @buffer = +''.b
      @futures = []
      @next_chunk_index = 0
      @size = 0
      @crc = Zlib.crc32
      @finished = false
      @executor, @owned_executor = resolve_executor(executor, max_workers)
    end

    def <<(data)
      raise IOError, 'closed stream' if @finished

      value = data.to_s.b
      @crc = Zlib.crc32(value, @crc)
      @size += value.bytesize
      @buffer << value

      schedule_full_chunks
      @output_stream
    end

    def finish
      return if @finished

      schedule_chunk(@buffer, true)
      @buffer = +''.b
      write_available_chunks until @futures.empty?
      @finished = true
    rescue StandardError
      cancel_remaining_chunks
      raise
    ensure
      @owned_executor.shutdown if @owned_executor.respond_to?(:shutdown)
    end

    attr_reader :size, :crc

    private

    def default_worker_count
      [Etc.nprocessors, 1].max
    end

    def resolve_executor(executor, max_workers)
      case executor
      when nil
        if max_workers == 1
          [SerialExecutor.new, true]
        else
          [ThreadPoolExecutor.new(max_workers), true]
        end
      when :serial
        [SerialExecutor.new, true]
      when :thread
        [ThreadPoolExecutor.new(max_workers), true]
      else
        [executor, false]
      end
    end

    def schedule_full_chunks
      while @buffer.bytesize >= @chunk_size
        chunk = @buffer.byteslice(0, @chunk_size)
        @buffer = @buffer.byteslice(@chunk_size, @buffer.bytesize - @chunk_size)
        schedule_chunk(chunk, false)
      end
    end

    def schedule_chunk(chunk, final)
      make_room_for_chunk
      index = @next_chunk_index
      @next_chunk_index += 1
      future = submit_chunk(index, chunk, final)
      @futures << future
    end

    def make_room_for_chunk
      write_available_chunks while @futures.size >= @max_pending_chunks
    end

    def submit_chunk(index, chunk, final)
      executor_method(@executor).call do
        self.class.deflate_chunk(chunk, @level, final)
      rescue StandardError => error
        raise error.exception("chunk #{index}: #{error.message}")
      end
    end

    def executor_method(executor)
      if executor.respond_to?(:post)
        executor.method(:post)
      elsif executor.respond_to?(:call)
        executor
      else
        raise ArgumentError, 'executor must respond to post or call'
      end
    end

    def write_available_chunks
      future = @futures.first
      compressed = future_value(future)
      @futures.shift
      @output_stream << @encrypter.encrypt(compressed) unless compressed.empty?
    rescue StandardError
      @futures.shift
      cancel_remaining_chunks
      raise
    end

    def future_value(future)
      if future.respond_to?(:value!)
        future.value!
      elsif future.respond_to?(:value)
        future.value
      else
        future.wait
        future.value
      end
    end

    def cancel_remaining_chunks
      futures = @futures
      @futures = []
      if @executor.respond_to?(:cancel)
        @executor.cancel(futures)
      else
        futures.each { |future| future.cancel if future.respond_to?(:cancel) }
      end
    end

    def self.deflate_chunk(data, level, final)
      deflater = ::Zlib::Deflate.new(level, -::Zlib::MAX_WBITS)
      flush = final ? ::Zlib::FINISH : ::Zlib::FULL_FLUSH
      deflater.deflate(data, flush)
    ensure
      if deflater
        deflater.reset unless deflater.finished?
        deflater.close
      end
    end
  end
end

# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
