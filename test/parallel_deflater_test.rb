# frozen_string_literal: true

require_relative 'test_helper'

class ParallelDeflaterTest < Minitest::Test
  class ReverseExecutor
    class Future
      attr_reader :index
      attr_accessor :canceled

      def initialize(index, job, mutex, condition)
        @index = index
        @job = job
        @mutex = mutex
        @condition = condition
        @complete = false
        @canceled = false
      end

      def run
        @mutex.synchronize do
          return if @canceled

          @result = @job.call
          @complete = true
          @condition.broadcast
        end
      end

      def value
        @mutex.synchronize do
          @condition.wait(@mutex) until @complete
          @result
        end
      end

      def cancel
        @mutex.synchronize do
          @canceled = true
          @complete = true
          @condition.broadcast
        end
      end
    end

    attr_reader :completed

    def initialize
      @mutex = Mutex.new
      @condition = ConditionVariable.new
      @futures = []
      @completed = []
    end

    def post(&job)
      @mutex.synchronize do
        index = @futures.size
        future = Future.new(index, job, @mutex, @condition)
        @futures << future
        future
      end
    end

    def run_reverse!
      futures = @mutex.synchronize { @futures.dup }
      futures.reverse_each do |future|
        future.run
        @completed << future.index
      end
    end

    def size
      @mutex.synchronize { @futures.size }
    end
  end

  class CountingExecutor < Zip::ParallelDeflater::ThreadPoolExecutor
    attr_reader :maximum_active

    def initialize
      @count_mutex = Mutex.new
      @active = 0
      @maximum_active = 0
      super(2)
    end

    def post(&job)
      super do
        activate
        begin
          job.call
        ensure
          deactivate
        end
      end
    end

    private

    def activate
      @count_mutex.synchronize do
        @active += 1
        @maximum_active = [@maximum_active, @active].max
      end
    end

    def deactivate
      @count_mutex.synchronize { @active -= 1 }
    end
  end

  class SuccessfulFuture
    def initialize(job)
      @result = job.call
    end

    attr_reader :result
    alias value result
  end

  class CallExecutor
    class Future
      def initialize(job)
        @job = job
      end

      def value
        @job.call
      end
    end

    def call(&job)
      Future.new(job)
    end
  end

  class FailedFuture
    def initialize(error)
      @error = error
    end

    def value
      raise @error
    end
  end

  class QueuedFuture
    attr_reader :canceled

    def initialize(job)
      @job = job
      @canceled = false
    end

    def cancel
      @canceled = true
    end

    def value
      raise 'queued job should have been canceled'
    end
  end

  class FailureExecutor
    attr_reader :submitted, :canceled

    def initialize
      @submitted = 0
      @canceled = []
    end

    def post(&job)
      index = @submitted
      @submitted += 1
      case index
      when 0, 1
        SuccessfulFuture.new(job)
      when 2
        FailedFuture.new(RuntimeError.new('boom'))
      else
        QueuedFuture.new(job)
      end
    end

    def cancel(futures)
      futures.each do |future|
        future.cancel
        @canceled << future
      end
    end
  end

  def test_writes_chunks_in_order_when_they_complete_in_reverse_order
    data = ('abcdefghijklmnopqrstuvwxyz' * 25).b
    output = StringIO.new
    executor = ReverseExecutor.new
    deflater = Zip::ParallelDeflater.new(
      output,
      Zlib::DEFAULT_COMPRESSION,
      Zip::NullEncrypter.new,
      chunk_size: 100,
      max_workers: 8,
      executor: executor
    )

    runner = Thread.new do
      sleep 0.001 until executor.size == 7
      executor.run_reverse!
    end
    deflater << data
    deflater.finish
    runner.join

    assert_equal [6, 5, 4, 3, 2, 1, 0], executor.completed
    assert_equal data, inflate(output.string)
    assert_equal data.bytesize, deflater.size
    assert_equal Zlib.crc32(data), deflater.crc
  end

  def test_single_worker_uses_the_same_chunked_stream
    data = ('abcdefghijklmnopqrstuvwxyz' * 25).b
    output = StringIO.new
    deflater = Zip::ParallelDeflater.new(
      output,
      Zlib::DEFAULT_COMPRESSION,
      Zip::NullEncrypter.new,
      chunk_size: 100,
      max_workers: 1
    )

    assert_kind_of Zip::ParallelDeflater::SerialExecutor,
                   deflater.instance_variable_get(:@executor)
    deflater << data
    deflater.finish

    assert_equal data, inflate(output.string)
  end

  def test_empty_member_has_one_finished_stream
    output = StringIO.new
    deflater = Zip::ParallelDeflater.new(
      output,
      Zlib::DEFAULT_COMPRESSION,
      Zip::NullEncrypter.new,
      chunk_size: 100,
      max_workers: 1
    )

    deflater.finish

    assert_equal '', inflate(output.string)
    assert_equal 0, deflater.size
    assert_equal Zlib.crc32(''), deflater.crc
  end

  def test_small_member_uses_one_finished_chunk
    data = 'abc'.b
    output = StringIO.new
    deflater = Zip::ParallelDeflater.new(
      output,
      Zlib::DEFAULT_COMPRESSION,
      Zip::NullEncrypter.new,
      chunk_size: 100,
      max_workers: 1
    )

    deflater << data
    deflater.finish

    assert_equal data, inflate(output.string)
  end

  def test_executor_can_accept_blocks_through_call
    data = ('abcdefghijklmnopqrstuvwxyz' * 25).b
    output = StringIO.new
    deflater = Zip::ParallelDeflater.new(
      output,
      Zlib::DEFAULT_COMPRESSION,
      Zip::NullEncrypter.new,
      chunk_size: 100,
      max_workers: 1,
      executor: CallExecutor.new
    )

    deflater << data
    deflater.finish

    assert_equal data, inflate(output.string)
  end

  def test_pending_chunk_limit_is_independent_of_worker_count
    data = ('abcdefghijklmnopqrstuvwxyz' * 25).b
    output = StringIO.new
    executor = CountingExecutor.new
    deflater = Zip::ParallelDeflater.new(
      output,
      Zlib::DEFAULT_COMPRESSION,
      Zip::NullEncrypter.new,
      chunk_size: 100,
      max_workers: 2,
      max_pending_chunks: 4,
      executor: executor
    )

    deflater << data
    deflater.finish
    executor.shutdown

    assert_equal 2, executor.maximum_active
    assert_equal data, inflate(output.string)
  end

  def test_limits_completed_and_running_chunks_in_memory
    data = ('abcdefghijklmnopqrstuvwxyz' * 25).b
    output = StringIO.new
    executor = CountingExecutor.new
    deflater = Zip::ParallelDeflater.new(
      output,
      Zlib::DEFAULT_COMPRESSION,
      Zip::NullEncrypter.new,
      chunk_size: 100,
      max_workers: 2,
      executor: executor
    )

    deflater << data
    deflater.finish
    executor.shutdown

    assert_equal 2, executor.maximum_active
    assert_equal data, inflate(output.string)
  end

  def test_failure_cancels_remaining_chunks_without_a_final_block
    data = ('abcdefghijklmnopqrstuvwxyz' * 25).b
    output = StringIO.new
    executor = FailureExecutor.new
    deflater = Zip::ParallelDeflater.new(
      output,
      Zlib::DEFAULT_COMPRESSION,
      Zip::NullEncrypter.new,
      chunk_size: 100,
      max_workers: 2,
      executor: executor
    )

    error = assert_raises(RuntimeError) { deflater << data }
    assert_equal 'boom', error.message
    assert_equal 4, executor.submitted
    assert_equal 1, executor.canceled.size
    assert executor.canceled.first.canceled

    inflater = Zlib::Inflate.new(-Zlib::MAX_WBITS)
    inflater.inflate(output.string)
    refute inflater.finished?
  ensure
    inflater&.close
  end

  private

  def inflate(data)
    Zip::Inflater.new(StringIO.new(data)).read
  end
end
