# frozen_string_literal: true

require_relative 'test_helper'
require_relative 'helpers/crc_tests'
require 'securerandom'

class ParallelDeflaterTest < Minitest::Test
  include CrcTests

  CHUNK_SIZE = 1024

  # A future that lets its executor decide when jobs actually run.
  class ExecutorFuture < ::Zip::ParallelDeflater::Future
    def initialize(executor, seq, job)
      super(job)
      @executor = executor
      @seq = seq
    end

    def value
      @executor.run_until_ready(self)
      super
    end

    def cancel
      @executor.record_cancelled(@seq) unless ready?
      super
    end
  end

  # An executor that completes jobs in the exact reverse of submission
  # order: jobs are queued and only run, most-recently-submitted first,
  # when a future's value is requested.
  class LifoExecutor
    def initialize(fail_on_seq: nil)
      @stack = []
      @submit_count = 0
      @fail_on_seq = fail_on_seq
      @completion_order = []
      @cancelled = []
    end

    attr_reader :completion_order, :cancelled

    def submit(job)
      seq = @submit_count
      @submit_count += 1
      wrapped = proc do
        raise %(chunk #{seq} failed) if seq == @fail_on_seq

        job.call
      end
      ExecutorFuture.new(self, seq, wrapped).tap { |future| @stack << future }
    end

    def run_until_ready(_future)
      until @stack.empty?
        future = @stack.pop
        future.execute
        @completion_order << future_seq(future)
      end
    end

    def record_cancelled(seq)
      @cancelled << seq
    end

    private

    def future_seq(future)
      future.instance_variable_get(:@seq)
    end
  end

  # An executor that runs each job only when that job's value is
  # requested, in whatever order the deflater asks for them.
  class StepExecutor
    def initialize(fail_on_seq: nil)
      @submit_count = 0
      @fail_on_seq = fail_on_seq
      @executed = []
      @cancelled = []
    end

    attr_reader :executed, :cancelled

    def submit(job)
      seq = @submit_count
      @submit_count += 1
      wrapped = proc do
        @executed << seq
        raise %(chunk #{seq} failed) if seq == @fail_on_seq

        job.call
      end
      ExecutorFuture.new(self, seq, wrapped)
    end

    def run_until_ready(future)
      future.execute unless future.ready?
    end

    def record_cancelled(seq)
      @cancelled << seq
    end
  end

  def teardown
    Zip.reset!
  end

  def test_crc
    run_crc_test(::Zip::ParallelDeflater)
  end

  def test_round_trip_with_reverse_completion_order
    data = test_data(CHUNK_SIZE * 10 + 123)
    executor = LifoExecutor.new
    compressed = deflate(data, executor: executor)

    # Ten full chunks plus the final terminator chunk, completed newest first.
    assert_equal((0..10).to_a.reverse, executor.completion_order)
    assert_equal(data, inflate(compressed))
  end

  def test_round_trip_with_default_serial_executor
    data = test_data(CHUNK_SIZE * 5 + 7)
    compressed = deflate(data)

    assert_equal(data, inflate(compressed))
  end

  def test_round_trip_with_thread_pool_executor
    data = test_data(CHUNK_SIZE * 20)
    executor = ::Zip::ParallelDeflater::ThreadPoolExecutor.new(4)
    compressed = deflate(data, executor: executor, max_pending: 4)
    executor.shutdown

    assert_equal(data, inflate(compressed))
  end

  def test_empty_entry
    assert_equal('', inflate(deflate('')))
  end

  def test_size_and_crc_cover_whole_entry
    data = test_data(CHUNK_SIZE * 3)
    out = StringIO.new(''.b)
    deflater = ::Zip::ParallelDeflater.new(out, ::Zip.default_compression,
                                           ::Zip::NullEncrypter.new, chunk_size: CHUNK_SIZE)
    deflater << data
    deflater.finish

    assert_equal(data.bytesize, deflater.size)
    assert_equal(::Zlib.crc32(data), deflater.crc)
  end

  def test_failure_cancels_remaining_work_and_writes_no_end_marker
    data = test_data(CHUNK_SIZE * 5)
    executor = StepExecutor.new(fail_on_seq: 2)
    out = StringIO.new(''.b)
    deflater = ::Zip::ParallelDeflater.new(out, ::Zip.default_compression,
                                           ::Zip::NullEncrypter.new,
                                           executor: executor, chunk_size: CHUNK_SIZE)
    deflater << data

    error = assert_raises(RuntimeError) { deflater.finish }
    assert_equal('chunk 2 failed', error.message)

    # Chunks 0 and 1 were written; chunk 2 failed; the rest never ran.
    assert_equal([0, 1, 2], executor.executed)
    assert_equal([3, 4, 5], executor.cancelled)

    # The partial output must not look like a complete deflate stream:
    # no normal end marker was written to mask the missing chunks.
    inflater = ::Zlib::Inflate.new(-::Zlib::MAX_WBITS)
    inflater.inflate(out.string)
    refute(inflater.finished?)

    # The failure is sticky: no terminator is written afterwards either.
    assert_raises(RuntimeError) { deflater.finish }
    assert_raises(RuntimeError) { deflater << 'more data' }
  end

  def test_output_stream_integration_with_reverse_completion_order
    data = test_data(CHUNK_SIZE * 8)
    executor = LifoExecutor.new

    buffer = ::Zip::OutputStream.write_buffer(
      ::StringIO.new(''.b),
      parallel_compression: { executor: executor, chunk_size: CHUNK_SIZE }
    ) do |zos|
      zos.put_next_entry('big_file.bin')
      zos << data
    end

    assert_equal((0..8).to_a.reverse, executor.completion_order)

    ::Zip::InputStream.open(::StringIO.new(buffer.string)) do |zis|
      entry = zis.get_next_entry
      assert_equal('big_file.bin', entry.name)
      assert_equal(data, zis.read)
    end
  end

  private

  def test_data(size)
    # Compressible, but not trivially so.
    (('The quick brown fox jumps over the lazy dog. ' * 64) + ::SecureRandom.bytes(512))
      .bytes.cycle.first(size).pack('C*')
  end

  def deflate(data, executor: nil, max_pending: 100)
    out = StringIO.new(''.b)
    options = { chunk_size: CHUNK_SIZE, max_pending: max_pending }
    options[:executor] = executor if executor
    deflater = ::Zip::ParallelDeflater.new(out, ::Zip.default_compression,
                                           ::Zip::NullEncrypter.new, **options)
    deflater << data
    deflater.finish
    out.string
  end

  def inflate(compressed)
    ::Zip::Inflater.new(::StringIO.new(compressed)).read
  end
end
