# frozen_string_literal: true

require 'etc'

module Zip
  # A Compressor that compresses a single zip entry in independent chunks,
  # optionally in parallel, and stitches the compressed chunks into a single
  # raw deflate stream that any standard zip reader can inflate.
  #
  # Each chunk is deflated independently, with no shared dictionary between
  # chunks, so the compression ratio can be slightly lower than a single
  # streamed deflate of the same data. Non-final chunks are terminated with
  # Zlib::SYNC_FLUSH, which ends the current deflate block on a byte boundary
  # without setting the deflate final-block bit; only the last chunk is
  # terminated with Zlib::FINISH. Concatenating the chunk outputs in
  # submission order therefore yields one well-formed deflate stream, whereas
  # concatenating several independently finished streams would not.
  #
  # Chunk compression jobs are run by an injectable executor. The default
  # SerialExecutor runs jobs inline on the calling thread; the chunk assembly
  # logic (ordering, CRC, backpressure and error handling) is identical
  # either way. A ThreadPoolExecutor is provided for real parallelism, and
  # any object responding to submit(job) - returning a future that responds
  # to value, ready? and cancel - can be injected instead.
  #
  # At most max_pending compressed chunks are held in memory waiting to be
  # written out; once that limit is reached, submission blocks until the
  # oldest unwritten chunk is ready, so memory use stays bounded no matter
  # which order chunks complete in.
  #
  # If any chunk fails to compress, all remaining work is cancelled, the
  # error is re-raised, and no further output - in particular no normal
  # deflate end marker - is written, so a truncated entry cannot be mistaken
  # for a complete one.
  class ParallelDeflater < Compressor
    # Default size of the chunks the input is split into, in bytes.
    DEFAULT_CHUNK_SIZE = 1 << 20

    # Default limit on compressed chunks held in memory before writing.
    DEFAULT_MAX_PENDING = 8

    # Error raised when a chunk compression job is cancelled before it ran.
    class CancelledError < Zip::Error; end

    def initialize(output_stream, level = Zip.default_compression, encrypter = NullEncrypter.new,
                   executor: nil, chunk_size: DEFAULT_CHUNK_SIZE, max_pending: DEFAULT_MAX_PENDING)
      super()
      raise Error, 'chunk_size must be positive' unless chunk_size.positive?
      raise Error, 'max_pending must be positive' unless max_pending.positive?

      @output_stream = output_stream
      @level = level
      @encrypter = encrypter
      @executor = executor || SerialExecutor.new
      @chunk_size = chunk_size
      @max_pending = max_pending
      @buffer = +''.b
      @pending = []
      @size = 0
      @crc = ::Zlib.crc32
      @finished = false
      @error = nil
    end

    def <<(data)
      raise IOError, 'closed stream' if @finished
      raise @error if @error

      val = data.to_s
      @crc = ::Zlib.crc32(val, @crc)
      @size += val.bytesize
      @buffer << val
      submit_chunk(final: false) while @buffer.bytesize >= @chunk_size
      @output_stream
    end

    # Flushes any buffered input as the final chunk, waits for all
    # outstanding chunk jobs and writes their output in submission order.
    def finish
      return if @finished
      raise @error if @error

      submit_chunk(final: true)
      write_next until @pending.empty?
      @finished = true
    end

    attr_reader :size, :crc

    private

    def submit_chunk(final:)
      chunk = @buffer.slice!(0, @chunk_size)
      @pending << @executor.submit(proc { compress_chunk(chunk, final) })
      write_next while @pending.first&.ready?
      write_next while @pending.size > @max_pending
    end

    def write_next
      future = @pending.shift
      @output_stream << @encrypter.encrypt(future.value)
    rescue StandardError => e
      fail_with(e)
    end

    def fail_with(error)
      @error = error
      @pending.each(&:cancel)
      @pending.clear
      raise error
    end

    def compress_chunk(chunk, final)
      deflater = ::Zlib::Deflate.new(@level, -::Zlib::MAX_WBITS)
      return deflater.deflate(chunk, ::Zlib::SYNC_FLUSH) unless final

      begin
        deflater.deflate(chunk, ::Zlib::FINISH)
      ensure
        deflater.close
      end
    end

    # A future representing one chunk compression job. Executors must return
    # objects with this interface (value, ready? and cancel) from submit.
    class Future
      def initialize(job)
        @job = job
        @done = false
        @lock = Mutex.new
        @condition = ConditionVariable.new
      end

      # Runs the job unless it has been cancelled. Called by the executor.
      def execute
        return if @lock.synchronize { @done }

        begin
          result = @job.call
        rescue StandardError => e
          error = e
        end
        @lock.synchronize do
          unless @done
            @result = result
            @error = error
            @done = true
            @condition.broadcast
          end
        end
        nil
      end

      # Marks the job as cancelled. A cancelled job never runs; if it is
      # already running, its result is discarded.
      def cancel
        @lock.synchronize do
          unless @done
            @error = CancelledError.new('compression job was cancelled')
            @done = true
            @condition.broadcast
          end
        end
        nil
      end

      # Whether the job has completed, failed or been cancelled.
      def ready?
        @lock.synchronize { @done }
      end

      # Blocks until the job has completed and returns its result. Re-raises
      # any error the job raised, or CancelledError if it was cancelled.
      def value
        @lock.synchronize do
          @condition.wait(@lock) until @done
          raise @error if @error

          @result
        end
      end
    end

    # An executor that runs jobs immediately, inline, on the submitting
    # thread. This is the default; it uses no extra threads.
    class SerialExecutor
      def submit(job)
        Future.new(job).tap(&:execute)
      end

      def shutdown; end
    end

    # A simple fixed-size thread pool executor. Deflating releases the GVL,
    # so on CRuby this compresses chunks truly in parallel. The caller owns
    # the executor and should call shutdown when it is no longer needed.
    class ThreadPoolExecutor
      def initialize(size = Etc.nprocessors)
        @shutdown = false
        @queue = Queue.new
        @threads = Array.new(size) do
          Thread.new do
            while (future = @queue.pop)
              future.execute
            end
          end
        end
      end

      def submit(job)
        raise IOError, 'executor is shut down' if @shutdown

        Future.new(job).tap { |future| @queue << future }
      end

      def shutdown
        @shutdown = true
        @threads.size.times { @queue << nil }
        @threads.each(&:join)
      end
    end
  end
end
