# Dynamic block whose first alphabet symbol is code-length repeat 16 with
# no preceding value, which must be rejected.
class W
  def initialize
    @buf = +''.b
    @byte = 0
    @bits = 0
  end

  def w(v, n)
    n.times { |i| @byte |= ((v >> i) & 1) << @bits; tick }
  end

  def code(v, n)
    n.times { |i| @byte |= ((v >> (n - 1 - i)) & 1) << @bits; tick }
  end

  def finish
    @buf << @byte if @bits.positive?
    @buf
  end

  private

  def tick
    @bits += 1
    return unless @bits == 8

    @buf << @byte
    @byte = 0
    @bits = 0
  end
end

order = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]
# CL table: symbol 16 gets a 1-bit code; symbols 0 and 15 get 2-bit codes
# so the table is Kraft-complete (1/2 + 1/4 + 1/4 = 1).
cl = Array.new(19, 0)
cl[16] = 1
cl[0] = 2
cl[15] = 2

bw = W.new
bw.w(1, 1)   # BFINAL
bw.w(2, 2)   # BTYPE dynamic
bw.w(257 - 257, 5)  # HLIT = 0 (257 codes)
bw.w(1 - 1, 5)      # HDIST = 0 (1 code)
bw.w(19 - 4, 4)
19.times { |i| bw.w(cl[order[i]], 3) }
# First alphabet symbol: code for CL symbol 16 (canonical 0, one bit 0).
bw.code(0, 1)
print bw.finish.unpack1('H*')
