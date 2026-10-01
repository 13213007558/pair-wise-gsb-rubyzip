# frozen_string_literal: true

# Generates fixtures that mimic old systems (e.g. Windows zh-CN archivers):
# the main name/comment bytes use a local encoding (GBK), while the true
# Unicode value is carried by the Info-ZIP Unicode Path (0x7075) and
# Unicode Comment (0x6375) extra fields.
require 'zlib'

NAME = '中文文件名.txt'
GBK_NAME = NAME.encode('GBK')
COMMENT = '渠道升级'
GBK_COMMENT = COMMENT.encode('GBK')
CONTENT = 'hello 中文'.b

# Minimal stored (no compression) ZIP writer with full control over every
# byte, so we can set encodings, flags and extra fields exactly.
class RawZip
  attr_reader :buf

  def initialize
    @buf = +''.b
  end

  def u16(v); @buf << [v].pack('v'); end
  def u32(v); @buf << [v].pack('V'); end
  def bytes(s); @buf << s.b; end

  # local: {gp:, name:, comment_extra:, local_extra:, cdir_extra:}
  def add(name:, gp_flags:, local_extra:, cdir_extra:, comment_extra: nil,
          data: CONTENT)
    @entries ||= []
    crc = Zlib.crc32(data)
    offset = @buf.bytesize

    # Local file header.
    u32(0x04034b50)
    u16(20)          # version needed
    u16(gp_flags)
    u16(0)           # stored
    u16(0)           # dos time
    u16(0x21)        # dos date (1980-01-01)
    u32(crc)
    u32(data.bytesize)
    u32(data.bytesize)
    u16(name.bytesize)
    u16(local_extra.bytesize)
    bytes(name)
    bytes(local_extra)
    bytes(data)

    @entries << {
      name: name, gp: gp_flags, crc: crc, size: data.bytesize,
      offset: offset, cdir_extra: cdir_extra,
      comment_extra: comment_extra
    }
  end

  def finish
    cdir_start = @buf.bytesize
    @entries.each do |e|
      extra = e[:cdir_extra].to_s
      comment = e[:comment_extra] ? e[:comment_extra][:comment] : +''.b
      u32(0x02014b50)
      u16(20)          # version made by (0 = FAT host)
      u16(20)          # version needed
      u16(e[:gp])
      u16(0)           # stored
      u16(0)
      u16(0x21)
      u32(e[:crc])
      u32(e[:size])
      u32(e[:size])
      u16(e[:name].bytesize)
      u16(extra.bytesize)
      u16(comment.bytesize)
      u16(0)           # disk start
      u16(0)           # internal attrs
      u32(0)           # external attrs
      u32(e[:offset])
      bytes(e[:name])
      bytes(extra)
      bytes(comment)
    end
    cdir_size = @buf.bytesize - cdir_start

    u32(0x06054b50)
    u16(0)
    u16(0)
    u16(@entries.size)
    u16(@entries.size)
    u32(cdir_size)
    u32(cdir_start)
    u16(0)
    @buf
  end
end

def unicode_extra(id, unicode_name, primary, crc_override: nil)
  crc = crc_override || Zlib.crc32(primary.b)
  body = [1, crc].pack('CV') + unicode_name.encode('UTF-8').b + "\x00".b
  [id].pack('v') + [body.bytesize].pack('v') + body
end

DIR = __dir__

# 1) GBK main name + valid 0x7075 in both headers and valid 0x6375 comment.
z = RawZip.new
ux_path    = unicode_extra(0x7075, NAME, GBK_NAME)
ux_comment = unicode_extra(0x6375, COMMENT, GBK_COMMENT)
z.add(name: GBK_NAME, gp_flags: 0, local_extra: ux_path,
      cdir_extra: ux_path + ux_comment,
      comment_extra: { comment: GBK_COMMENT })
File.binwrite(File.join(DIR, 'gbk-with-unicode-extra.zip'), z.finish)

# 2) Same Chinese name, UTF-8 main bytes with the EFS bit set (no extra).
z = RawZip.new
z.add(name: NAME.b, gp_flags: 0x800, local_extra: +''.b,
      cdir_extra: +''.b)
File.binwrite(File.join(DIR, 'utf8-efs.zip'), z.finish)

# 3) GBK main name but the 0x7075 CRC is corrupted: must be ignored and the
# main field rules applied (raw GBK bytes, not the unicode value).
z = RawZip.new
bad = unicode_extra(0x7075, NAME, GBK_NAME, crc_override: 0xDEADBEEF)
z.add(name: GBK_NAME, gp_flags: 0, local_extra: bad, cdir_extra: bad)
File.binwrite(File.join(DIR, 'gbk-bad-crc.zip'), z.finish)

# 4) GBK main name with an unknown version (2) 0x7075: not trusted on read,
# but preserved byte-for-byte on a lossless rewrite.
body = [2, Zlib.crc32(GBK_NAME.b)].pack('CV') + NAME.b + "\x00".b
unknown = [0x7075].pack('v') + [body.bytesize].pack('v') + body
z = RawZip.new
z.add(name: GBK_NAME, gp_flags: 0, local_extra: unknown,
      cdir_extra: unknown)
File.binwrite(File.join(DIR, 'gbk-unknown-version.zip'), z.finish)

puts 'generated'
