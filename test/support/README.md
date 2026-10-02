# Deflate64 test fixture generators

These scripts build the binary Deflate64 fixtures committed under
`test/data/`. They are Python 3 only (no third-party packages) and exist so
the fixtures can be regenerated and audited by hand.

* `make_deflate64_fixture.py` builds `zipWithDeflate64Compression.zip`, a
  multi-entry method-9 archive covering stored blocks, fixed and dynamic
  Huffman blocks, a 64 KiB window back-reference and the Deflate64-only
  length code 285 (16 extra bits).
* `make_deflate64_malformed.py` builds `deflate64_beyond64k.bin` and
  `deflate64_distance_too_far.bin`, raw streams whose back-references
  point beyond the bytes decoded so far. `gen_repeat16.rb` builds
  `deflate64_repeat16.bin`, a dynamic block that starts with an illegal
  code-length repeat.

Every well-formed entry was cross-checked against the independent
Info-ZIP UnZip 6.00 implementation (`unzip`) that ships with macOS, and
the Ruby test suite checks entry sizes and CRCs while streaming.
