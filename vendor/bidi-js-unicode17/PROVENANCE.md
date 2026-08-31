# bidi-js Unicode 17 adapter provenance

- Upstream: https://github.com/lojjic/bidi-js
- Upstream commit: `8ab3197c9b0b6562b669aafedadb1a2581b4e8fc`
- Upstream release: `1.0.3`
- License: MIT; see `LICENSE.txt`.
- Local data change: the upstream generator was run against Unicode 17.0.0
  `DerivedBidiClass.txt`, `BidiBrackets.txt`, `BidiMirroring.txt`, and
  `UnicodeData.txt`.
- Generated upstream content SHA-256 before repository newline normalization:
  `b2062539894f139b94d52d34daef0cd3d155813c9730f806c848993d05996d3b`.
- Packaged `bidi.mjs` SHA-256:
  `4d0e3c6460d08f053cf1c430cef67166f4f5322f1d0c1be455d97934061ff4c8`.
- Conformance: the generated source passed every Unicode 17.0.0
  `BidiTest.txt` case (770,241) and `BidiCharacterTest.txt` case (91,707).
  The repository reruns those pinned official corpora.
