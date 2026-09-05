# Third-party notices

This product (Text Integrity) is licensed under the Apache License 2.0; see
[`LICENSE`](LICENSE). This file carries the attribution notices for the
third-party data and code distributed with it.

## Unicode 17.0.0 data

Text Integrity includes unmodified data files from Unicode 17.0.0 and UTS #39
revision 32, and a deterministic compact image generated from exactly those
files. The source files, exact source URLs, byte lengths, and SHA-256 digests
are listed in
[`vendor/unicode/17.0.0/MANIFEST.json`](vendor/unicode/17.0.0/MANIFEST.json);
the generated runtime image and its digest chain are described in
[`vendor/unicode/17.0.0/compact/MANIFEST.json`](vendor/unicode/17.0.0/compact/MANIFEST.json).

Copyright © 1991-2026 Unicode, Inc. Unicode and the Unicode Logo are registered
trademarks of Unicode, Inc. in the United States and other countries.

The data is provided under the Unicode License V3. The complete copyright and
permission notice is included without modification at
[`vendor/unicode/17.0.0/license/LICENSE.txt`](vendor/unicode/17.0.0/license/LICENSE.txt).

The repository also includes unmodified, gzip-compressed Unicode 17.0.0
conformance corpora for CI. Their exact source URLs, compressed/uncompressed
sizes, and SHA-256 digests are listed in
[`vendor/unicode/17.0.0/CONFORMANCE_MANIFEST.json`](vendor/unicode/17.0.0/CONFORMANCE_MANIFEST.json)
and are covered by the same Unicode License V3.

## bidi-js 1.0.3 Unicode 17 adapter

The vendored UBA module is generated from `bidi-js` 1.0.3 at upstream commit
`8ab3197c9b0b6562b669aafedadb1a2581b4e8fc`, with its data regenerated from the
bundled Unicode 17.0.0 files. Upstream source:
<https://github.com/lojjic/bidi-js>.

`bidi-js` is Copyright © 2018 Jason Johnston and is licensed under the MIT
License. The complete notice is retained at
[`vendor/bidi-js-unicode17/LICENSE.txt`](vendor/bidi-js-unicode17/LICENSE.txt),
and generation/conformance provenance at
[`vendor/bidi-js-unicode17/PROVENANCE.md`](vendor/bidi-js-unicode17/PROVENANCE.md).

## tr46 6.0.0 and punycode 2.3.1

The runtime dependency `tr46@6.0.0` implements UTS #46 using Unicode 17 data
and depends on `punycode@2.3.1`. Both packages are distributed under the MIT
License and retain their package license files when installed by npm.

- tr46: <https://github.com/jsdom/tr46>
- punycode.js: <https://github.com/mathiasbynens/punycode.js>

Both are exact direct runtime dependencies in `package.json`; their package
integrity digests are pinned in [`package-lock.json`](package-lock.json), and
the reference behavior manifest binds the installed runtime-file-tree digest.

## Independent Rust verifier dependencies

The source-only native/WASM parity verifier under `native/` depends on
`serde` 1.0.229, `serde_json` 1.0.151, `unicode-segmentation` 1.13.3,
`unicode-normalization` 0.1.25, `unicode-bidi` 0.3.18, `idna` 1.1.0, and
`idna_adapter` 1.2.1. The verifier also uses `sha2` 0.11.0 to reproduce the
Node core's non-disclosing SHA-256 skeleton digests. The
IDNA adapter uses the pinned ICU4X 2.1 runtime/data packages in
`native/Cargo.lock`. Their exact transitive dependency versions and crates.io
checksums are pinned there. The Unicode and IDNA crates are available under
MIT or Apache-2.0 terms.

The verifier disables `unicode-bidi`'s `hardcoded-data` feature, overrides its
paired-bracket lookup, and supplies generated Unicode 17 `Bidi_Class` and
`Bidi_Paired_Bracket` data. The same generated verifier module carries the
project-owned combining-class and mirroring tables used for UAX #9 L3/L4.
`flate2` 1.1.10 and its pinned transitive crates are test-only dependencies
used to rerun the repository's compressed official Bidi corpora.

`serde`, `serde_json`, `itoa`, `proc-macro2`, `quote`, `syn`, `displaydoc`,
`litemap`, `potential_utf`, `stable_deref_trait`, `tinystr`, `utf8_iter`,
`writeable`, `yoke`, `zerofrom`, `zerotrie`, `zerovec`, and `synstructure` are
available under MIT or Apache-2.0 terms; `sha2`, `digest`, `block-buffer`,
`crypto-common`, `generic-array`, `typenum`, and `cpufeatures` under MIT or
Apache-2.0; `smallvec` under MIT or Apache-2.0;
`tinyvec` and `tinyvec_macros` under Zlib, MIT, or Apache-2.0; `memchr` under
Unlicense or MIT; `zmij` under MIT; and `unicode-ident` under MIT or
Apache-2.0 together with the Unicode 3.0 license.
These crates are fetched for the independent build and are not vendored into
the npm runtime package.
