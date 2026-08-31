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

Exact versions and integrity digests are pinned in
[`package-lock.json`](package-lock.json).
