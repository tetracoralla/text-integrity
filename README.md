# Text Integrity

Text Integrity is a local deterministic provider for explicit Unicode strings
and byte arrays. One shared core powers a JSON CLI, eight read-only MCP tools,
a stable library entry, and a minimal local web interface. It never accepts or
reads a caller-supplied file, URL, clipboard, or workspace and never uses a
model to infer text intent. Its only filesystem read is the packaged, digest-
verified Unicode runtime image described below.

## Operations

1. `inspect` — code points, extended grapheme clusters, UTF-8/UTF-16 sizes,
   malformed surrogate observations, and bounded detail.
2. `normalize` — NFC, NFD, NFKC, or NFKD without mutating the input, including
   canonical and compatibility-equivalence facts.
3. `compare` — locale collation with explicit locale, locale matcher,
   collation type, usage, sensitivity, punctuation, numeric, and case-first
   settings; requested and resolved behavior are both returned.
4. `transcode` — strict UTF-8/UTF-16LE decode and encode, or explicit lossy
   replacement. Results include BOM observation, first invalid byte,
   decode/re-encode equality, and exactly one caller-selected byte
   representation (`bytes`, `hex`, or `base64`).
5. `security` — one of three tagged forms:
   - descriptive `free_text` observations;
   - a named `identifier` profile with UAX #31 XID, NFKC_Casefold, UTS #39
     restriction level, mixed-number, and full `bidiSkeleton` comparison;
   - UTS #55-style diagnostics over explicit source text and caller-supplied
     identifier/token spans and scopes.
6. `explain_difference` — exact equality, all four normalization relations,
   NFKC_Casefold, first differing code point and grapheme, UTF-8/UTF-16/line
   coordinates, invisible characters, line endings, collation, and confusable
   relation in one call.
7. `index` — UTF-8 byte, UTF-16 code-unit, code-point, grapheme, and line/column
   coordinates, with optional byte-budget chunking that never cuts a grapheme.
8. `protocol_profile` — UTS #46 domain processing or one named RFC 8265 PRECIS
   profile: case-mapped username, case-preserved username, or opaque string.

## Determinism boundary

These are fixed programmatic transformations and predicates. Repeating a call
with the same explicit input, named profile/options, package version, and
supported runtime produces the same result. There is no sampling, model call,
probability, universal security score, or hidden ambient input.

Normative Unicode behavior is fixed to Unicode 17.0.0 and UTS #39 revision 32.
The runtime data is a build-time compact interval-table image generated from
the pinned UCD sources; it is SHA-256 verified on load and reproduces
byte-for-byte from those sources (`npm run build:unicode -- --check`). The
package requires a Node.js runtime that reports Unicode `17.0` and rejects any
other runtime. Every result records Node, ICU, Unicode, and CLDR versions.
Locale collation remains explicitly tied to those reported runtime data
versions.

## Supported runtimes

`engines` accepts only the verified release-line ranges:
`>=22.22.1 <23 || >=24.20.0 <25 || >=26.8.1 <27`. This excludes the untested
odd-numbered Node lines and earlier 24/26 builds. The full conformance suite
(all pinned Unicode corpora below) has actually been run and passed on Node
22.22.1, 24.20.0, and 26.8.1 (all report ICU Unicode 17.0). Any runtime
reporting a different Unicode version fails closed with
`UNICODE_VERSION_MISMATCH` rather than producing version-drifted results.

## Install and check

```sh
npm ci
npm run check
```

`npm run check` validates syntax, manifests and package inventory; reruns all
core, CLI, live MCP (both protocol eras), HTTP, and carrier-bound tests;
verifies the compact data image reproduces from the pinned sources; and reruns
all pinned official cases:

- NormalizationTest: 20,034 cases
- GraphemeBreakTest: 766 cases
- IdnaTestV2: 6,389 well-formed JavaScript-string cases
- BidiTest: 770,241 paragraph-mode cases
- BidiCharacterTest: 91,707 cases

## Library entry

Hosts that already hold structured arguments can call the core directly with
zero Agent turns; every carrier uses the same functions.

```js
import { executeOperation, TOOL_DEFINITIONS, LIBRARY_INFO } from "text-integrity";

const result = executeOperation("explain_difference", {
  left: "é",
  right: "e\u0301",
  locale: "en",
  options: {
    usage: "sort", sensitivity: "variant", ignorePunctuation: false, numeric: false,
    caseFirst: "false", localeMatcher: "best fit", collation: "default"
  },
  confusableDirection: "LTR"
});
```

The entry also exports `SUPPORTED_OPERATIONS`, `LIMITS`, `TextIntegrityError`,
`errorPayload`, `runtimeInfo`, and the pinned data-version constants.

## CLI

The CLI writes one JSON result to stdout. Errors use a stable JSON envelope on
stderr and exit with status 2.

```sh
node bin/text-integrity.js --help
node bin/text-integrity.js --schema

node bin/text-integrity.js explain_difference \
  --left 'é' --right 'é' --locale en \
  --usage sort --sensitivity variant \
  --ignore-punctuation false --numeric false --case-first false \
  --locale-matcher 'best fit' --collation default \
  --confusable-direction LTR

node bin/text-integrity.js transcode \
  --source-kind bytes --bytes '[72, 105]' --source-encoding utf-8 \
  --target-encoding utf-16le --allow-lossy false --byte-representation hex

printf '%s' '{"operation":"inspect","arguments":{"text":"\ud800"}}' \
  | node bin/text-integrity.js --json
```

Raw JSON stdin is the lossless route for escaped malformed UTF-16 and complex
tagged inputs. Both `--name value` and `--name=value` accept literal values that
begin with `--`.

## MCP

```sh
node bin/text-integrity-mcp.js
```

The server is dual-era over newline-delimited JSON-RPC on stdio:

- **Modern era (protocol `2026-07-28`)** — stateless. Every request carries
  `params._meta["io.modelcontextprotocol/protocolVersion"]`. `server/discover`
  advertises supported versions, capabilities, and identity; `tools/list`
  returns the eight tools in deterministic order with `ttlMs`/`cacheScope`;
  `tools/call` returns `resultType: "complete"` with a concise text summary
  plus the complete structured result (the result JSON is not duplicated into
  the text). Unknown versions receive error `-32022` listing supported ones.
- **Legacy era (`2025-11-25`, `2025-06-18`, `2025-03-26`, `2024-11-05`,
  `2024-10-07`)** — `initialize` handshake negotiation. From `2025-06-18` on,
  results include `structuredContent` with the full JSON also as text content;
  older revisions receive the JSON text alone.

The eight direct tools:

- `text_inspect`
- `text_normalize`
- `text_compare`
- `text_transcode`
- `text_security_observe`
- `text_explain_difference`
- `text_index_map`
- `text_protocol_profile`

Each tool has a closed tagged input schema, a closed typed output envelope, and
read-only/idempotent/closed-world annotations. Input lines, JSON-RPC IDs, core
results, and complete MCP envelopes are independently bounded. The complete
eight-tool discovery response is additionally capped at 24 KiB to keep host
context cost finite.

The transport owns backpressure: responses are written through a bounded
pipeline, the input is paused whenever the output blocks or the request queue
reaches its cap, and reading resumes when the consumer drains. A slow consumer
cannot force unbounded buffering. `notifications/cancelled` suppresses the
response of a request still waiting in the queue, and requests that sit past
the deadline return an error instead of executing, after which the connection
keeps serving.

A client can point directly at a source checkout after `npm ci`:

```json
{
  "mcpServers": {
    "text-integrity": {
      "command": "node",
      "args": ["./bin/text-integrity-mcp.js"],
      "cwd": "/absolute/path/to/text-integrity"
    }
  }
}
```

After the package is publicly available from npm, an installation-free client
route is:

```json
{
  "mcpServers": {
    "text-integrity": {
      "command": "npx",
      "args": ["-y", "-p", "text-integrity", "text-integrity-mcp"]
    }
  }
}
```

The repository does not change user configuration or install itself.
The validated product-local plugin entry is
[`/.codex-plugin/plugin.json`](.codex-plugin/plugin.json), which routes directly
to the same MCP server through [`/.mcp.json`](.mcp.json). Run `npm ci` in the
plugin source before using this source checkout; no marketplace or global
installation is performed by the repository.

## Local web surface

```sh
npm run ui
```

Open `http://127.0.0.1:4173`. The interface contains only the eight repeat-use
tasks. It preserves whitespace in text results, rejects empty byte-list items,
and cancels/invalidates an in-flight request when the semantic mode changes.
Source-span diagnostics remain Agent/API-only rather than becoming operator UI.
Input and results are not persisted.

## Limits

- Each text field: 4,096 UTF-8 bytes.
- General paired text: 8,192 UTF-8 bytes combined.
- Security comparison text: 4,096 UTF-8 bytes combined.
- Byte input and requested chunk size: 4,096 bytes.
- Detail items: 128; source spans: 128; chunks: 128.
- Locale: 128 characters; collation name: 32; source scope: 64.
- CLI, HTTP, and MCP serialized request: 131,072 bytes; JSON-RPC ID: 256
  serialized bytes. The carrier allowance covers JSON escaping of every valid
  core request and does not expand the smaller semantic text/byte budgets.
- Complete MCP tool catalog: 24,576 bytes.
- Complete core result and CLI error envelope: 65,536 bytes.
- Complete MCP response, including text plus structured content: 131,072 bytes.
- MCP request queue: 64 requests; request deadline: 30,000 ms.

When a requested detail or chunk representation cannot fit its declared
complete-result budget, the operation fails with a stable error instead of
silently dropping fields.

## Security and source-diagnostic scope

Security results are observations and named-profile conformance, never an
overall safe/malicious/spoofed label or risk score. Skeletons remain internal;
only relations and SHA-256 digests are returned. Full UBA display reordering,
combining-mark reversal, and mirroring are supported for LTR, RTL, and
first-strong directions and validated against Unicode 17 conformance corpora.

Source diagnostics accept only explicit source text and caller-provided spans.
They can identify raw-distinct confusable names in one supplied scope, including
canonically or compatibility-equivalent spellings, plus bidi/default-
ignorable/format characters, and abnormal line endings. They do not parse,
compile, render, authorize, or scan a file or workspace.

Translation, language detection, proofreading, transliteration, regex
execution, semantic similarity, rendering-specific visual judgment, arbitrary
file access, and universal security classification remain outside this core.

## Performance

[`scripts/bench.mjs`](scripts/bench.mjs) measures cold start, warm percentiles,
stdio burst throughput, slow-consumer memory bounds, cancellation recovery,
maximum-input envelope sizes, catalog cost, million-call steady state, and
memory growth. `node scripts/bench.mjs --slo` enforces the release fences
derived from the recorded baseline in
[`docs/PERFORMANCE_BASELINE.md`](docs/PERFORMANCE_BASELINE.md).

## Data and licensing

This project is licensed under the Apache License 2.0
([`LICENSE`](LICENSE)); contributions are accepted under the same terms.

Runtime data is the compact image generated from the Unicode 17.0.0 sources
listed in [`vendor/unicode/17.0.0/MANIFEST.json`](vendor/unicode/17.0.0/MANIFEST.json)
and verified on load against
[`vendor/unicode/17.0.0/compact/MANIFEST.json`](vendor/unicode/17.0.0/compact/MANIFEST.json).
The repository also keeps the full text corpora for CI and regeneration; the
published package ships only the compact image, licenses, and code. Each
source file is size- and SHA-256-checked before compaction. The bundled
Unicode files use the Unicode License V3. The vendored `bidi-js` adapter has
its own executable
[`MANIFEST.json`](vendor/bidi-js-unicode17/MANIFEST.json); `bidi-js`, `tr46`,
and `punycode` use MIT licenses, with details in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

## Support policy

- Supported after public release: the current major on the exact Node release
  ranges listed under [Supported runtimes](#supported-runtimes).
- Security fixes: supported lines receive security fixes; see
  [`SECURITY.md`](SECURITY.md) for reporting.
- Bugs and features: file an issue; pull requests follow
  [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Releases: versioned in [`CHANGELOG.md`](CHANGELOG.md); after trusted
  publishing is configured, npm publications carry provenance and workflow
  artifacts carry SBOMs, checksums, and build/SBOM attestations.
