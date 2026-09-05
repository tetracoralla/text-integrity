# Text Integrity

Text Integrity is a local deterministic provider for explicit Unicode strings
and byte arrays. One shared core powers a library, JSON CLI, eight read-only MCP
tools, and a minimal local web interface. It never reads a caller-supplied file,
URL, clipboard, or workspace, and it never uses a model to infer text intent.

## Operations

1. `inspect` — code points, extended grapheme clusters, encoded sizes,
   malformed-surrogate observations, and bounded detail.
2. `normalize` — NFC, NFD, NFKC, or NFKD without mutating the input, with
   canonical/compatibility facts and optional bounded witnesses.
3. `compare` — locale collation with every option explicit; requested and
   runtime-resolved behavior are both returned.
4. `transcode` — strict or explicitly lossy UTF-8/UTF-16LE processing with BOM,
   invalid-offset, round-trip, one selected byte representation, and witness
   facts.
5. `security` — descriptive free-text observations, one named identifier
   profile, or diagnostics over explicit source and caller-supplied spans.
6. `explain_difference` — exact, normalization, NFKC_Casefold, coordinate,
   alignment, invisible/newline, collation, and confusable facts in one result.
7. `index` — UTF-8 byte, UTF-16 code-unit, code-point, grapheme, and line/column
   coordinates, with grapheme-safe optional chunking.
8. `protocol_profile` — UTS #46 domain processing or a named RFC 8265 PRECIS
   profile.

Witness modes are `none`, `summary`, and `full_required`. A complete witness
returns every declared stage or segment or fails; it is never silently
truncated.

## Determinism and scope

Normative Unicode behavior is pinned to Unicode 17.0.0 and UTS #39 revision 32.
The compact runtime image is generated from digest-pinned sources and verified
on load. Project-owned normalization, grapheme segmentation, default lowercase,
closed decoding, and security primitives do not depend on mutable host string
behavior. Locale collation remains explicitly tied to the returned Node, ICU,
Unicode, and CLDR versions.

The reproducible unit is the operation, explicit arguments, package version,
data identity, and relevant runtime identity. Results contain no sampling,
probability, hidden ambient input, universal security verdict, or inferred
author intent.

Supported Node release lines are:

```text
>=22.22.1 <23 || >=24.20.0 <25 || >=26.8.1 <27
```

A runtime that does not report Unicode 17.0 fails closed.

## Install and verify

```sh
npm ci
npm run check
```

`npm run check` validates source, schemas, generated data, official pinned
Unicode/IDNA/bidi corpora, carriers, package inventory, and an isolated
installed-package smoke. The independent implementation is checked separately:

```sh
npm run check:independent
```

Tag preparation uses the stricter boundary:

```sh
npm run release:check
```

It combines the ordinary and independent checks, the unchanged performance
fences, and separate npm and Cargo/WASM dependency inventories. These commands
do not publish.

## Library

```js
import {
  executeOperation,
  OUTPUT_SCHEMAS,
  TOOL_DEFINITIONS
} from "text-integrity";

const result = executeOperation("normalize", {
  text: "e\u0301",
  form: "NFC",
  witnessMode: "summary"
});
```

The library also exports the supported-operation list, shared limits, stable
error helpers, runtime/data identity, compact MCP schemas, and the complete
leaf-closed `text-integrity.public-result-contract/2` schemas. Exported contract
graphs are deeply immutable; clone them before consumer-local presentation
changes.

The same complete per-operation schemas are available through:

```sh
node bin/text-integrity.js --schema-full normalize
```

and the MCP resources rooted at:

```text
text-integrity://schemas/public-result-contract/2/
```

### Namespace integrity

`analyzeNamespaceIntegrity` is a bounded library-first collection operation;
it is not a ninth MCP tool.

```js
import { analyzeNamespaceIntegrity } from "text-integrity";

const result = analyzeNamespaceIntegrity({
  items: [
    { id: "a", text: "paypal", scope: "tenant" },
    { id: "b", text: "pаypal", scope: "tenant" }
  ],
  relations: ["uts39_confusable"],
  confusableDirection: "LTR"
});
```

It returns bounded groups and member IDs rather than every pair. Internal
normalization, protocol, and skeleton keys are not returned. Their SHA-256
identities are not anonymization: low-entropy values can be enumerated offline.
Declared ICU collation relations remain environment-bound and do not fabricate
a stable sort key.

### Reference and replay

The `text-integrity/reference` entrypoint provides canonical tagged requests,
behavior manifests, `text-integrity.measurement-record/2`, bounded validation
and parsing, digest-only replay, offline comparison, property observations,
replay receipts, and package-sidecar verification.

```js
import {
  createMeasurementRecord,
  parseMeasurementRecord,
  replayMeasurementRecord
} from "text-integrity/reference";

const record = createMeasurementRecord({
  operation: "normalize",
  arguments: {
    text: { $text: { kind: "unicode_scalar_string", value: "e\u0301" } },
    form: "NFC"
  }
});

const received = parseMeasurementRecord(JSON.stringify(record));
const replay = replayMeasurementRecord(received);
```

Records, manifests, receipts, and digest matches are comparison material—not
correctness, conformance, privacy, release, rollback, or business-acceptance
certificates. See [`reference/README.md`](reference/README.md) for the complete
reference contract.

The package also exports a bounded import-free WASM comparison carrier at
`text-integrity/reference/wasm` and the raw module at
`text-integrity/reference/wasm/module`. Its supported operations, raw ABI,
module identity, and limits are owned by [`native/README.md`](native/README.md),
[`src/reference/wasm.js`](src/reference/wasm.js), and
[`wasm/MANIFEST.json`](wasm/MANIFEST.json).

## CLI

The CLI writes one JSON result to stdout. Stable error envelopes are written to
stderr with exit status 2.

```sh
node bin/text-integrity.js --help
node bin/text-integrity.js --schema

node bin/text-integrity.js normalize \
  --text '①À̕' --form NFKC --witness-mode full_required

node bin/text-integrity.js transcode \
  --source-kind bytes --bytes '[72, 105]' --source-encoding utf-8 \
  --target-encoding utf-16le --allow-lossy false \
  --byte-representation hex --witness-mode full_required

printf '%s' '{"operation":"inspect","arguments":{"text":"\ud800"}}' \
  | node bin/text-integrity.js --json
```

Raw JSON stdin is the lossless route for escaped malformed UTF-16 and complex
tagged inputs.

## MCP

```sh
node bin/text-integrity-mcp.js
```

The server uses newline-delimited JSON-RPC on stdio and supports the modern
stateless protocol plus the declared legacy handshake revisions. Modern calls
return concise text and the complete structured result without duplicating the
JSON into the text. Both eras expose static per-operation result-schema
resources.

The eight tools are:

- `text_inspect`
- `text_normalize`
- `text_compare`
- `text_transcode`
- `text_security_observe`
- `text_explain_difference`
- `text_index_map`
- `text_protocol_profile`

Each tool has a closed tagged input, closed output envelope, and accurate
read-only/idempotent annotations. The server bounds complete discovery,
requests, IDs, queueing, deadlines, and responses; pauses input under output
backpressure; suppresses queued cancelled responses; and continues serving
after bounded failures.

A source checkout can be configured after `npm ci`:

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

The source-local Codex plugin descriptor is
[`.codex-plugin/plugin.json`](.codex-plugin/plugin.json), which routes through
[`.mcp.json`](.mcp.json). The repository does not modify user configuration,
install itself globally, or imply installed-Host availability.

### OpenAdam Agent Host component

[`agent-tool.json`](agent-tool.json) declares the same library, CLI, MCP,
plugin, thin product Skill, checks, legal material, and read-only admission
probes to the packaged OpenAdam Developer Kit. Its `check`, `pack`, `probe`,
and `measure` routes validate or build an isolated component; none installs,
activates, publishes, or changes an Agent application's current tool set.

## Local web surface

```sh
npm run ui
```

Open the loopback address printed by the server (normally
`http://127.0.0.1:4173`). The interface exposes the repeat-use tasks, preserves
text whitespace, keeps Transcode text/byte drafts separate, rejects invalid
byte entries, and invalidates stale in-flight results after semantic changes.
Inputs and results are not persisted.

## Bounds

Exact current values are exported as `LIMITS` and enforced by the schemas and
carriers. Principal limits include 4 KiB per text or byte input, bounded paired
and namespace text totals, 128 ordinary detail/span/chunk items, a 64 KiB core
result, a 128 KiB complete MCP result, a 24 KiB tool catalog, a 64-request MCP
queue, and a 30-second queued-request deadline. Reference records and raw WASM
frames have separate closed limits at their own entrypoints.

When a requested complete representation cannot fit, the operation returns a
stable error instead of dropping fields.

## Security and protocol non-claims

Security results are observations or named-profile conformance, never an
overall safe, malicious, spoofed, or risk-score label. Source diagnostics do
not parse, compile, render, authorize, or scan files and workspaces. Protocol
processing is not presented as generic normalization.

Translation, language detection, proofreading, transliteration, regex
execution, semantic similarity, rendering-specific visual judgment, arbitrary
resource access, and automatic security policy remain outside the product.

## Performance, data, and licensing

`scripts/bench.mjs` measures cold/warm latency, throughput, retained memory,
catalog/envelope size, slow-consumer behavior, and cancellation recovery.
`--slo` enforces the regression fences described in
[`docs/PERFORMANCE_CONTRACT.md`](docs/PERFORMANCE_CONTRACT.md). A passing or
failing run is a current machine observation, not a timeless README claim.

The project is Apache-2.0 licensed. Unicode source and compact-data identities
are listed in [`vendor/unicode/17.0.0/MANIFEST.json`](vendor/unicode/17.0.0/MANIFEST.json)
and [`vendor/unicode/17.0.0/compact/MANIFEST.json`](vendor/unicode/17.0.0/compact/MANIFEST.json).
Third-party terms are recorded in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

See [`SECURITY.md`](SECURITY.md) for vulnerability reporting,
[`CONTRIBUTING.md`](CONTRIBUTING.md) for contributions, and
[`CHANGELOG.md`](CHANGELOG.md) for version history.
