# Text Integrity behavior reference

The reference layer makes selected text measurements reproducible and
comparable without turning a generated record into an authority. It packages
canonical requests, strict versioned envelopes, semantic/environment
projections, manifests, replay utilities, and the independent WASM carrier.

Exact current schema identifiers are exported by
`src/reference/versions.js`. Exact corpus contents, operation scopes, digests,
and runtime identities are owned by the JSON artifacts in this directory and
by `wasm/MANIFEST.json`, not duplicated in this document.

## Packaged artifacts

- `behavior-corpus.json` contains canonical tagged requests. Tagged text
  distinguishes a Unicode scalar string from raw UTF-16 code units so another
  runtime cannot silently repair an isolated surrogate.
- `behavior-manifest.json` records the materialized requests, result
  projections, identities, and case-specific reproducibility targets produced
  by one named runtime and data set.
- `replay-receipt.json` binds the package/reference inputs needed to regenerate
  the current derived reference state. It is checked for freshness by the
  source and installed-package paths.

These files are comparison inputs. They do not certify that an implementation,
manifest, package, or result is correct.

## Behavior manifests

`generateBehaviorManifest` materializes each tagged request, executes the
shared core, validates the complete public result, splits semantic facts from
environment metadata, and computes canonical identities. The split uses the
same implementation as result-budget accounting and does not mutate the
complete result.

`compareBehaviorManifests` reports changes in product/data identity, case
inventory, requests, semantic results, environment metadata, and complete
results. Locale-collation calibration is reported separately so environment
drift remains visible without being forced into a fixed-data equality claim.

Use the current artifacts and commands rather than a prose count:

```sh
npm run behavior:check
npm run behavior:compare -- before.json after.json
```

Regeneration is explicit:

```sh
npm run behavior:write
```

## Measurement records

`text-integrity.measurement-record/2` is the bounded direct-consumer route for
one explicit tagged request. It contains:

- the exact tagged request and complete public success or deterministic core
  error result;
- product, data, operation-profile, and reproducibility identities;
- request, semantic, environment, and complete-result digests;
- fixed non-claims and the nested public-result contract identity.

`validateMeasurementRecord` accepts only a bounded plain JSON graph with a
closed current shape, valid public result, unchanged non-claims, consistent
projections, and recomputed digests. It rejects cycles, accessors, custom
prototypes, oversized/deep/wide trees, unknown fields, and unsupported schema
versions.

Serialized callers must enter through `parseMeasurementRecord`. It applies the
wire-size limit before fatal UTF-8 decoding or JSON parsing, rejects duplicate
keys before host-parser collapse, then runs the same structural validator and
the smaller materialized-record limit.

`replayMeasurementRecord` reruns the retained request against the current
runtime and returns a bounded digest-only drift observation. It does not copy
request/result text or diagnose a cause.

`compareMeasurementRecords` validates both records, omits their text, and
reports every changed identity category. Semantic comparison is applicable
only to the same validated request. A cross-runtime-exact target requires data
and semantic identity; environment or complete-result identity is not runtime
equivalence.

```js
import {
  compareMeasurementRecords,
  createMeasurementRecord,
  parseMeasurementRecord,
  replayMeasurementRecord,
  validateMeasurementRecord
} from "text-integrity/reference";
```

Digests are identities, not anonymization. Low-entropy request and result text
can be enumerated offline.

## Property observation

The fixed-seed property verifier regenerates a bounded corpus and returns one
closed property-verification observation with its seed, generator version,
corpus identity, named property records, complete assertion counts, runtime
identity, and result ceiling.

```sh
npm run property:check
```

It is a deterministic mutation/property check of the named cases. It does not
replace official conformance corpora or independent implementation comparison.

## Replay receipt and package sidecars

The replay receipt binds the package manifest, behavior inputs, compact Unicode
data, vendored bidi runtime, reference sources, WASM manifest/module, and fixed
protocol runtime files. It can be checked or regenerated atomically:

```sh
npm run replay:check
npm run replay:write
```

`replay:write` validates the complete candidate before replacing the committed
receipt and recovers a missing or corrupt copy without publishing a package.

`npm run replay:package` packs and installs the current package in a temporary
consumer, regenerates the receipt from installed bytes, and emits an external
package sidecar. A sidecar binds one exact tarball by filename, byte count,
SHA-1, SHA-256, and npm SHA-512 integrity. Sidecars are not committed as
current repository state and must remain paired with their original tarball.

The byte verifier recomputes those identities from explicit caller-supplied
bytes. Receipt and sidecar comparison return bounded digest/type changes rather
than raw changed values. Unknown schemas fail closed; migration and rollback
selection remain external decisions.

## Independent native and WASM comparison

The Rust implementation consumes the same tagged request model and pinned data
through a native runner and an import-free raw WASM module. The verifier compares
Node, native, raw WASM, and the packaged bounded loader only for the scopes
declared by the current behavior/reference metadata.

Some operations are complete cross-runtime targets; some composed operations
have a deterministic scoped projection; ICU collation remains environment-
bound. Inspect `behavior-manifest.json`, `src/reference/wasm.js`, and the
verifier output for the current classification. Do not infer promotion from an
old count or from the presence of Rust code.

```sh
npm run check:independent
npm run wasm:check
```

The raw ABI, statuses, batch/work ceilings, supported public loader operations,
source/lock identity, and module imports/exports are executable values in
`src/reference/wasm.js` and `wasm/MANIFEST.json`. The loader validates those
values before accepting work, validates duplicate-key-free bounded JSON, and
validates the semantic result against the requested operation's complete
schema. Carrier failures publish no partial or stale result and must recover on
the next valid request.

See [`../native/README.md`](../native/README.md) for the independent source
boundary.

## Claims and lifecycle

- A manifest or digest match is an identity observation, not correctness.
- A property or parity run covers only its named corpus, operations, projections,
  and current artifacts.
- A replay receipt or sidecar does not authorize release, publication,
  rollback, installation, or business acceptance.
- Historical sidecars stay with historical tarballs; they are not rewritten to
  a new schema and do not become current repository state.
- Any schema transition requires an explicit version and version-aware adapter.
- Current readiness is determined by rerunning the applicable source, runtime,
  performance, package, and installed-Host lanes—not by this README.
