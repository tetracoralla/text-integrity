# Text Integrity product model

## Product and task

Text Integrity is a deterministic fact provider for people and software that
need to inspect explicit text or bytes without asking a model to guess what the
author meant. A human can paste a value into the local interface; a host that
already has structured input can call the library, CLI, MCP server, or bounded
reference WASM carrier directly.

The product reports transformations, relations, coordinates, protocol results,
Unicode-security properties, data identity, runtime identity, and declared
limitations. Policy remains with the caller: Text Integrity does not decide
whether a name is acceptable, a source is malicious, or a difference is
intentional.

## Authority and shared semantics

All production semantics live in `src/core/`. Adapters own framing and
presentation only. The independent Rust implementation and import-free WASM
module are comparison implementations; they do not silently replace the core
or promote their own results into correctness claims.

Inputs contain only inline strings, byte arrays, explicit options, and optional
caller-provided spans over inline source. The product has no path, URL,
clipboard, workspace, parser, compiler, font, model, or network authority.

Normative Unicode behavior is fixed to the packaged Unicode 17.0.0 data and UTS
#39 revision 32 sources. The compact runtime image is deterministically
generated and digest-checked against those pinned inputs. Normalization,
extended grapheme segmentation, default lowercase for PRECIS, UTF-8/UTF-16LE
decoding, and the security primitives owned by the project do not delegate
their semantics to mutable host string helpers. Locale collation remains an
explicit Node/ICU environment measurement. UTS #46 uses the fixed `tr46` and
Punycode dependency boundary named by the package.

Executable schemas and version constants own exact current shapes. In
particular, the complete result ABI is
`text-integrity.public-result-contract/2`; the MCP catalog uses a compact
projection of the same result values so discovery remains bounded. Complete
per-operation JSON Schemas are available from the library, CLI, and MCP static
resources.

## Operations

The eight public operations are read-only and idempotent.

1. `inspect` observes code points, extended grapheme clusters, encoded sizes,
   malformed UTF-16, and bounded detail.
2. `normalize` applies NFC, NFD, NFKC, or NFKD without mutating the input. It
   keeps canonical and compatibility relations separate and can return no
   witness, a complete summary, or a fail-closed complete witness.
3. `compare` performs explicitly configured locale collation and returns both
   requested and runtime-resolved options and versions.
4. `transcode` decodes or encodes the closed UTF-8/UTF-16LE set. Strict mode is
   the default; replacement is opt-in and reported as loss. BOM presence, the
   first invalid byte, round-trip facts, one selected byte representation, and
   optional bounded witnesses remain visible.
5. `security` is a tagged family: descriptive free-text observations; one named
   identifier profile with optional confusable comparison; or diagnostics over
   explicit source and caller-provided token/identifier spans and scopes.
6. `explain_difference` composes exact representation, normalization,
   NFKC_Casefold, coordinates, deterministic code-point/grapheme alignment,
   invisible/newline facts, locale collation, and identifier-confusable facts.
   It explains observable differences, not author intent.
7. `index` maps UTF-8 byte, UTF-16 code-unit, code-point, extended-grapheme, and
   line/column coordinates. Optional chunks end only at grapheme boundaries.
8. `protocol_profile` keeps UTS #46 domain processing and the named RFC 8265
   PRECIS profiles separate from ordinary normalization. Witnesses report only
   stages the selected engine actually exposes.

A requested complete witness either returns every declared stage or segment or
fails; summary mode retains complete counts and identities without pretending
to be the expanded representation.

## Identifier, source, and namespace boundaries

Identifier profiles expose named UAX #31/UTS #39 predicates. Confusable
comparison supports explicit LTR, RTL, and first-strong directions through the
pinned Unicode-17 bidi/skeleton path. Internal skeleton strings are never
returned as normalized text.

Source diagnostics are not a language parser. The caller owns the correctness
of spans and scopes; Text Integrity maps those coordinates to Unicode facts and
does not discover files, symbols, scopes, or maliciousness.

`analyzeNamespaceIntegrity` is a bounded direct-library collection operation,
not a ninth MCP tool. It groups explicit IDs within explicit scopes under named
exact, normalization, NFKC_Casefold, confusable, protocol, or declared-
collation relations without returning an all-pairs matrix. It does not choose
an application uniqueness policy. Non-collation key digests are identities,
not anonymization; low-entropy values can be enumerated offline. Declared ICU
collation remains environment-bound and never fabricates a sort key.

## Reference and replay model

The `text-integrity/reference` entrypoint provides canonical JSON, tagged text
materialization, behavior manifests, result projections, measurement records,
replay, comparison, property observations, replay receipts, and package-sidecar
verification. These functions are reference infrastructure, not additional
text operations.

`text-integrity.measurement-record/2` retains one explicit tagged request, the
complete public success or deterministic error result, data and operation
identity, reproducibility target, four digests, and fixed non-claims under its
declared byte and graph limits. Serialized consumers enter through the bounded,
duplicate-key-rejecting parser before structural validation.

Replay reruns only the retained request against the current runtime and returns
a digest-only drift observation. Offline comparison accepts two validated
records and reports every changed identity category without copying request or
result text. Cross-runtime expectation applies only to the same request under a
cross-runtime-exact profile and depends on data plus semantic identity.
Environment or complete-result equality is not runtime equivalence.

The committed behavior manifest and replay receipt are reproducible comparison
inputs. Package sidecars remain external records paired with exact tarball
bytes. Unknown schema versions reject until an explicit version-aware adapter
exists. None of these artifacts certifies correctness, conformance, release,
rollback, privacy, or business acceptance.

The independent Rust/native/WASM route consumes the same tagged request model
and pinned data. Each operation or sub-operation is described only at the
parity scope currently executed by `npm run check:independent`. ICU-dependent
collation and any unimplemented complete consumer remain explicitly outside a
cross-runtime-exact claim. Raw ABI versions, statuses, limits, module identity,
and supported WASM operations are owned by `src/reference/wasm.js`,
`wasm/MANIFEST.json`, and `native/README.md`, rather than duplicated here.

## Determinism and claim boundary

The reproducible unit is the operation, explicit arguments, package version,
declared data identity, and relevant runtime identity. There is no sampling,
model inference, probability, user history, ambient lookup, or hidden policy.

An identifier `conforms` result means only that the selected profile's
predicates passed. A `not_confusable` result is bounded to the selected data,
direction, and algorithm. A digest match is an identity observation. A passing
test or independent comparison is a check of its named corpus and projection;
none is a universal security, quality, or product-acceptance verdict.

## Agent and human delivery

Structured callers should use the library or direct host route without an
Agent turn. Natural-language callers should reach one of the eight MCP tools in
one selection and one call; the complete selected schema must be sufficient
without a preliminary discovery call. Stable errors and cumulative bounds make
invalid calls recoverable without speculative retries.

The local web surface is a minimal professional measurement interface. It
exposes the repeat-use human tasks while keeping protocol, Agent, engine, and
reference-system mechanics out of the primary UI. Inputs and results are not
persisted.

## Layer classification and non-goals

Text Integrity is one concrete provider. It does not claim a provider-neutral
Capability Profile or Procedure, and it does not need an Agent facade around
already structured work. A portable semantic standard requires a second real
provider and a separate interoperability decision.

Translation, language detection, proofreading, transliteration, regex
execution, semantic similarity, rendering-specific visual judgment, repository
scanning, application authorization, maliciousness classification, automatic
repair planning, and author-intent inference remain outside the product.
