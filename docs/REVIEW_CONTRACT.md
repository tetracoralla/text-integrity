# Text Integrity review contract

This is the repository-specific minimum for a current, defect-first review.
Current source, executable contracts, generated identities, and rerun runtime
behavior control implementation claims. This document and prior reports are
neither completion certificates nor ceilings on independent discovery.

## Authority map

- `src/core/` owns operation semantics, limits, validation, and stable errors.
- `src/contracts.js`, `src/output-schemas.js`, `src/result-contract.js`, and
  `src/mcp-output-schemas.js` own public input and result discovery.
- Library, CLI, MCP, HTTP, and browser modules own carrier framing and
  presentation, not alternate text semantics.
- `vendor/unicode/17.0.0/`, its generated compact image and manifests, and the
  vendored bidi runtime own the pinned Node data inputs.
- `src/reference/`, `reference/`, `native/`, and `wasm/MANIFEST.json` own the
  bounded comparison, replay, independent-runtime, and WASM routes.
- Tests, generation checks, CI, and package scripts own rerunnable checks and
  distribution reconstruction. Documentation owns intended scope and usage.

Text Integrity is one concrete provider; there is no provider-neutral
Capability or Procedure manifest in this repository.

## Stable seams to review

### Meaning and authority

- All production carriers route to the same core and accept only explicit
  strings, bytes, options, or caller-provided spans.
- Normalization is non-mutating; canonical and compatibility relations stay
  separate; transcoding and witnesses expose loss or fail closed.
- Locale collation preserves requested, resolved, and runtime facts and remains
  environment-bound.
- Free-text, identifier, source-span, and confusable observations remain
  distinct and never become a global safety, maliciousness, or intent verdict.
- UTS #46 and each PRECIS profile remain named protocol operations.

### Contracts, limits, and recovery

- Public contracts are closed and deeply immutable; returned collections do
  not share caller-visible mutable state.
- Cumulative request/work and complete serialized-result limits apply through
  every carrier. `full_required` never silently truncates.
- MCP schema-invalid arguments are protocol errors; schema-valid domain
  failures remain typed tool results. Message size, IDs, queues, backpressure,
  deadlines, and cancellation stay bounded and recoverable.
- Coordinate, grapheme, alignment, namespace, digest, and chunk ordering remain
  deterministic within their declared data/runtime scope.

### Reference and distribution truth

- Untrusted records enter through bounded JSON parsing and closed structural
  validation. Replay, receipts, sidecars, manifests, and digests establish only
  their named identity or comparison.
- Independent parity is limited to operations and projections actually rerun;
  ICU-dependent or incomplete consumers are not promoted by prose.
- A packaged install must reconstruct its schemas, data identities, reference
  WASM, legal inventory, and runtime behavior without importing the checkout.
- Installed Agent Host activation is a separate observation from a source-local
  plugin or MCP process and requires a fresh task after binding changes.

## Review method

Record the revision and dirty state without discarding existing work. Rebuild
the current operation set, schemas, limits, carrier paths, reachable UI states,
package contents, and reference surfaces from source before selecting tests.
Exercise at least one plausible omission, composition, interruption, or
authority mismatch that was not copied from existing test names or this file.
If the target changes during review, restart the affected observations.

For an ordinary source handoff:

```sh
npm run check
npm run check:independent
```

For release preparation, also run the unchanged release boundary:

```sh
npm run release:check
```

When a runtime lane is in scope, send current requests through the applicable
library, raw CLI, modern and legacy MCP, HTTP, and rendered browser paths. Test
hostile representation and encoding inputs, cross-operation compositions,
worst-case complete outputs, interrupted/blocked carriers, recovery, and final
visible state. Inspect the packed installation rather than inferring it from
source tests. Review the installed Host route in a fresh task when activated.

## Verdict lanes

- **Development regression:** source, schemas, generation, tests, conformance,
  bounds, and package checks — Agent/Controller `PASS`, `FAIL`, or `BLOCKED`.
- **Runtime Agent flow:** real carriers and the separately installed Host route
  — Agent/Controller `PASS`, `FAIL`, or `BLOCKED`.
- **Runtime human flow:** rendered pointer, keyboard, responsive, transition,
  error, and recovery behavior — Agent/Controller `PASS`, `FAIL`, or `BLOCKED`.
- **Performance and release:** current fence execution, independent rebuild,
  package reconstruction, inventory, and publication authorization — report
  separately from functional regression.
- **Business/experience acceptance:** task fit, value, and visual judgment —
  owner `OK`, `Not OK`, or `Pending`.

Report shared ABI drift, installed namespace conflicts, host contention, or
sibling dependencies as escalations. Do not repair another repository here.
