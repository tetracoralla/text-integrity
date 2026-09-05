# Text Integrity repository contract

This repository owns one deterministic Unicode and text-integrity provider.
Current source, executable schemas, generated identities, tests, and rerun
runtime behavior control claims about what works. Documentation owns intended
boundaries and usage; it does not certify its own freshness or completion.

Read `docs/PRODUCT_MODEL.md` before changing product meaning and
`docs/REVIEW_CONTRACT.md` when reviewing or handing off behavior. They are
short entrypoints, not substitutes for inspecting current source.

## Product boundaries

- `src/core/` is the only implementation of text semantics. Library, CLI, MCP,
  HTTP/UI, native, and WASM surfaces are adapters or independent verifiers.
- Inputs are explicit strings, byte arrays, options, or caller-provided spans
  over explicit source. Do not add file, URL, clipboard, workspace, parser,
  compiler, font, model, or network authority.
- Keep normalization non-mutating; keep canonical and compatibility
  equivalence separate. Never hide replacement, truncation, or other loss.
- Locale comparison requires explicit caller options and returns requested,
  resolved, and runtime-version facts. Do not invent a stable ICU sort key or
  cross-environment equality claim.
- Security output is descriptive or named-profile conformance only. Keep free
  text, identifiers, explicit source spans, and confusable comparison distinct;
  never emit an overall safe, malicious, spoofed, or risk-score verdict, and
  never expose an internal skeleton as normalization.
- UTS #46 domain processing and each RFC 8265 PRECIS profile remain separately
  named protocol-string operations.
- Do not add translation, language detection, proofreading, transliteration,
  regex execution, semantic similarity, rendering-specific visual judgment,
  or new Unicode-security claims without authoritative data and a reviewed
  product need.

## Contract and delivery boundaries

- Preserve closed, deeply immutable public schema/catalog objects, stable error
  codes, and caller-isolated result collections.
- Enforce cumulative request/work limits and complete serialized-result budgets
  in shared code. A compact carrier representation must not weaken semantics or
  silently omit required output.
- Keep semantic facts separate from truthful environment metadata without
  mutating the complete result.
- MCP exposes exactly the eight direct read-only/idempotent operations. The
  library-first namespace operation does not become another tool without a
  measured routing need.
- `text-integrity.measurement-record/2` is a bounded reference route for one
  explicit tagged request. Validation, replay, and comparison accept untrusted
  JSON only through their closed size/shape/digest contracts. Digests are
  identities, not anonymization; records and receipts are not self-certifying.
- Reference manifests, replay receipts, package sidecars, property observations,
  and independent Rust/WASM results establish only the named comparison when
  regenerated. They do not authorize release, rollback, or broader correctness.
- Package sidecars remain external and paired with their original tarball
  bytes. Unknown artifact schema versions fail closed.
- This is a concrete provider, not a provider-neutral Capability Profile or
  Procedure. Do not add one without a second real provider and a separate
  standardization decision.

## Working and handoff

- Preserve unrelated dirty work. Do not modify sibling repositories.
- Do not commit, push, publish, install globally, or change user/host state
  unless the owner explicitly authorizes that action.
- Do not write milestone logs, acceptance packets, current PASS/FAIL snapshots,
  host state, test counts, or package measurements into the product contract.
  Keep transient recovery and review records in the task or CI system.
- Run `npm run check` before handoff. Run the independent and release-specific
  commands named in `docs/REVIEW_CONTRACT.md` when those lanes are in scope.
- Report development regression, runtime Agent flow, runtime human flow,
  performance/release state, and owner business/experience acceptance
  separately.
