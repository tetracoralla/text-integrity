# Text Integrity repository contract

This repository owns one provider product for deterministic Unicode and text
integrity work. Read `docs/PRODUCT_MODEL.md` and `docs/REVIEW_CONTRACT.md`
before changing behavior.

## Product boundaries

- `src/core/` is the only implementation of inspection, normalization,
  comparison, and transcoding semantics.
- CLI, MCP, and the local web surface are adapters around that core.
- Inputs are explicit strings or byte arrays. Do not add file paths, URLs,
  ambient clipboard access, or workspace traversal.
- Keep normalization non-mutating and report whether text changed and whether
  it remains canonically or compatibility equivalent.
- Keep locale comparison explicit: callers supply locale and every comparison
  option. Return the runtime-resolved options and runtime data versions.
- Transcoding supports only the closed encoding set implemented by the current
  mature runtime adapter. Never hide replacement or other lossy behavior.
- Security observation uses only the bundled Unicode 17.0.0 / UTS #39 revision
  32 data. Keep free-text signals separate from identifier-only properties and
  confusable comparison. Never add an overall security verdict or risk score or
  expose a skeleton as normalization. Confusable comparison supports only the
  explicit LTR, RTL, and first-strong directions implemented by the vendored
  Unicode-17 UBA adapter and rerun against the official BidiTest corpora.
- Source diagnostics accept only explicit source plus host-provided token and
  identifier spans. They do not own parsing, compilation, file access, scope
  discovery, or a maliciousness verdict.
- UTS #46 domain processing and RFC 8265 PRECIS profiles remain separately
  named protocol-string operations; do not merge them into normalization.
- Do not add translation, language detection, proofreading, transliteration,
  regex execution, semantic similarity, rendering-specific visual judgment, or
  further Unicode security claims without an authoritative dataset and a
  separately reviewed product need.

## Architecture and delivery

- Preserve strict, closed schemas and stable error codes.
- Enforce cumulative request and complete serialized result budgets in the
  shared core. Carrier-specific framing must not weaken them.
- MCP tools are read-only and idempotent.
- This is a concrete provider, not a provider-neutral Capability Profile or
  Procedure. Do not add `capabilities/provider.json` without a second real
  provider and a separate standardization decision.
- Do not commit, push, publish, install globally, or modify sibling repositories
  unless the owner explicitly authorizes that action.

Run `npm run check` before handoff. Report development regression, runtime
Agent flow, runtime human flow, and owner business/experience acceptance as
separate lanes.
