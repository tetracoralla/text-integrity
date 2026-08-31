# Text Integrity product model

## Product and tasks

Text Integrity is one concrete provider product for software makers, support
operators, localization work, and Agents that need deterministic facts about
explicit text. It replaces repeated ad-hoc string reasoning with one bounded
operation whose inputs, data versions, transformations, and limitations are
visible.

The human task is to paste text or bytes, select one of eight repeat-use tasks,
and inspect the result. The Agent task is to invoke one direct typed tool for
inspection, normalization, collation, transcoding, difference explanation,
coordinate/chunk mapping, Unicode security/source diagnostics, or a named
protocol-string profile.

## Shared semantics

All behavior lives in `src/core/`. CLI, MCP, and HTTP/UI are adapters and do not
reimplement Unicode algorithms. Every input is an inline string, byte array, or
host-supplied span over an inline string. There is no path, URL, clipboard,
workspace, parser, compiler, font, or network authority.

The core combines:

- a build-time compact interval-table image generated deterministically from
  the pinned Unicode 17.0.0 UCD and UTS #39 revision 32 sources, SHA-256
  verified on load and byte-reproducible from those sources;
- Node's Unicode-17 normalization, grapheme, decoder, and locale runtime;
- a vendored Unicode-17 build of `bidi-js` for UBA L2 plus explicit L3/L4;
- pinned `tr46@6.0.0` data and algorithms for UTS #46 revision 35;
- direct RFC 8264 derived-property and RFC 8265 profile evaluation.

The package requires Node
`>=22.22.1 <23 || >=24.20.0 <25 || >=26.8.1 <27` and checks
`process.versions.unicode === "17.0"` before every operation; the full
conformance suite has been run and passed on Node 22, 24, and 26. Runtime
versions remain part of every result because ICU collation is versioned data
rather than an eternal platform fact.

## Operations and effects

All eight operations are read-only and idempotent.

1. `inspect` accepts even malformed JavaScript UTF-16 so an isolated surrogate
   can be observed without fabricating UTF-8 bytes.
2. `normalize` rejects malformed UTF-16, preserves the original, and keeps
   canonical and compatibility equivalence separate.
3. `compare` requires every supported collation option, including locale
   matcher and collation type, and returns requested and resolved options.
4. `transcode` accepts explicit text or bytes in the closed UTF-8/UTF-16LE set.
   Strict processing is default; replacement is opt-in and always reports loss.
   BOM, first invalid byte, and source re-encode equality make byte effects
   inspectable. The caller selects exactly one byte representation
   (`bytes`, `hex`, or `base64`); equivalent payload copies are not multiplied.
5. `security` is a tagged family:
   - `free_text` is descriptive only;
   - `identifier` requires one named UAX #31/UTS #39 profile and optionally one
     explicit comparison direction;
   - `source` requires explicit source plus host-provided token/identifier spans
     and scope labels.
6. `explain_difference` composes exact, normalization, NFKC_Casefold,
   coordinate, invisible/newline, collation, and identifier-confusable facts
   into one deterministic task result. It does not infer why a human authored
   the difference.
7. `index` maps five coordinate systems and optionally chunks only at extended
   grapheme boundaries.
8. `protocol_profile` keeps UTS #46 and each PRECIS profile separately named.
   Protocol processing is not presented as ordinary normalization.

## Identifier and source boundaries

The identifier profiles are:

- `uax31_xid`: XID_Start followed by XID_Continue;
- `uax31_nfkc_casefold`: NFKC_Casefold followed by XID syntax;
- `uts39_general_security`: XID syntax plus UTS #39 allowed repertoire,
  restriction-level, and mixed-number observations.

Confusable comparison implements Unicode 17 `bidiSkeleton` for explicit LTR,
RTL, or first-strong direction using full UBA reordering, L3 combining-mark
reversal, and L4 mirroring. Default_Ignorable code points are removed at the
normative internal-skeleton step. Skeleton strings are never returned as a
normalization; relations, classes, resolved scripts, paragraph levels, and
digests are returned.

Source diagnostics are intentionally not a language parser. The caller owns
span and scope correctness. The operation only maps those spans to current
Unicode facts: same-scope confusable identifiers, bidi/default-ignorable/format
characters, and abnormal line endings. It returns no maliciousness, code
correctness, or authorization decision.

## Protocol profiles

`uts46_domain` supports explicit `to_ascii` and `to_unicode` actions and every
available processing flag. `to_unicode` supplements `tr46@6.0.0` with the UTS
#46 revision-35 X4_2 interior/empty-label compatibility check; a final root dot
remains permitted.

PRECIS exposes case-mapped and case-preserved Username profiles and
the OpaqueString profile. Derived properties, context rules, width/additional
mapping, case mapping, NFC, directionality, and idempotence-checked enforcement are
evaluated from the pinned Unicode data. Comparison means equality only after
the same named profile is independently enforced on both explicit strings.

## Determinism and claim boundary

The deterministic unit is:

`operation + explicit arguments + package version + declared runtime/data versions`.

There is no model inference, randomness, network lookup, font-dependent visual
judgment, user-history input, or global security score. An identifier-profile
`conforms` value means only that named profile's deterministic predicates
passed; it is not an application authorization or benignness claim. A
`not_confusable` result is bounded to the named direction, Unicode data, and
algorithm, not every possible rendering.

## Agent route and cost

The public catalog is capped at eight direct tools. Each dominant task takes
one call and requires no list/describe preflight. `text_explain_difference`
exists specifically to avoid an Agent making several calls and synthesizing a
Unicode conclusion itself. `text_index_map` makes offsets and context-budget
chunks executable rather than conversational.

Hosts that already hold structured arguments import the library entry and
spend zero Agent turns; the CLI, MCP, and web carriers call the same core
functions. The MCP transport serves both protocol eras from one process: the
modern stateless `2026-07-28` revision (`server/discover`, per-request
`_meta` versioning, `ttlMs`/`cacheScope` list caching, `resultType`) and the
legacy `initialize` era. Modern tool results carry a concise deterministic
text summary plus the complete structured result; legacy revisions keep the
JSON-equivalent text behavior. `transcode` returns exactly one
caller-selected byte representation. The measured envelope and catalog costs
are recorded in `docs/PERFORMANCE_BASELINE.md`.

Limits apply to complete input and output envelopes. Detail is explicitly
bounded; aggregate counts remain complete. A representation that cannot fit is
rejected instead of partially serialized. No latency or token advantage is
claimed beyond the measured runtime facts recorded in the baseline.

## Layer classification

- Provider core: this repository.
- Tools: library entry, CLI, MCP, and local HTTP carriers.
- Transport: the MCP stdio server owns framing only — bounded queues,
  backpressure, deadlines, and cancellation — with no Unicode semantics.
- Plugin: validated product-local MCP manifest; source-local only and not
  installed or published by this repository.
- Human surface: minimal local web UI.
- Skill: absent; the direct catalog contains no unresolved routing method.
- Procedure: absent; the operations do not define one settled professional
  multi-stage workflow.
- Capability Profile: absent; no second real provider establishes substitution.

## Non-goals

Translation, language detection, proofreading, transliteration, regex
execution, semantic similarity, arbitrary file/workspace scanning, parsing,
compilation, rendering-specific visual judgment, and overall security
classification remain outside this product. A future encoding, language
profile, or security claim requires authoritative data, a current consumer,
closed semantics, and executable conformance before it enters the core.
