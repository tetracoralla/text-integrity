# Text Integrity review contract

This is the repository-specific minimum for an independent review. Current
source and rerun runtime output are authority; this document and prior reports
are not proof.

## Authority chain

1. `src/core/` owns all semantics, limits, runtime validation, and errors.
2. Runtime Unicode data is the compact image
   `vendor/unicode/17.0.0/compact/data.bin`, generated deterministically by
   `scripts/build-unicode-data.mjs` from the SHA-pinned source corpus under
   `vendor/unicode/17.0.0/`; the compact manifest digest is pinned in code and
   chained to the source manifest digest. UBA code and provenance live under
   `vendor/bidi-js-unicode17/`.
3. `src/contracts.js` owns public MCP discovery schemas; `src/library.js` is
   the stable direct-host entry.
4. `.codex-plugin/plugin.json` and `.mcp.json` own the source-local Agent entry.
5. `src/cli.js`, `src/mcp/server.js`, and `src/ui/server.js` own carrier
   framing only. The MCP server additionally owns bounded queues,
   backpressure, request deadlines, and cancellation — never Unicode
   semantics.
6. `test/` and the pinned conformance manifest own rerunnable regressions.
7. Documentation describes intended scope but cannot establish behavior.

There is no provider-neutral Capability or Procedure manifest.

## Exact entry points

- Core library: `import { executeOperation } from "text-integrity"`.
- CLI: `node bin/text-integrity.js ...` or raw JSON via `--json`.
- MCP: `node bin/text-integrity-mcp.js`, one bounded JSON-RPC message per
  line; modern requests carry `params._meta["io.modelcontextprotocol/protocolVersion"]`,
  legacy clients open with `initialize`.
- Human runtime: `node src/ui/server.js`, default
  `http://127.0.0.1:4173`.

## Current invariants

- All carrier semantics route through `src/core/`; browser code performs no
  Unicode algorithm.
- Inputs contain only explicit strings, byte arrays, options, and optional
  spans over an explicit source string. No path, URL, clipboard, workspace,
  parser, compiler, font, or network coordinate is accepted.
- Every operation runs only when the runtime reports Unicode 17.0.
- Unknown/missing fields and invalid tagged variants fail closed.
- Inspection never fabricates UTF-8 bytes for an isolated surrogate.
- Normalization is non-mutating and keeps canonical and compatibility
  equivalence separate.
- Comparison requires locale matcher and collation type in addition to all
  other supported options and returns both requested and resolved values.
- Transcoding is strict unless loss is explicitly allowed. The caller selects
  exactly one byte representation (`bytes`, `hex`, or `base64`); equivalent
  payload copies are never multiplied. BOM presence, first invalid byte, and
  round-trip equality remain visible.
- Difference explanation reports representation relations and coordinates; it
  never supplies author intent.
- Coordinate chunking never cuts an extended grapheme cluster and fails if one
  grapheme or the number of chunks exceeds the requested bounds.
- Free-text security output remains descriptive. Identifier mode requires one
  named profile. Source mode requires host spans and does no implicit scan.
- `internalSkeleton` removes Default_Ignorable code points before the
  confusables mapping. Confusable comparison uses full Unicode-17 UBA for LTR,
  RTL, and first-strong directions and never exposes a skeleton as normalized
  text.
- Profile conformance, restriction level, mixed numbers, and confusable class
  never become a safe/malicious/spoofed verdict or risk score.
- UTS #46 and each PRECIS profile stay separately named from normalization.
- Every Unicode source file and compressed conformance corpus is verified by
  size and SHA-256 at build/check time; the runtime loads only the compact
  image, whose manifest digest is pinned in code and must reproduce
  byte-for-byte from the pinned sources. Runtime behavior performs no network
  request.
- MCP publishes eight direct read-only/idempotent tools with closed tagged
  input schemas and closed typed output envelopes. The server is dual-era:
  modern `2026-07-28` requests (`server/discover`, per-request `_meta`
  version, `resultType`, `ttlMs`/`cacheScope`) are served statelessly; legacy
  revisions negotiate through `initialize`. Modern tool results carry a
  concise deterministic text summary plus the complete structured result;
  legacy `2025-06-18`+ results keep text JSON-equivalent to structured
  content, and pre-`2025-06-18` results carry the JSON text alone. Requests
  before `initialize` in the legacy era fail closed with `-32002`. Unknown
  versions in `_meta` receive `-32022` with the supported list.
- The MCP transport bounds its own memory: a bounded request queue, input
  paused while output is backpressured or the queue is full, resumed on
  drain; `notifications/cancelled` suppresses a queued request's response;
  requests past the deadline answer with an error; the connection keeps
  serving after each.
- The validated product-local plugin routes only to the packaged MCP entry and
  does not imply an installed-host or marketplace state.
- CLI/MCP input, JSON-RPC ID, the complete tool catalog, every cumulative text
  family, every detail list, core output, and complete MCP output have named
  bounds.
- The UI contains only repeat-use task controls, preserves whitespace, rejects
  empty byte entries, and aborts/invalidates stale requests on semantic changes.
- Package inventory includes the compact Unicode image and its manifest, the
  Unicode and UBA licenses/provenance, UTS #46 dependencies, and every
  runtime file while excluding the UCD text corpus, the conformance corpora,
  and browser artifacts. The full corpora remain in the repository for CI.

## Official conformance

`npm run check` must rerun, not merely inventory:

- all 20,034 Unicode 17 normalization cases;
- all 766 Unicode 17 grapheme-break cases;
- all 6,389 well-formed JavaScript-string UTS #46 test cases, including the
  supplemental X4_2 compatibility condition;
- all 770,241 BidiTest paragraph-mode cases;
- all 91,707 BidiCharacterTest cases.

The count is a narrow check of those corpora, not a general product-acceptance
metric.

## Required command and runtime smokes

```sh
npm run check
```

A reviewer must also run at least one current request through the library
entry, CLI raw JSON, live MCP in both eras (a modern `server/discover` +
`tools/call` and a legacy `initialize` + `tools/list` + `tools/call`), local
HTTP, and the rendered browser. A green static suite alone does not establish
runtime or human acceptance. Performance fences are rerun with
`node scripts/bench.mjs --slo` against `docs/PERFORMANCE_BASELINE.md`.

## Adversarial sequences

1. Inspect decomposed text plus a family emoji; compare code-point and grapheme
   counts. Repeat with an escaped isolated surrogate over CLI raw JSON.
2. Normalize decomposed `é` and circled digit one; verify canonical and
   compatibility relations differ.
3. Compare `A`/`a` with every option, then omit locale matcher or collation and
   verify a closed failure.
4. Strictly decode valid UTF-16LE with BOM, invalid UTF-8, and odd UTF-16LE;
   verify BOM, exact offset, and opt-in replacement paths. Run each transcode
   once per byte representation and verify only the selected representation
   appears.
5. Explain a CRLF/NFC/confusable composition in one call and verify the first
   code-point/grapheme coordinates plus all composed final relations.
6. Map `A + family emoji + CRLF + B`, then request a chunk smaller than the
   family grapheme and verify the negative regression.
7. Compare `☝` with `☝️` and verify Default_Ignorable removal makes the
   skeleton relation confusable. Exercise the official bidiSkeleton example.
8. Run all three identifier profiles on valid, invalid, mixed-number, and mixed-
   script inputs; verify no aggregate security label appears.
9. Supply same-scope confusable identifier spans plus a bidi control and CR
   line ending; then change scope and verify the pair is no longer reported.
10. Exercise UTS #46 nontransitional/transitional output, interior empty labels,
    final root dot, and the three PRECIS profiles including context and bidi
    failures.
11. Send a legal CLI value beginning with `--`, an empty byte-list item, a raw
    escaped surrogate, an oversized CLI JSON request, and an unknown field.
12. Send an oversized MCP line followed by a valid ping, an oversized or object
    JSON-RPC ID, a maximum transcode result, and a notification. Verify bounded
    recovery and silence for notifications.
13. Probe the MCP server as a dual-era client: a modern `server/discover` with
    `_meta` version `2026-07-28` returns `supportedVersions`; a request with
    an unknown `_meta` version receives `-32022`; a legacy `initialize`
    negotiates each supported revision and a pre-`initialize` request fails
    with `-32002`. Verify a modern `tools/call` returns a concise summary
    plus the complete structured result while the legacy era keeps
    JSON-equivalent text.
14. Open 5,000 pings against the MCP server without reading stdout, confirm
    the server's memory stays bounded, then resume reading and require every
    response. Cancel one request behind blocked output and verify its
    response is suppressed and the next ping still answers.
15. In one browser session, start a request, change operation, and verify that
    the old response cannot render. Check whitespace-only output, narrow width,
    keyboard traversal, and the byte-list error.

## Validation lanes

- Development regression: syntax, tests, schemas, hashes, bounds, conformance,
  package inventory, and carrier smokes — Agent/Controller PASS/FAIL/BLOCKED.
- Runtime Agent flow: live core/CLI/MCP/HTTP path; installed-host routing and
  credentials are separate facts — Agent/Controller PASS/FAIL/BLOCKED.
- Runtime human flow: real browser pointer/keyboard/responsive/error-recovery
  behavior — Agent/Controller PASS/FAIL/BLOCKED.
- Business/experience acceptance: task fit, value, and visual taste — owner
  OK/Not OK/Pending.

## Workspace escalations

A reviewer reports any shared ABI/error drift, installed namespace conflict,
duplicated cross-product abstraction, resource contention, or sibling
dependency under `tools-dev workspace escalations`. Use `none observed` when
current checks find none. Do not repair siblings from this repository.
