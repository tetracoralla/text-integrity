# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Prepared first public release under Apache License 2.0. No registry or hosted
release is claimed until the tagged release workflow completes.

### Added

- Dual-era MCP transport: the modern stateless `2026-07-28` protocol
  (`server/discover`, per-request `_meta` protocol versions, `resultType`,
  `ttlMs`/`cacheScope` on list results, `-32022` version negotiation errors)
  alongside the legacy `initialize` handshake era
  (`2025-11-25`/`2025-06-18`/`2025-03-26`/`2024-11-05`/`2024-10-07`).
- MCP transport backpressure: bounded request queue, input pause/resume tied
  to output drain, request deadlines, `notifications/cancelled` suppression
  for queued requests, and recovery after each.
- `server/discover`-based modern discovery and deterministic tool order for
  client caching.
- Stable library entry (`text-integrity` → `src/library.js`) exposing the
  core operations, contracts, limits, and error envelope for zero-Agent-call
  hosts.
- `byteRepresentation` (`bytes`/`hex`/`base64`) for `transcode`: exactly one
  byte representation is returned instead of four equivalent copies.
- Modern-era MCP tool results: concise deterministic text summary plus the
  complete structured result; the result JSON is no longer duplicated into
  the text block (legacy eras keep the previous JSON-text behavior).
- Build-time compact Unicode data image
  (`vendor/unicode/17.0.0/compact/`): deterministic binary interval tables
  generated from the pinned UCD/UTS #39 sources, SHA-256 verified on load;
  cold first security call dropped from ~147 ms to ~25 ms and resident memory
  from ~110 MB to ~54 MB with byte-identical lookups across all 1,114,112
  code points.
- Performance baseline suite (`npm run bench`,
  [`docs/PERFORMANCE_BASELINE.md`](docs/PERFORMANCE_BASELINE.md)) measuring
  cold start, warm percentiles, burst throughput, slow-consumer bounds,
  cancellation recovery, envelope sizes, catalog cost, million-call steady
  state, and memory growth, with `--slo` release fences derived from the
  recorded baseline.
- Open-source surface: Apache-2.0 `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`,
  package metadata (repository, bugs, homepage, exports, files), official
  npm registry pinning (`.npmrc`, lockfile), CI matrix, CodeQL, Dependabot,
  dependency review, and a release workflow with npm provenance, SBOM,
  checksums, and artifact attestation.
- Repository-wide LF checkout rules so Windows does not rewrite pinned,
  digest-verified source artifacts.
- Platform-correct repository path conversion in the release checker, including
  Windows drive-letter paths.
- Cross-platform npm subprocess invocation for package inventory and installed
  artifact smoke checks on Windows.

### Changed

- Runtime package ships only the compact data image, code, and licenses:
  the five conformance corpora (74.4% of the previous package) and the full
  UCD text files stay in the repository and CI; the package dropped to
  roughly 240 KB.
- Requests before `initialize` in the legacy era now fail closed with
  `-32002` instead of being answered.
- Node support matrix is `>=22.22.1 <23 || >=24.20.0 <25 || >=26.8.1 <27`
  after running the full
  conformance suite on Node 22.22.1, 24.20.0, and 26.8.1.
- Cold-start regression headroom now includes the measured public
  GitHub-hosted Ubuntu runner, while remaining below the pre-1.0 baseline.
- Slow-consumer transport tests now count newline-delimited responses across
  arbitrary stream chunk boundaries.

## [0.3.0]

- Text difference explanation, coordinate mapping, grapheme-safe chunking,
  identifier/source diagnostics, UTS #46 and RFC 8265 PRECIS profiles,
  Unicode 17 security observations, and the vendored Unicode-17 UBA adapter
  with full conformance corpora (internal baseline release).
