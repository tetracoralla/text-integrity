# Performance baseline and release fences

This document records measured baselines produced by
[`scripts/bench.mjs`](../scripts/bench.mjs) and derives the release fences it
enforces with `--slo`. The fences are regression fences: each one is the
recorded baseline with explicit headroom (or, for throughput floors, a value
set well below the baseline so slower CI runners do not flake). They are not a
product-acceptance or fitness claim.

## Recording

- Date: 2026-08-31
- Package: text-integrity 1.0.0 release candidate
- Runtime: Node.js v22.22.1 (Unicode 17.0)
- Machine: Apple M4, 10 cores, 16 GB RAM, macOS (darwin-arm64)
- Command: `node --expose-gc scripts/bench.mjs`

The same command must be rerun on the current source when this document or the
fences are revised; numbers below are the record of that one run, not a promise.

## Baseline (Node 22, this machine)

| Measurement | Result |
| --- | --- |
| Cold first security identifier call, median of 10 fresh processes | 25.1 ms (p99 28.8 ms), median RSS 54.1 MB |
| Warm `security` identifier (comparison included), n=20,000 | median 0.014 ms, p99 0.058 ms, max 0.314 ms |
| Warm `security` free_text, n=1,000 | median 0.007 ms, p99 0.012 ms |
| Warm `explain_difference`, n=5,000 | median 0.071 ms, p99 0.409 ms |
| Steady state, 1,000,000 free_text calls | 6.75 s, 148,058 calls/s |
| Steady-state RSS growth after 1M calls | 176 KB after explicit collection |
| stdio burst, 1,002 modern-era requests incl. process start | 82 ms total; all 1,002 responses recovered |
| Slow consumer (5,000 pings unread for 500 ms) | server RSS 55,888 KB while paused; all 5,001 responses recovered; exit 0 |
| Cancellation behind blocked output | cancelled response absent; follow-up catalog request answered; 2 expected responses |
| Complete modern `tools/list` response (8 tools) | 22,172 bytes (~5,543 tokens at 4 bytes/token) |
| Max transcode (4,096 B → UTF-16LE hex) core result | 20,843 bytes |
| Same result, legacy MCP envelope | 41,862 bytes (2.01× core) |
| Same result, modern MCP envelope | 21,121 bytes (1.01× core) |

Context from the pre-1.0 review that motivated this work: cold first call was
~147 ms (core data load ~83 ms) with median process RSS ~109.5 MB, and the MCP
envelope duplicated the complete JSON, so a maximum transcode response was
~105 KB against a ~52 KB core result. The 1.0.0 layout (compact binary
interval tables, single byte representation, concise modern text) is what the
table above records.

The catalog is intentionally kept complete (closed input and output schemas
for all eight direct tools) and stays under the 24 KiB catalog budget. Modern
clients may cache `tools/list` (`ttlMs`/`cacheScope`); the catalog size itself
was accepted as a product trade-off rather than converted to a
search/describe/run indirection.

## Release fences (`scripts/bench.mjs --slo`)

| Fence | Limit | Baseline | Headroom |
| --- | --- | --- | --- |
| Cold first security call median | ≤ 75 ms | 25.1 ms | 3.0× |
| Cold-process RSS median | ≤ 96 MB | 54.1 MB | 1.8× |
| Warm security identifier p99 | ≤ 0.25 ms | 0.058 ms | 4.3× |
| Warm explain_difference p99 | ≤ 5 ms | 0.409 ms | 12.2× (collation variability) |
| Steady-state throughput | ≥ 25,000 calls/s | 148,058/s | floor at 0.17× baseline (see variance note) |
| stdio burst recovery | exactly 1,002 responses | 1,002 | exact |
| Slow-consumer paused RSS | ≤ 96 MB | 56.1 MB | 1.7× |
| Slow-consumer response recovery | all 5,001 | 5,001 | exact |
| Slow-consumer process exit | exactly 0 | 0 | exact |
| Queued cancellation suppression and recovery | both true | both true | exact |
| Max modern MCP envelope | ≤ 131,072 B | 21,121 B | hard LIMITS cap |
| Catalog bytes | ≤ 24,576 B | 22,172 B | hard LIMITS cap |
| Steady-state RSS growth over 1M calls | ≤ 32 MB | 0.2 MB | bounded ceiling |

`npm run bench -- --slo` (or `node scripts/bench.mjs --slo`) exits non-zero
when any fence is violated. The throughput floor and RSS fences are wide on
purpose: the fence exists to catch order-of-magnitude regressions (unbounded
queue growth, accidental O(n²) parsing, a lost compact layout), not to compare
machines. Do not tighten a fence without a new recorded baseline for the
change that motivates it.

Observed variance note (2026-08-31): the same machine measured 148,582
free_text calls/s on an idle run and 44,964 calls/s immediately after a full
`npm run check` (thermal/background-load interference), a 3.3× swing with no
code change. That measurement is why the throughput floor sits at 25,000/s:
it must fail only on genuine regressions, not on machine load. Latency fences
showed no comparable swing locally (warm p99 stayed within a few percent
across runs). The first public GitHub-hosted Ubuntu run measured a 51.3 ms
cold median and 64.9 ms p99 with the same source; the 75 ms cold fence includes
headroom over that slower runner while remaining well below the pre-1.0
~147 ms observation.

## Method notes

- Cold start measures a fresh `node -e` process from launch to the first
  completed `security` identifier call end to end (module graph, compact blob
  read + SHA-256 verification, first full UBA confusable comparison).
- Warm percentiles measure `executeOperation` in-process after one warm-up
  call, `performance.now()` around each call.
- Steady state runs one million `free_text` calls; `--expose-gc` collects
  before and after so the growth figure reflects retained memory, not pending
  garbage. `--expose-gc` is optional; without it the growth fence still holds
  with the same 32 MB bound.
- The slow-consumer scenario pauses the client read side for 500 ms while
  5,001 requests are already written, then resumes and requires every response.
- The cancellation scenario deterministically blocks output, queues and
  cancels one request, verifies that its response is absent, drains output,
  and requires a subsequent modern catalog request to succeed.
- Envelope ratios compare byte lengths of the JSON-RPC response for the same
  core result: legacy era (full JSON text + structuredContent) versus modern
  era (concise text + structuredContent).
