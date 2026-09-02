# Performance regression contract

This document describes the performance check enforced by
`scripts/bench.mjs --slo`. It is not a run log, a portable speed promise, or
product acceptance. Current measurements belong in CI artifacts or task
records and must be reacquired from the current source.

## Executable authority

The `SLO` object in `scripts/bench.mjs` owns the exact enforced values. This
table is a human-readable map of the same boundaries.

| Fence | Limit |
| --- | --- |
| Cold first security call median | at most 75 ms |
| Cold-process RSS median | at most 96 MB |
| Warm security identifier p99 | at most 0.25 ms |
| Warm difference explanation p99 | at most 5 ms |
| Steady-state free-text throughput | at least 25,000 calls/s |
| Stdio burst recovery | exactly 1,002 responses |
| Slow-consumer paused RSS | at most 96 MB |
| Slow-consumer recovery | all 5,001 responses and exit 0 |
| Queued cancellation suppression and recovery | both true |
| Complete modern MCP envelope | at most the shared MCP result limit |
| Complete tool catalog | at most the shared catalog limit |
| Retained RSS growth over one million calls | at most 32 MB |

Run the enforced check with:

```sh
node --expose-gc scripts/bench.mjs --slo
```

## Measurement scope

- Cold start runs a fresh process through its first identifier-security result,
  including module loading and compact-data verification.
- Warm percentiles measure the shared library core after warm-up.
- Steady state executes one million free-text calls and, when explicit garbage
  collection is available, compares retained RSS after collection.
- The stdio burst and slow-consumer cases require every expected response and a
  clean exit after backpressure.
- The cancellation case requires a cancelled queued response to stay absent
  and a later request on the same connection to succeed.
- Envelope and catalog measurements include complete serialized carrier
  framing, not only semantic payload bytes.

## Interpretation and changes

A nonzero exit is a failure of this named regression check. Host contention,
thermal state, or another process may explain a measurement but does not waive
it or prove a code regression; re-run under controlled conditions and retain
both observations outside this contract.

The fences have deliberate cross-machine headroom and are meant to catch
material regressions such as unbounded buffering, a lost compact layout, or
accidental quadratic work. Do not weaken a threshold merely to obtain a green
run. Change it only with a source-backed reason, a replacement measurement,
and review of the action the check blocks.
