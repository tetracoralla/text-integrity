# Independent native/WASM reference runner

`native/` is an independent Rust implementation used to compare selected Text
Integrity semantics across Node, a native process, raw WASM, and the packaged
bounded WASM loader. It is verifier infrastructure, not a second public product
and not an authority that can promote its own coverage.

## Boundary

The runner consumes the same closed tagged request model and pinned Unicode,
UTS #39, UTS #46, PRECIS, normalization, grapheme, script, bidi, and security
inputs as the Node implementation, but executes independent Rust algorithms.

Coverage is operation-specific:

- some public operations are complete semantic comparison targets;
- some composed operations expose only a named deterministic projection;
- ICU locale collation remains environment-bound;
- a public WASM operation is advertised only when the bounded loader validates
  the complete projected result contract for that operation.

The current classification is owned by the verifier output,
`reference/behavior-manifest.json`, and `src/reference/wasm.js`. Do not copy
case counts or promotion status from an older report into a current claim.

## Build and compare

The repository pins its Rust toolchain and Cargo lockfile. Ordinary checks are:

```sh
cargo fmt --check --manifest-path native/Cargo.toml
cargo test --locked --manifest-path native/Cargo.toml
npm run check:independent
npm run wasm:check
```

`npm run check:independent` regenerates required Rust data, builds the native
and WASM targets, executes the bounded differential corpus, compares complete
declared semantic projections and errors, and reports the actual batch/work
maxima. `wasm:check` requires the packaged module bytes and manifest to
reproduce from current source and lock state.

Use `npm run wasm:write` only when intentionally updating the derived module and
manifest after a source change. It does not publish.

## Raw WASM ABI

The import-free module exposes memory allocation, execution, result access, ABI
identity, and limit-reporting functions. Exact current exports, status codes,
input/batch/result ceilings, and cumulative expensive-work ceilings are owned
by:

- `src/reference/wasm.js` for the bounded loader contract;
- `wasm/MANIFEST.json` for the packaged module identity and interface;
- `native/src/lib.rs` for the Rust ABI implementation.

The frame is preflighted before its first item. Invalid ownership, mismatched
lengths, oversized frames, excessive aggregate results, or excessive declared
work publish no partial result and clear stale output. A valid request must
still succeed on the same instance after a carrier rejection.

Core request/result limits remain smaller than the raw batch carrier where
applicable. A large batch allowance never expands one operation's semantic
budget.

## Claim limits

- A successful differential run means only that the named current cases and
  projections matched.
- Engine labels and environment-bound fields may be excluded only through the
  explicit semantic projection owned by shared code.
- Stage-level parity does not establish a complete consumer operation.
- Generated Rust tables must reproduce from pinned sources; their presence is
  not enough.
- The verifier does not establish release readiness, installed Agent routing,
  public substitutability, application policy, or business acceptance.

Reproducible WASM packaging uses Rust 1.89.0 and remaps the Cargo home and
repository paths to fixed virtual roots. This removes machine-specific panic
locations from the stripped module; the packaged bytes and manifest must match
a rebuild on Linux as well as the maintainer build. Ambient Rust compiler flags
do not alter this packaging recipe.
