# Contributing

Thanks for considering a contribution. This repository is a deterministic
Unicode product with explicit inputs and bounded results. Read
[`docs/PRODUCT_MODEL.md`](docs/PRODUCT_MODEL.md) when a change would alter
product meaning. Use [`docs/REVIEW_CONTRACT.md`](docs/REVIEW_CONTRACT.md) for
review and handoff; it is not a pre-implementation checklist.

## Getting started

```sh
git clone <repository>
cd text-integrity
npm ci
```

Before proposing or handing off a change, `npm run check` must pass. It reruns
syntax checks, the full test suite including every pinned Unicode conformance
corpus, compact-data reproducibility, and the package inventory.

## Ground rules

- All semantics live in `src/core/`. CLI, MCP, and the local web surface are
  adapters; do not reimplement Unicode logic in a carrier.
- Inputs stay explicit strings and byte arrays. Do not add file paths, URLs,
  clipboard access, workspace traversal, ambient configuration, or network
  access to any operation.
- Keep schemas closed (`additionalProperties: false`), error codes stable, and
  every documented budget enforced in the shared core.
- New Unicode claims or new data require authoritative pinned sources and a
  conformance story before they enter the core; discuss in an issue first.
- Regenerating the compact runtime image requires the vendor sources:
  `npm run build:unicode` (uses `vendor/unicode/17.0.0/`), then update the
  pinned manifest digest in `src/core/unicode-security-data.js`. `npm run
  check` fails until the committed image reproduces.

## Making changes

1. Open or comment on an issue describing the change for anything beyond a
   clear bug fix.
2. Keep edits surgical; match local style; no unrelated refactors.
3. Add or extend tests that fail if the change is reverted. Fixes to guards,
   error branches, and edge cases need a negative regression.
4. Run `npm run check` and, when touching performance-relevant paths,
   `node scripts/bench.mjs --slo`.
5. Update `CHANGELOG.md` under `Unreleased` and any affected documentation
   (README limits, product model, review contract).
6. Open a pull request from a feature branch. The title and commits should
   describe the change, not the process.

Dependency changes go through Dependabot or an explicit issue; the lockfile
resolves against the official npm registry, and pull requests are checked by
dependency review for known vulnerabilities.

## Releasing (maintainers)

For a brand-new npm name, trusted publishing cannot be configured until the
package exists. Before the first real release, the package owner must reserve
the name once with a minimal `0.0.0` bootstrap publication from a clean local
directory using an npm account protected by 2FA. That bootstrap package must
not claim to be Text Integrity 1.0.0. Then configure the npm Trusted Publisher
for `tetracoralla/text-integrity`, workflow `release.yml`, environment `npm`, and
allowed action `npm publish`; protect that GitHub environment with a required
reviewer. Do not add an automation token to this repository.

For every real release:

1. Confirm `npm run check` on all supported Node majors locally or via CI.
2. Move `CHANGELOG.md` entries from `Unreleased` to a new version heading and
   confirm that the package version exactly matches the intended tag.
3. Tag `vX.Y.Z`. CI fails closed on a tag/version mismatch, builds the exact
   package, generates the SBOM and checksums,
   attaches build provenance attestations, publishes to npm with provenance
   (trusted publishing), and re-verifies the downloaded artifact.
4. Create a GitHub Release with the artifacts and their checksums.

## License

By contributing, you agree that your contributions are licensed under the
Apache License 2.0 ([`LICENSE`](LICENSE)).
