# Security Policy

## Supported versions

Once the first public version is released, the current major is supported.
Fixes are applied to the latest minor release line; there are no separate
long-term patch branches.

| Version | Supported |
| ------- | --------- |
| 1.0.x   | After the first public release |

## Reporting a vulnerability

Report privately at <https://github.com/tetracoralla/text-integrity/security/advisories/new>.
If that is impossible, open a regular issue stating only that a security
discussion is needed and a maintainer will provide a contact.

- Do not include secrets, credentials, or real user data in a report.
- Include reproduction steps and the affected version.
- Expect an acknowledgment within 7 days. Fixes for accepted issues are
  released as patch versions and credited in the changelog unless you prefer
  to remain anonymous.

Public disclosure is coordinated with the reporter; please do not disclose
before a fix is released.

## Scope

This package processes explicit strings and byte arrays supplied by the
caller. It accepts no caller-supplied file paths or URLs, reads no environment
configuration, clipboard, or workspace, performs no network access, and runs
all MCP tools read-only. Its only filesystem read is its own packaged,
digest-verified Unicode runtime image.
Security issues in the following areas are in scope:

- Any path where caller input causes unbounded memory or CPU use beyond the
  documented budgets (see Limits in the README).
- Any escape of the closed schemas or error envelopes, or mutation of inputs.
- Integrity weaknesses in the pinned Unicode data chain (vendor manifest →
  compact image → runtime verification).
- MCP transport issues: unbounded buffering under a slow consumer, responses
  emitted for cancelled requests, or protocol-era confusion between the modern
  stateless and legacy handshake behaviors.

Not in scope: the security *semantics of Unicode itself* (spoofing judgments
beyond the pinned UTS #39 data), and vulnerabilities in Node.js or
dependencies — report those upstream. Dependency advisories are handled
through Dependabot and dependency review in this repository.

## Data integrity chain

- The Unicode 17 source files are pinned by
  `vendor/unicode/17.0.0/MANIFEST.json` (SHA-256 per file).
- `scripts/build-unicode-data.mjs` verifies those pins and deterministically
  generates `vendor/unicode/17.0.0/compact/data.bin`; `npm run check` requires
  the committed image to reproduce byte-for-byte.
- At runtime the compact manifest digest is pinned in code; the blob is
  verified against the manifest, and the manifest is chained to the source
  manifest digest before any operation runs.
- The vendored UBA adapter is verified against
  `vendor/bidi-js-unicode17/MANIFEST.json` in every check run.
