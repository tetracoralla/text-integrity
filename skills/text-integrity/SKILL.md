---
name: text-integrity
description: Use Text Integrity for deterministic Unicode 17 facts about explicit text or bytes: inspect representation, normalize, compare, transcode, map indexes, explain differences, observe named security properties, or apply UTS #46 and PRECIS.
---

# Text Integrity

Select one of the eight direct tools without a preliminary discovery call when
the user supplies explicit text or bytes and asks for a deterministic Unicode,
encoding, coordinate, collation, security-observation, difference, or named
protocol-string result.

Ask for a missing choice only when it changes the requested fact, such as the
normalization form, source encoding, locale comparison options, identifier
direction, or protocol profile. Do not infer author intent or silently choose a
security or application-acceptance policy.

Keep free text, identifiers, caller-provided source spans, and confusable
comparison distinct. Present security results as named observations or profile
conformance, never as an overall safe, malicious, spoofed, or risk-score
verdict. Preserve reported replacement, truncation, runtime dependence, and
declared limitations.

On a stable error, report the code and the missing or invalid fact. Do not retry
with altered text, lossy conversion, a different locale, or a different profile
unless the user authorizes that semantic change.
