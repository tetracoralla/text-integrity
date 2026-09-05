import { readFileSync, writeFileSync } from "node:fs";
import { compareBehaviorManifests, createBehaviorManifest } from "../src/reference/behavior.js";

const CORPUS_PATH = new URL("../reference/behavior-corpus.json", import.meta.url);
const MANIFEST_PATH = new URL("../reference/behavior-manifest.json", import.meta.url);
const corpus = JSON.parse(readFileSync(CORPUS_PATH, "utf8"));
const rendered = `${JSON.stringify(createBehaviorManifest(corpus), null, 2)}\n`;
const mode = process.argv[2] ?? "--check";

if (mode === "--write") {
  writeFileSync(MANIFEST_PATH, rendered);
  process.stdout.write("behavior manifest updated\n");
} else if (mode === "--stdout") {
  process.stdout.write(rendered);
} else if (mode === "--check") {
  const committedText = readFileSync(MANIFEST_PATH, "utf8");
  const committed = JSON.parse(committedText);
  const generated = JSON.parse(rendered);
  if (JSON.stringify(committed.environment) === JSON.stringify(generated.environment)) {
    if (committedText !== rendered) {
      process.stderr.write("behavior manifest differs from the current canonical corpus and reference runtime\n");
      process.exitCode = 1;
    } else {
      process.stdout.write("behavior manifest matches the current canonical corpus and reference runtime\n");
    }
  } else {
    const comparison = compareBehaviorManifests(committed, generated);
    const disallowed = comparison.changes.filter((change) => {
      if (change.kind !== "semantic_changed") return change.kind !== "environment_metadata_changed";
      return generated.cases.find((entry) => entry.id === change.id)?.reproducibilityTarget === "cross_runtime_exact";
    });
    if (committed.corpus.sha256 !== generated.corpus.sha256
      || committed.product.version !== generated.product.version
      || comparison.verificationMetadataChanged
      || disallowed.length > 0) {
      process.stderr.write("cross-runtime-exact behavior differs from the committed reference manifest\n");
      process.exitCode = 1;
    } else {
      process.stdout.write("cross-runtime-exact behavior matches; environment-bound cases were replayed without enforcing equality\n");
    }
  }
} else {
  process.stderr.write("usage: node scripts/behavior-manifest.mjs [--check|--write|--stdout]\n");
  process.exitCode = 2;
}
