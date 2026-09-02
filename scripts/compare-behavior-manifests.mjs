import { readFileSync } from "node:fs";
import { compareBehaviorManifests } from "../src/reference/behavior.js";

const [beforePath, afterPath] = process.argv.slice(2);
if (!beforePath || !afterPath) {
  process.stderr.write("usage: node scripts/compare-behavior-manifests.mjs BEFORE.json AFTER.json\n");
  process.exit(2);
}

const before = JSON.parse(readFileSync(beforePath, "utf8"));
const after = JSON.parse(readFileSync(afterPath, "utf8"));
process.stdout.write(`${JSON.stringify(compareBehaviorManifests(before, after), null, 2)}\n`);
