import { readFileSync } from "node:fs";
import { validateCargoWasmSbom, validateNpmSbom } from "./release-sbom.js";

if (process.argv.length !== 4) {
  process.stderr.write("usage: node scripts/verify-release-sboms.mjs <npm-sbom.json> <cargo-wasm-sbom.json>\n");
  process.exit(2);
}

const npmResult = validateNpmSbom(JSON.parse(readFileSync(process.argv[2], "utf8")));
const cargoResult = validateCargoWasmSbom(JSON.parse(readFileSync(process.argv[3], "utf8")));
process.stdout.write(`release SBOM files verified: npm ${npmResult.componentCount}; Cargo/WASM ${cargoResult.componentCount}\n`);
