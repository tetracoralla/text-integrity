import { generateCargoWasmSbom } from "./release-sbom.js";

process.stdout.write(`${JSON.stringify(generateCargoWasmSbom(), null, 2)}\n`);
