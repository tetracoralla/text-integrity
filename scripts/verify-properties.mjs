import {
  PROPERTY_VERIFICATION_LIMITS,
  runPropertyVerification
} from "../src/reference/property-verification.js";

if (process.argv.length !== 2) {
  process.stderr.write("usage: npm run property:check\n");
  process.exit(2);
}

const result = runPropertyVerification();
const serialized = JSON.stringify(result);
if (result.complete !== true
  || result.passed !== true
  || Buffer.byteLength(serialized, "utf8") > PROPERTY_VERIFICATION_LIMITS.maxSerializedBytes) {
  throw new Error("Property verification did not produce a complete bounded passing observation.");
}
process.stdout.write(`${serialized}\n`);
