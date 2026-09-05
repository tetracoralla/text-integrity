import { byteArray, deepFreezeContract, string, withError } from "./schemas/common.js";
import {
  compare,
  index,
  inspect,
  normalize,
  transcodeFor
} from "./schemas/basic.js";
import { precisCompare, precisEnforce, uts46 } from "./schemas/protocol.js";
import { explainDifference } from "./schemas/difference.js";
import {
  freeTextSecurity,
  identifierSecurity,
  sourceDiagnose
} from "./schemas/security.js";
import { namespaceIntegrity } from "./schemas/namespace.js";

export const OUTPUT_SCHEMAS = deepFreezeContract({
  inspect: withError(inspect),
  normalize: withError(normalize),
  compare: withError(compare),
  transcode: withError(
    transcodeFor("bytes", byteArray),
    transcodeFor("hex", string),
    transcodeFor("base64", string)
  ),
  security: withError(freeTextSecurity, identifierSecurity, sourceDiagnose),
  explain_difference: withError(explainDifference),
  index: withError(index),
  protocol_profile: withError(uts46("to_ascii"), uts46("to_unicode"), precisEnforce, precisCompare),
  namespace_integrity: withError(namespaceIntegrity)
});
