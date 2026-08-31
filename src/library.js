// Stable direct-host entry. Hosts that already hold structured arguments can
// call the core directly with zero Agent turns; every carrier (CLI, MCP, local
// web surface) routes through the same functions exported here.
import { PRODUCT_NAME, VERSION } from "./version.js";

export {
  executeOperation,
  SUPPORTED_OPERATIONS,
  SUPPORTED_ENCODINGS,
  SUPPORTED_NORMALIZATION_FORMS,
  SUPPORTED_BYTE_REPRESENTATIONS
} from "./core/operations.js";
export { TOOL_DEFINITIONS } from "./contracts.js";
export { OUTPUT_SCHEMAS } from "./output-schemas.js";
export { LIMITS } from "./core/limits.js";
export { TextIntegrityError, errorPayload } from "./core/errors.js";
export { runtimeInfo, PINNED_UNICODE_VERSION } from "./core/runtime.js";
export {
  UNICODE_SECURITY_VERSION,
  UTS39_REVISION,
  UNICODE_SECURITY_MANIFEST_SHA256
} from "./core/unicode-security-data.js";

export const LIBRARY_INFO = Object.freeze({ name: PRODUCT_NAME, version: VERSION });
