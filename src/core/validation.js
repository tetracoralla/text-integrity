import { TextIntegrityError } from "./errors.js";

export function requireObject(value, field = "arguments") {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TextIntegrityError("INVALID_INPUT", `${field} must be an object.`, { field });
  }
  return value;
}

export function assertKeys(value, allowed, required = []) {
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unknown.length > 0) {
    throw new TextIntegrityError("INVALID_INPUT", "Unknown fields are not allowed.", { unknownFields: unknown.sort() });
  }
  const missing = required.filter((key) => !Object.hasOwn(value, key));
  if (missing.length > 0) {
    throw new TextIntegrityError("INVALID_INPUT", "Required fields are missing.", { missingFields: missing });
  }
}

export function requireString(value, field) {
  if (typeof value !== "string") {
    throw new TextIntegrityError("INVALID_INPUT", `${field} must be a string.`, { field });
  }
  return value;
}

export function requireBoolean(value, field) {
  if (typeof value !== "boolean") {
    throw new TextIntegrityError("INVALID_INPUT", `${field} must be a boolean.`, { field });
  }
  return value;
}

export function requireEnum(value, field, values) {
  if (!values.includes(value)) {
    throw new TextIntegrityError("INVALID_INPUT", `${field} must be one of: ${values.join(", ")}.`, { field, allowed: values });
  }
  return value;
}

export function requireInteger(value, field, minimum, maximum) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new TextIntegrityError("INVALID_INPUT", `${field} must be an integer from ${minimum} to ${maximum}.`, {
      field,
      minimum,
      maximum
    });
  }
  return value;
}

export function requireArray(value, field, maximum = Infinity) {
  if (!Array.isArray(value)) {
    throw new TextIntegrityError("INVALID_INPUT", `${field} must be an array.`, { field });
  }
  if (value.length > maximum) {
    throw new TextIntegrityError("REQUEST_TOO_LARGE", `${field} exceeds the ${maximum}-item limit.`, {
      field,
      actualItems: value.length,
      limitItems: maximum
    });
  }
  return value;
}
