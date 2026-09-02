export class DuplicateJsonKeyError extends TypeError {}
export class BoundedJsonDepthError extends RangeError {}

function schemaValueIdentity(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean"
    || typeof value === "number") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(schemaValueIdentity).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => (
    `${JSON.stringify(key)}:${schemaValueIdentity(value[key])}`
  )).join(",")}}`;
}

export function assertUniqueJsonObjectKeys(json, {
  maxDepth,
  subject = "JSON input"
}) {
  let index = 0;
  const syntax = () => { throw new SyntaxError("Invalid JSON syntax."); };
  const isDigit = (code) => code >= 0x30 && code <= 0x39;
  const skipWhitespace = () => {
    while (index < json.length && [0x09, 0x0a, 0x0d, 0x20].includes(json.charCodeAt(index))) {
      index += 1;
    }
  };
  const scanString = () => {
    if (json.charCodeAt(index) !== 0x22) syntax();
    const start = index;
    index += 1;
    while (index < json.length) {
      const code = json.charCodeAt(index);
      if (code === 0x22) {
        index += 1;
        return json.slice(start, index);
      }
      if (code <= 0x1f) syntax();
      if (code !== 0x5c) {
        index += 1;
        continue;
      }
      index += 1;
      if (index >= json.length) syntax();
      const escape = json[index];
      if (escape === "u") {
        if (!/^[0-9a-fA-F]{4}$/u.test(json.slice(index + 1, index + 5))) syntax();
        index += 5;
      } else if ('"\\/bfnrt'.includes(escape)) {
        index += 1;
      } else {
        syntax();
      }
    }
    syntax();
  };
  const scanNumber = () => {
    if (json[index] === "-") index += 1;
    if (json[index] === "0") {
      index += 1;
    } else {
      const first = json.charCodeAt(index);
      if (first < 0x31 || first > 0x39) syntax();
      index += 1;
      while (isDigit(json.charCodeAt(index))) index += 1;
    }
    if (json[index] === ".") {
      index += 1;
      if (!isDigit(json.charCodeAt(index))) syntax();
      while (isDigit(json.charCodeAt(index))) index += 1;
    }
    if (json[index] === "e" || json[index] === "E") {
      index += 1;
      if (json[index] === "+" || json[index] === "-") index += 1;
      if (!isDigit(json.charCodeAt(index))) syntax();
      while (isDigit(json.charCodeAt(index))) index += 1;
    }
  };
  const consumeLiteral = (literal) => {
    if (json.slice(index, index + literal.length) !== literal) syntax();
    index += literal.length;
  };
  const parseValue = (depth) => {
    if (depth > maxDepth) {
      throw new BoundedJsonDepthError(`${subject} exceeds depth ${maxDepth}.`);
    }
    skipWhitespace();
    const token = json[index];
    if (token === '"') {
      scanString();
      return;
    }
    if (token === "{") {
      index += 1;
      skipWhitespace();
      if (json[index] === "}") {
        index += 1;
        return;
      }
      const keys = new Set();
      while (true) {
        skipWhitespace();
        const keyToken = scanString();
        const key = JSON.parse(keyToken);
        if (keys.has(key)) {
          throw new DuplicateJsonKeyError(`${subject} must not contain duplicate object keys.`);
        }
        keys.add(key);
        skipWhitespace();
        if (json[index] !== ":") syntax();
        index += 1;
        parseValue(depth + 1);
        skipWhitespace();
        if (json[index] === "}") {
          index += 1;
          return;
        }
        if (json[index] !== ",") syntax();
        index += 1;
      }
    }
    if (token === "[") {
      index += 1;
      skipWhitespace();
      if (json[index] === "]") {
        index += 1;
        return;
      }
      while (true) {
        parseValue(depth + 1);
        skipWhitespace();
        if (json[index] === "]") {
          index += 1;
          return;
        }
        if (json[index] !== ",") syntax();
        index += 1;
      }
    }
    if (token === "t") return consumeLiteral("true");
    if (token === "f") return consumeLiteral("false");
    if (token === "n") return consumeLiteral("null");
    if (token === "-" || isDigit(json.charCodeAt(index))) return scanNumber();
    syntax();
  };

  skipWhitespace();
  parseValue(0);
  skipWhitespace();
  if (index !== json.length) syntax();
}

export function validateJsonGraph(root, {
  limits,
  field = "record",
  rootLabel = field,
  isProxy = () => false
}) {
  const active = new Set();
  const stack = [{ value: root, depth: 0, field }];
  let nodeCount = 0;
  while (stack.length > 0) {
    const { value, depth, field: currentField, exit } = stack.pop();
    if (exit === true) {
      active.delete(value);
      continue;
    }
    nodeCount += 1;
    if (nodeCount > limits.maxJsonNodes) {
      throw new RangeError(`${rootLabel} exceeds ${limits.maxJsonNodes} JSON nodes.`);
    }
    if (depth > limits.maxJsonDepth) {
      throw new RangeError(`${rootLabel} exceeds JSON depth ${limits.maxJsonDepth}.`);
    }
    if (value === null || typeof value === "boolean") continue;
    if (typeof value === "string") {
      if (value.length > limits.maxStringCodeUnits) {
        throw new RangeError(`${currentField} exceeds the string code-unit limit.`);
      }
      continue;
    }
    if (typeof value === "number") {
      if (!Number.isFinite(value)) throw new TypeError(`${currentField} must be a finite JSON number.`);
      continue;
    }
    if (typeof value !== "object") throw new TypeError(`${currentField} is not JSON-safe.`);
    if (isProxy(value)) throw new TypeError(`${currentField} must not be a Proxy.`);
    if (active.has(value)) throw new TypeError(`${rootLabel} must be an acyclic JSON value.`);
    active.add(value);
    stack.push({ value, depth, field: currentField, exit: true });

    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) {
        throw new TypeError(`${currentField} must use the standard Array prototype.`);
      }
      if (value.length > limits.maxArrayItems) {
        throw new RangeError(`${currentField} exceeds the array-item limit.`);
      }
      const keys = Reflect.ownKeys(value);
      if (keys.length !== value.length + 1 || keys.some((key) => {
        if (key === "length") return false;
        return typeof key !== "string" || !/^(0|[1-9][0-9]*)$/u.test(key)
          || Number(key) >= value.length;
      })) {
        throw new TypeError(`${currentField} must be a dense JSON array without extra fields.`);
      }
      for (let index = value.length - 1; index >= 0; index -= 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor)) {
          throw new TypeError(`${currentField}[${index}] must be an enumerable data value.`);
        }
        stack.push({
          value: descriptor.value,
          depth: depth + 1,
          field: `${currentField}[${index}]`
        });
      }
      continue;
    }

    if (Object.getPrototypeOf(value) !== Object.prototype) {
      throw new TypeError(`${currentField} must use the standard Object prototype.`);
    }
    const keys = Reflect.ownKeys(value);
    if (keys.length > limits.maxObjectKeys) {
      throw new RangeError(`${currentField} exceeds the object-key limit.`);
    }
    for (const key of keys) {
      if (typeof key !== "string" || key.length > limits.maxIdentifierCodeUnits
        || !key.isWellFormed()) {
        throw new TypeError(`${currentField} has an unsupported property key.`);
      }
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor)) {
        throw new TypeError(`${currentField}.${key} must be an enumerable data value.`);
      }
      stack.push({
        value: descriptor.value,
        depth: depth + 1,
        field: `${currentField}.${key}`
      });
    }
  }
}

export function valueMatchesSchema(value, schema) {
  if (schema.oneOf) {
    return schema.oneOf.filter((branch) => valueMatchesSchema(value, branch)).length === 1;
  }
  if (Object.hasOwn(schema, "const") && value !== schema.const) return false;
  if (schema.enum && !schema.enum.includes(value)) return false;
  if (schema.type === "null") return value === null;
  if (schema.type === "string") {
    return typeof value === "string"
      && (schema.minLength === undefined || value.length >= schema.minLength)
      && (schema.maxLength === undefined || value.length <= schema.maxLength);
  }
  if (schema.type === "boolean") return typeof value === "boolean";
  if (schema.type === "integer") {
    return Number.isInteger(value)
      && (schema.minimum === undefined || value >= schema.minimum)
      && (schema.maximum === undefined || value <= schema.maximum);
  }
  if (schema.type === "number") {
    return typeof value === "number" && Number.isFinite(value)
      && (schema.minimum === undefined || value >= schema.minimum)
      && (schema.maximum === undefined || value <= schema.maximum);
  }
  if (schema.type === "array") {
    if (!Array.isArray(value)
      || (schema.minItems !== undefined && value.length < schema.minItems)
      || (schema.maxItems !== undefined && value.length > schema.maxItems)
      || (schema.contains !== undefined
        && !value.some((item) => valueMatchesSchema(item, schema.contains)))
      || (schema.items !== undefined
        && !value.every((item) => valueMatchesSchema(item, schema.items)))) return false;
    if (schema.uniqueItems === true) {
      const identities = value.map((item) => schemaValueIdentity(item));
      if (new Set(identities).size !== identities.length) return false;
    }
    return true;
  }
  if (schema.type === "object") {
    if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
    if ((schema.required ?? []).some((name) => !Object.hasOwn(value, name))) return false;
    if (schema.additionalProperties === false
      && Object.keys(value).some((name) => !Object.hasOwn(schema.properties ?? {}, name))) return false;
    return Object.entries(value).every(([name, item]) => {
      const property = schema.properties?.[name];
      return property === undefined || valueMatchesSchema(item, property);
    });
  }
  return true;
}
