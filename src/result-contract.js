import { OUTPUT_SCHEMAS } from "./output-schemas.js";
import { deepFreezeContract } from "./schemas/common.js";

export const PUBLIC_RESULT_SCHEMA_VERSION = "text-integrity.public-result-contract/2";
export const RESULT_SCHEMA_RESOURCE_VERSION = "text-integrity.result-schema-resource/1";
export const JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema";

const RESOURCE_ROOT = "text-integrity://schemas/public-result-contract/2";

function schemaDocument(operation, outputSchema) {
  const uri = `${RESOURCE_ROOT}/${operation}`;
  return deepFreezeContract({
    $schema: JSON_SCHEMA_DIALECT,
    $id: uri,
    title: `Text Integrity ${operation} result`,
    "x-text-integrity-contract": PUBLIC_RESULT_SCHEMA_VERSION,
    "x-text-integrity-resource": RESULT_SCHEMA_RESOURCE_VERSION,
    "x-text-integrity-operation": operation,
    ...structuredClone(outputSchema)
  });
}

export const RESULT_SCHEMA_RESOURCES = deepFreezeContract(Object.fromEntries(
  Object.entries(OUTPUT_SCHEMAS).map(([operation, outputSchema]) => {
    const schema = schemaDocument(operation, outputSchema);
    return [operation, {
      operation,
      uri: schema.$id,
      name: `${operation} result schema`,
      title: `Strict ${operation} result schema`,
      description: `Complete leaf-closed ${PUBLIC_RESULT_SCHEMA_VERSION} schema for ${operation}.`,
      mimeType: "application/schema+json",
      schema
    }];
  })
));

export const RESULT_SCHEMA_RESOURCE_LIST = deepFreezeContract(
  Object.values(RESULT_SCHEMA_RESOURCES).map(({ schema: _schema, ...resource }) => resource)
);

export function resultSchemaResourceForOperation(operation) {
  return RESULT_SCHEMA_RESOURCES[operation] ?? null;
}

export function resultSchemaResourceForUri(uri) {
  return Object.values(RESULT_SCHEMA_RESOURCES).find((resource) => resource.uri === uri) ?? null;
}
