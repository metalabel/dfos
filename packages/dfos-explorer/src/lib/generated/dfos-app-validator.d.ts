/*

  Types for the generated dfos-app.v1 validator (build-schema-validator.mjs).

  Hand-authored on purpose: ajv's standalone output is plain JS, and this type
  surface — a predicate carrying its last error list — is fixed by ajv's calling
  convention, not by the schema. It does not change when the schema does.

*/

export interface SchemaError {
  instancePath: string;
  schemaPath: string;
  keyword: string;
  params: Record<string, unknown>;
  message?: string;
}

export interface SchemaValidator {
  (data: unknown): boolean;
  errors?: SchemaError[] | null;
}

declare const validate: SchemaValidator;
export default validate;
export { validate };
