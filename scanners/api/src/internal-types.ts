import type { PathSegment } from './pointer.js';

export type ApiKind = 'openapi3' | 'swagger2' | 'postman2';

export type SourceFormat = 'yaml' | 'json';

/** Resolves a path within the parsed document to a best-effort source location. */
export interface Locator {
  locate(path: readonly PathSegment[]): { line?: number; column?: number };
}

/** A candidate file that self-identified as one of the supported API document kinds. */
export interface ParsedDoc {
  kind: ApiKind;
  format: SourceFormat;
  /** Parsed document as plain JS data (objects/arrays/primitives), like JSON.parse output. */
  root: Record<string, unknown>;
  locator: Locator;
}

export interface SecurityScheme {
  name: string;
  type: string | undefined;
  in?: string;
  scheme?: string;
  flow?: string; // Swagger 2 oauth2
  flows?: Record<string, unknown>; // OpenAPI 3 oauth2
  /** The `name` field of an apiKey scheme (the actual header/query param name to send). */
  paramName?: string;
  path: readonly PathSegment[];
}

export interface NormalizedOperation {
  path: string;
  method: string;
  operation: Record<string, unknown>;
  /** Merged path-item-level + operation-level parameters (raw objects). */
  parameters: Record<string, unknown>[];
  /** True only when the operation object itself literally has a `security` key. */
  hasOwnSecurity: boolean;
  ownSecurity: unknown[] | undefined;
  opPath: readonly PathSegment[];
}

export interface NormalizedApiDoc {
  kind: 'openapi3' | 'swagger2';
  root: Record<string, unknown>;
  securitySchemes: SecurityScheme[];
  /** True only when the document root literally has a `security` key. */
  hasGlobalSecurity: boolean;
  globalSecurity: unknown[] | undefined;
  servers: Array<{ url: string; path: readonly PathSegment[] }>;
  operations: NormalizedOperation[];
}
