import { isRefNode, resolveLocalRef } from './ref.js';
import { isPlainObject, MAX_WALK_DEPTH } from './util.js';
import type { PathSegment } from './pointer.js';

export interface SchemaVisit {
  /** The (possibly $ref-resolved) schema object at this node. */
  node: Record<string, unknown>;
  /** Path from the traversal root to this node, in the original (un-dereferenced) document shape. */
  path: readonly PathSegment[];
  /** The property name this node was reached through, when it is an object property. */
  propertyName: string | undefined;
}

export type SchemaVisitor = (visit: SchemaVisit) => void;

interface WalkState {
  root: unknown;
  visit: SchemaVisitor;
  refStack: ReadonlySet<string>;
  objectStack: ReadonlySet<object>;
  depth: number;
}

/**
 * Recursively walk an OpenAPI/Swagger schema-like object: properties, array
 * items, and allOf/oneOf/anyOf/additionalProperties combinators. Follows
 * local $ref (within the same document only) and is safe against both $ref
 * cycles and structural object cycles (e.g. YAML anchor self-reference),
 * bounded additionally by a hard depth cap.
 */
export function walkSchema(
  schema: unknown,
  root: unknown,
  visit: SchemaVisitor,
  path: readonly PathSegment[] = [],
  propertyName: string | undefined = undefined,
): void {
  walkInternal(schema, path, propertyName, {
    root,
    visit,
    refStack: new Set(),
    objectStack: new Set(),
    depth: 0,
  });
}

function walkInternal(
  schema: unknown,
  path: readonly PathSegment[],
  propertyName: string | undefined,
  state: WalkState,
): void {
  if (state.depth > MAX_WALK_DEPTH) return;
  if (!isPlainObject(schema)) return;

  let node: Record<string, unknown> = schema;
  let refStack = state.refStack;
  let objectStack = state.objectStack;

  if (isRefNode(node)) {
    const ref = node.$ref;
    if (refStack.has(ref)) return; // $ref cycle
    const resolved = resolveLocalRef(state.root, ref);
    if (!isPlainObject(resolved)) return; // unresolved/external ref: noted-and-skipped by the caller
    refStack = new Set(refStack).add(ref);
    node = resolved;
  }

  if (objectStack.has(node)) return; // structural cycle (e.g. YAML anchor self-reference)
  objectStack = new Set(objectStack).add(node);

  state.visit({ node, path, propertyName });

  const nextState: WalkState = { ...state, refStack, objectStack, depth: state.depth + 1 };

  const properties = node.properties;
  if (isPlainObject(properties)) {
    for (const [name, sub] of Object.entries(properties)) {
      walkInternal(sub, [...path, 'properties', name], name, nextState);
    }
  }

  if (node.items !== undefined) {
    walkInternal(node.items, [...path, 'items'], propertyName, nextState);
  }

  for (const combinator of ['allOf', 'oneOf', 'anyOf'] as const) {
    const arr = node[combinator];
    if (Array.isArray(arr)) {
      arr.forEach((sub, i) => walkInternal(sub, [...path, combinator, i], propertyName, nextState));
    }
  }

  if (isPlainObject(node.additionalProperties)) {
    walkInternal(
      node.additionalProperties,
      [...path, 'additionalProperties'],
      undefined,
      nextState,
    );
  }
}
