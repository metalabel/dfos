/*

  THE ROLE SET — THE CANONICAL SPELLING OF "WHICH ROLES THIS PROOF COVERS".

  A key proof binds a candidate key to a POSITION in a chain, and a position has
  a role. `roleSet` is the member that carries that: the subset of the closed set
  {auth, assert, controller} the envelope consents to, serialized ONE way and
  only one way — the subset in the fixed order `auth,assert,controller`,
  comma-joined, no whitespace, no duplicates, never empty.

  WHY A STRING AND NOT AN ARRAY. The member lives inside the CLOSED payload whose
  canonical bytes are recomputed and byte-compared by the verifier (see
  key-proof.ts). Every member of that payload is a string, so the byte contract
  has exactly one shape to pin per language. An array member would need its own
  canonicalization rule — element order, empty-array handling, nesting — layered
  on top of the one this file already fixes.

  WHY THE ORDER IS FIXED RATHER THAN SORTED-AT-SERIALIZE. `auth,assert,controller`
  is the declaration order of the three key arrays on an identity operation, not
  an alphabetical accident. A verifier reading the string sees the same order it
  reads the chain in.

  ANY OTHER BYTE FORM IS A SCHEMA REJECT — the same class as a member-order
  violation, and for the same reason: `assert,auth` and `auth,assert` name the
  same set, so admitting both would mean one role set has more than one payload
  spelling and the payload stops being a function of its members.

  Byte-twin: `roleSet` in dfos-protocol-go/role_set.go.

*/

/**
 * The CLOSED role set. Membership in an identity operation's `authKeys`,
 * `assertKeys`, and `controllerKeys` arrays respectively — the three positions a
 * key can hold in a chain, and the only three a proof can consent to.
 *
 * THIS ORDER IS THE CANONICAL SERIALIZATION ORDER. It is not sorted; it is the
 * order the roles appear in an identity operation.
 */
export const KEY_ROLES = ['auth', 'assert', 'controller'] as const;

/** One role a key can hold in an identity chain. */
export type KeyRole = (typeof KEY_ROLES)[number];

const isKeyRole = (value: string): value is KeyRole =>
  (KEY_ROLES as readonly string[]).includes(value);

/**
 * Serialize a set of roles to its ONE canonical spelling. Duplicates in the input
 * collapse (a set is a set); an unknown role or an empty result throws, because
 * neither can be signed.
 *
 * This is the producer half. `parseRoleSet` is the verifier half, and the two are
 * inverses on exactly the canonical strings: `parseRoleSet(serializeRoleSet(r))`
 * round-trips, and `serializeRoleSet(parseRoleSet(s)) === s` for every `s` the
 * parse admits.
 */
export const serializeRoleSet = (roles: Iterable<KeyRole>): string => {
  const present = new Set<string>();
  for (const role of roles) {
    if (!isKeyRole(role)) {
      throw new Error(`invalid role set: unknown role ${JSON.stringify(role)}`);
    }
    present.add(role);
  }
  if (present.size === 0) throw new Error('invalid role set: must name at least one role');
  return KEY_ROLES.filter((role) => present.has(role)).join(',');
};

/**
 * Parse a role set from its canonical spelling, or `null` when the bytes are not
 * that spelling. Returns `null` rather than throwing so the caller raises the
 * failure in ITS OWN vocabulary — a `schema` rejection inside key-proof
 * verification, a chain error inside the identity walk.
 *
 * THE PARSE IS THE CANONICALITY CHECK. It is strict in every direction at once:
 * an unknown role, a duplicate, a member out of the fixed order, any whitespace
 * (` auth` is not `auth`), an empty segment, and the empty string all return
 * `null`. There is no lenient mode and no normalization — a producer that meant
 * `auth,assert` must spell it `auth,assert`.
 */
export const parseRoleSet = (value: string): KeyRole[] | null => {
  const parts = value.split(',');
  const roles: KeyRole[] = [];
  const seen = new Set<string>();
  for (const part of parts) {
    if (!isKeyRole(part) || seen.has(part)) return null;
    seen.add(part);
    roles.push(part);
  }
  // The order gate. Everything above admits `assert,auth`; only this refuses it.
  if (roles.join(',') !== KEY_ROLES.filter((role) => seen.has(role)).join(',')) return null;
  return roles;
};

/** True when `value` is exactly the canonical spelling of the set it names. */
export const isCanonicalRoleSet = (value: string): boolean => parseRoleSet(value) !== null;

/**
 * Does this role set cover `role`? The question the CHAIN WALK asks: an
 * introduction of key K to role R is proved only by an envelope whose role set
 * includes R. A non-canonical role set covers nothing — it never parsed.
 */
export const roleSetCovers = (value: string, role: KeyRole): boolean =>
  parseRoleSet(value)?.includes(role) ?? false;
