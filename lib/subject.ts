import { createHmac } from "node:crypto";

/**
 * The pairwise subject an app sees for a person: the ONE statement of how it
 * is derived (OIDC Core 8.1).
 *
 *   root:     base64( HMAC-SHA256( SIGNIN_PAIRWISE_SECRET, "<sector>.<userId>" ) )
 *   persona:  base64( HMAC-SHA256( SIGNIN_PAIRWISE_SECRET, "<sector>.<userId>|persona|<personaId>" ) )
 *
 * `sector` is the host of the app's redirect URI. The root form is exactly
 * what @better-auth/oauth-provider issues today (its computePairwiseSub); the
 * flow tests prove the two agree on every token, and test/subject.test.ts pins
 * it to a literal, so nothing can change an existing person's identifier in
 * an existing app without failing CI.
 *
 * Personas (future, not built): a person may one day hold several "lives"
 * under one root, each with its own subject per app. The root life is the
 * account itself — `persona` undefined, or equal to `userId` — and keeps
 * today's value byte for byte. Only a non-root persona adds its id as a
 * further HMAC input. `|` cannot occur in a host or in a better-auth id, so a
 * persona subject can never equal any root subject's input.
 *
 * A life's id lives in its own id space: `life_<uuid>`. better-auth user ids
 * are alphanumeric and never carry that prefix, so a life id can never equal a
 * user id and silently fall back to the root subject. Anything else that is
 * not this user's own id is refused, never hashed.
 */
export const LIFE_PREFIX = "life_";
const LIFE_ID = /^life_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function isLifeId(value: string): boolean {
  return LIFE_ID.test(value);
}
export interface SubjectInput {
  secret: string;
  /** The app's redirect host, e.g. "heidi.orangecat.ch". */
  sector: string;
  userId: string;
  /** A life under this account: `life_<uuid>`. Undefined or `userId` = the root. */
  persona?: string;
}

export function isRootPersona(userId: string, persona: string | undefined): boolean {
  return persona === undefined || persona === userId;
}

export function pairwiseSub({ secret, sector, userId, persona }: SubjectInput): string {
  if (!secret || !sector || !userId) throw new Error("pairwiseSub: secret, sector and userId are required");
  const root = `${sector}.${userId}`;
  let input = root;
  if (!isRootPersona(userId, persona)) {
    if (!persona || !isLifeId(persona))
      throw new Error(`pairwiseSub: a persona must be undefined, the user id, or ${LIFE_PREFIX}<uuid>`);
    input = `${root}|persona|${persona}`;
  }
  return createHmac("sha256", secret).update(input).digest("base64");
}

/** The sector of a client: the host of its first redirect URI (as the plugin computes it). */
export function sectorOf(redirectUri: string): string {
  return new URL(redirectUri).host;
}
