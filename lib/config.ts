/**
 * What the sign-in service needs from its environment, read in one place.
 *
 * Three values are load-bearing for every app at once, so production refuses
 * to start without them rather than inventing a default:
 *
 *  - SIGNIN_URL — the public origin. It IS the OIDC issuer: every app compares
 *    `iss` byte for byte, so it is used exactly as given (no trailing slash).
 *  - BETTER_AUTH_SECRET — signs the broker's own sessions and the signed
 *    authorize query handed to the sign-in page.
 *  - SIGNIN_PAIRWISE_SECRET — derives the per-app subject. Changing it changes
 *    every person's `sub` in every app: each app would see strangers. It is
 *    set once and never rotated.
 */
type Env = Record<string, string | undefined>;

export const MIN_SECRET_LENGTH = 32;
const DEV_SECRET = "development-only-secret-not-for-production-use";
const DEV_PAIRWISE = "development-only-pairwise-secret-not-for-production";
const DEV_URL = "http://localhost:3000";

export interface SigninConfig {
  /** Public origin and OIDC issuer, e.g. https://signin.example. */
  url: string;
  secret: string;
  pairwiseSecret: string;
  production: boolean;
}

const text = (value: string | undefined) => value?.trim() || "";

/** https, or http on localhost; no path, query or fragment. */
export function usableOrigin(value: string): string | null {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  const local = url.hostname === "localhost" || url.hostname === "127.0.0.1";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && local))
    return null;
  if (url.pathname !== "/" || url.search || url.hash) return null;
  if (url.username || url.password) return null;
  return url.origin;
}

function secretFrom(
  name: string,
  value: string,
  production: boolean,
  fallback: string,
): string {
  if (value.length >= MIN_SECRET_LENGTH) return value;
  if (production)
    throw new Error(`${name} is missing or shorter than ${MIN_SECRET_LENGTH} characters`);
  return fallback;
}

export function readConfig(env: Env = process.env): SigninConfig {
  const production = env.NODE_ENV === "production";
  const rawUrl = text(env.SIGNIN_URL);
  const url = rawUrl ? usableOrigin(rawUrl) : production ? null : DEV_URL;
  if (!url) throw new Error("SIGNIN_URL must be an https origin with no path");
  return {
    url,
    secret: secretFrom("BETTER_AUTH_SECRET", text(env.BETTER_AUTH_SECRET), production, DEV_SECRET),
    pairwiseSecret: secretFrom(
      "SIGNIN_PAIRWISE_SECRET",
      text(env.SIGNIN_PAIRWISE_SECRET),
      production,
      DEV_PAIRWISE,
    ),
    production,
  };
}
