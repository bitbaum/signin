import { placeholderEmail } from "@bitbaum/accountkit/auth";
import { importPKCS8, SignJWT } from "jose";

/**
 * The upstream providers this service holds credentials for, ONCE, on behalf
 * of every app (fleet STACK.md, "Identity"). Each is switched on only when all
 * of its env is set, and is otherwise absent from the sign-in page — never a
 * button that fails.
 *
 * Every provider is asked for the least it can give: an identifier. No email
 * scope, no profile scope where the provider allows it. A value never
 * requested cannot leak, be linked on, or be handed to an app.
 */
type Env = Record<string, string | undefined>;

export type UpstreamId = "google" | "apple" | "github" | "twitter" | "facebook";

export interface Upstream {
  id: UpstreamId;
  /** What the button says after "Continue with". */
  label: string;
  /** All of these must be set for the provider to be offered. */
  env: readonly string[];
}

/** Order is the order of the buttons. */
export const UPSTREAMS: readonly Upstream[] = [
  { id: "google", label: "Google", env: ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"] },
  {
    id: "apple",
    label: "Apple",
    env: ["APPLE_CLIENT_ID", "APPLE_TEAM_ID", "APPLE_KEY_ID", "APPLE_PRIVATE_KEY"],
  },
  { id: "github", label: "GitHub", env: ["GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET"] },
  { id: "twitter", label: "X", env: ["X_CLIENT_ID", "X_CLIENT_SECRET"] },
  { id: "facebook", label: "Facebook", env: ["META_APP_ID", "META_APP_SECRET"] },
];

const text = (value: string | undefined) => value?.trim() || "";

export function enabledUpstreams(env: Env): Upstream[] {
  return UPSTREAMS.filter((u) => u.env.every((name) => text(env[name])));
}

export function upstreamById(id: string, env: Env): Upstream | null {
  return enabledUpstreams(env).find((u) => u.id === id) ?? null;
}

/**
 * Who signed in, and nothing else. The stored user carries no name, no
 * picture and no provider address: its email is a reserved `.invalid`
 * placeholder derived from provider + subject (accountkit's rule), so two
 * providers that report the same address can never meet on it.
 */
export function pseudonymousUser(providerId: UpstreamId, subject: unknown) {
  const sub = String(subject ?? "");
  if (!sub) throw new Error(`${providerId}: profile has no subject`);
  return {
    name: "",
    email: placeholderEmail(providerId, sub),
    emailVerified: false,
    image: undefined,
  };
}

/** Apple's client secret is a short-lived ES256 JWT signed with the team key. */
export const APPLE_SECRET_LIFETIME_SECONDS = 150 * 24 * 60 * 60; // Apple allows 6 months
export async function appleClientSecret(env: Env, now = Date.now()): Promise<string> {
  const pem = text(env.APPLE_PRIVATE_KEY).replace(/\\n/g, "\n");
  const key = await importPKCS8(pem, "ES256");
  const iat = Math.floor(now / 1000);
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: text(env.APPLE_KEY_ID) })
    .setIssuer(text(env.APPLE_TEAM_ID))
    .setSubject(text(env.APPLE_CLIENT_ID))
    .setAudience("https://appleid.apple.com")
    .setIssuedAt(iat)
    .setExpirationTime(iat + APPLE_SECRET_LIFETIME_SECONDS)
    .sign(key);
}

/** better-auth `socialProviders` for every upstream whose env is set. */
export async function socialProviders(env: Env) {
  const on = new Set(enabledUpstreams(env).map((u) => u.id));
  const providers: Record<string, unknown> = {};
  if (on.has("google"))
    providers.google = {
      clientId: text(env.GOOGLE_CLIENT_ID),
      clientSecret: text(env.GOOGLE_CLIENT_SECRET),
      disableDefaultScope: true,
      scope: ["openid"],
      prompt: "select_account",
      mapProfileToUser: (p: { sub?: string }) => pseudonymousUser("google", p.sub),
    };
  if (on.has("apple"))
    providers.apple = {
      clientId: text(env.APPLE_CLIENT_ID),
      clientSecret: await appleClientSecret(env),
      disableDefaultScope: true,
      mapProfileToUser: (p: { sub?: string }) => pseudonymousUser("apple", p.sub),
    };
  if (on.has("github"))
    providers.github = {
      clientId: text(env.GITHUB_CLIENT_ID),
      clientSecret: text(env.GITHUB_CLIENT_SECRET),
      // No scope at all: GitHub then grants read access to public profile
      // data only, and /user/emails answers 404.
      disableDefaultScope: true,
      mapProfileToUser: (p: { id?: number | string }) => pseudonymousUser("github", p.id),
    };
  if (on.has("twitter"))
    providers.twitter = {
      clientId: text(env.X_CLIENT_ID),
      clientSecret: text(env.X_CLIENT_SECRET),
      // users.read needs tweet.read alongside it; no users.email, no offline.access.
      disableDefaultScope: true,
      scope: ["users.read", "tweet.read"],
      mapProfileToUser: (p: { data?: { id?: string } }) => pseudonymousUser("twitter", p.data?.id),
    };
  if (on.has("facebook"))
    providers.facebook = {
      clientId: text(env.META_APP_ID),
      clientSecret: text(env.META_APP_SECRET),
      disableDefaultScope: true,
      scope: ["public_profile"],
      mapProfileToUser: (p: { id?: string; sub?: string }) =>
        pseudonymousUser("facebook", p.sub ?? p.id),
    };
  return providers;
}
