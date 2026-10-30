import { createHash, createHmac } from "node:crypto";
import { betterAuth } from "better-auth";
import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";
import { readConfig, type SigninConfig } from "./config";
import { socialProviders } from "./upstreams";

type Env = Record<string, string | undefined>;

/** Scopes accountkit's OIDC client asks for. `email` is accepted and answered with a placeholder. */
export const SCOPES = ["openid", "profile", "email"] as const;

/** The sign-in page and the (never used) consent page, relative to SIGNIN_URL. */
export const LOGIN_PAGE = "/";
export const CONSENT_PAGE = "/consent";
export const ERROR_PAGE = "/problem";

/**
 * How a client secret is kept: SHA-256, never the secret itself. Stated here
 * (rather than left to the plugin's default) because `clients:sync` writes
 * the registry's rows and must store the secret the same way.
 */
export function hashClientSecret(secret: string): string {
  return createHash("sha256").update(secret).digest("base64url");
}

/**
 * The address an app is shown when it asks for the `email` scope.
 *
 * The stored placeholder (accountkit `placeholderEmail`) is the same for every
 * app, so handing it out would give apps a shared key to join their records
 * on — exactly what the pairwise subject exists to prevent. This one is
 * derived per app and per person, is `.invalid` (RFC 2606: it cannot receive
 * mail) and is never verified.
 */
export function appScopedEmail(
  pairwiseSecret: string,
  clientId: string,
  userId: string,
): string {
  const digest = createHmac("sha256", pairwiseSecret)
    .update(`email.${clientId}.${userId}`)
    .digest("hex")
    .slice(0, 32);
  return `${digest}@signin.invalid`;
}

export interface CreateSigninAuthOptions {
  /** A better-auth database adapter (drizzle on pg in production, pglite in tests). */
  database: Parameters<typeof betterAuth>[0]["database"];
  env?: Env;
  config?: SigninConfig;
}

export async function createSigninAuth(options: CreateSigninAuthOptions) {
  const env = options.env ?? process.env;
  const config = options.config ?? readConfig(env);
  const providers = await socialProviders(env);

  return betterAuth({
    appName: "bitbaum sign-in",
    baseURL: config.url,
    basePath: "/api/auth",
    secret: config.secret,
    database: options.database,
    telemetry: { enabled: false },
    // Rate limiting is limitkit's, keyed on the proxy hop (lib/http.ts).
    rateLimit: { enabled: false },
    // No passwords here: this service is a broker for providers, not an
    // account system of its own.
    emailAndPassword: { enabled: false },
    socialProviders: providers,
    account: {
      accountLinking: {
        // An address is never an identity. Each (provider, subject) is its own
        // person here; nothing joins two of them.
        enabled: false,
        disableImplicitLinking: true,
      },
      encryptOAuthTokens: true,
    },
    user: {
      // A person can leave; their pairwise subjects die with the row.
      deleteUser: { enabled: true },
      changeEmail: { enabled: false },
    },
    session: {
      // The broker's session is what lets a second app sign in without asking
      // the provider again. Short, because it is shared by every app on this
      // browser.
      expiresIn: 24 * 60 * 60,
      updateAge: 60 * 60,
    },
    advanced: {
      useSecureCookies: config.production,
      ipAddress: { disableIpTracking: true },
      cookiePrefix: "signin",
    },
    onAPIError: { errorURL: `${config.url}${ERROR_PAGE}` },
    databaseHooks: {
      account: {
        // The service needs to know WHO signed in, never to act at the
        // provider on their behalf: provider tokens are dropped before storage.
        create: {
          before: async (data) => ({
            data: { ...data, accessToken: null, refreshToken: null, idToken: null },
          }),
        },
        update: {
          before: async (data) => ({
            data: { ...data, accessToken: null, refreshToken: null, idToken: null },
          }),
        },
      },
    },
    plugins: [
      jwt({
        // The issuer is the origin, not /api/auth: apps build discovery from
        // SIGNIN_ISSUER + /.well-known/openid-configuration.
        jwt: { issuer: config.url },
        // RS256 is the one algorithm every OIDC client must accept.
        jwks: { keyPairConfig: { alg: "RS256", modulusLength: 2048 } },
      }),
      oauthProvider({
        loginPage: LOGIN_PAGE,
        consentPage: CONSENT_PAGE,
        scopes: [...SCOPES],
        // The plugin computes the subject itself; lib/subject.ts states the
        // derivation and the tests hold the two equal, byte for byte.
        pairwiseSecret: config.pairwiseSecret,
        grantTypes: ["authorization_code", "refresh_token"],
        allowDynamicClientRegistration: false,
        // Clients are the registry's rows (lib/clients.ts, clients:sync).
        storeClientSecret: { hash: async (secret: string) => hashClientSecret(secret) },
        customUserInfoClaims: ({ user, jwt: token }) => {
          const clientId = String(token.client_id ?? token.azp ?? "");
          return {
            email: appScopedEmail(config.pairwiseSecret, clientId, user.id),
            email_verified: false,
          };
        },
      }),
    ],
  });
}

export type SigninAuth = Awaited<ReturnType<typeof createSigninAuth>>;
