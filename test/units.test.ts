import { describe, expect, it } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { decodeJwt, decodeProtectedHeader } from "jose";
import { readConfig } from "../lib/config";
import { appleClientSecret, enabledUpstreams, socialProviders, UPSTREAMS } from "../lib/upstreams";
import { CLIENT_APPS, redirectUri, registryProblems } from "../lib/clients";
import { signedOAuthQuery } from "../lib/login";
import { createSigninAuth } from "../lib/auth";
import { secretEnvName, syncClients } from "../lib/sync-clients";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import * as schema from "../lib/db/schema";
import { BROKER_ENV, createDatabase } from "./harness";

const applePem = generateKeyPairSync("ec", { namedCurve: "P-256" })
  .privateKey.export({ type: "pkcs8", format: "pem" })
  .toString();

const ALL = {
  GOOGLE_CLIENT_ID: "g", GOOGLE_CLIENT_SECRET: "g",
  APPLE_CLIENT_ID: "ch.example.signin", APPLE_TEAM_ID: "TEAM123456", APPLE_KEY_ID: "KEY1234567", APPLE_PRIVATE_KEY: applePem,
  GITHUB_CLIENT_ID: "h", GITHUB_CLIENT_SECRET: "h",
  X_CLIENT_ID: "x", X_CLIENT_SECRET: "x",
  META_APP_ID: "m", META_APP_SECRET: "m",
};

describe("upstream providers", () => {
  it("offers none with no env, and each one only with all of its env", () => {
    expect(enabledUpstreams({})).toEqual([]);
    expect(enabledUpstreams(ALL).map((u) => u.id)).toEqual(["google", "apple", "github", "twitter", "facebook"]);
    for (const upstream of UPSTREAMS) {
      for (const missing of upstream.env) {
        const env = { ...ALL, [missing]: "  " };
        expect(enabledUpstreams(env).map((u) => u.id)).not.toContain(upstream.id);
      }
    }
  });

  it("asks no provider for an email address", async () => {
    const providers = (await socialProviders(ALL)) as Record<string, { scope?: string[]; disableDefaultScope?: boolean }>;
    expect(Object.keys(providers).sort()).toEqual(["apple", "facebook", "github", "google", "twitter"]);
    for (const [id, p] of Object.entries(providers)) {
      expect(p.disableDefaultScope, id).toBe(true);
      expect((p.scope ?? []).some((s) => /email/i.test(s)), id).toBe(false);
    }
  });

  it("mints Apple's client secret from the team key", async () => {
    const now = Date.UTC(2026, 9, 30);
    const jwt = await appleClientSecret(ALL, now);
    expect(decodeProtectedHeader(jwt)).toMatchObject({ alg: "ES256", kid: "KEY1234567" });
    const claims = decodeJwt(jwt);
    expect(claims).toMatchObject({ iss: "TEAM123456", sub: "ch.example.signin", aud: "https://appleid.apple.com" });
    expect(claims.exp! - claims.iat!).toBeLessThanOrEqual(180 * 24 * 3600);
  });
});

describe("config", () => {
  it("refuses to start in production without its three values", () => {
    expect(() => readConfig({ NODE_ENV: "production" })).toThrow(/SIGNIN_URL/);
    expect(() => readConfig({ NODE_ENV: "production", SIGNIN_URL: "https://signin.example" })).toThrow(/BETTER_AUTH_SECRET/);
    expect(() =>
      readConfig({ NODE_ENV: "production", SIGNIN_URL: "https://signin.example", BETTER_AUTH_SECRET: "s".repeat(32) }),
    ).toThrow(/SIGNIN_PAIRWISE_SECRET/);
  });

  it("takes the issuer as an origin only", () => {
    const base = { NODE_ENV: "production", BETTER_AUTH_SECRET: "s".repeat(32), SIGNIN_PAIRWISE_SECRET: "p".repeat(32) };
    expect(readConfig({ ...base, SIGNIN_URL: "https://signin.example" }).url).toBe("https://signin.example");
    expect(() => readConfig({ ...base, SIGNIN_URL: "http://signin.example" })).toThrow();
    expect(() => readConfig({ ...base, SIGNIN_URL: "https://signin.example/auth" })).toThrow();
  });
});

describe("client registry", () => {
  it("is sound as committed", () => {
    expect(registryProblems(CLIENT_APPS)).toEqual([]);
  });

  it("uses the callback accountkit's OIDC provider sends", () => {
    expect(redirectUri({ origin: "https://heidi.orangecat.ch" })).toBe(
      "https://heidi.orangecat.ch/api/auth/callback/bitbaum-signin",
    );
  });

  it("refuses two apps on one host (they would share a subject)", () => {
    expect(
      registryProblems([
        { id: "a", name: "A", origin: "https://x.example" },
        { id: "b", name: "B", origin: "https://x.example" },
      ]).join(),
    ).toMatch(/already another app's host/);
  });

  it("refuses plain http, paths and bad ids", () => {
    expect(registryProblems([{ id: "A b", name: "x", origin: "http://x.example/path" }])).toHaveLength(3);
  });
});

describe("the sign-in page's form", () => {
  it("posts back exactly the signed parameters", () => {
    const page = new URLSearchParams(
      "client_id=heidi&scope=openid&ba_param=ba_param&ba_param=client_id&ba_param=exp&ba_param=scope&exp=9&sig=abc&utm=injected",
    );
    const signed = new URLSearchParams(signedOAuthQuery(page)!);
    expect(signed.get("utm")).toBeNull();
    expect(signed.get("sig")).toBe("abc");
    expect(signed.getAll("ba_param")).toHaveLength(4);
  });

  it("has nothing to post without a signature", () => {
    expect(signedOAuthQuery({ client_id: "heidi" })).toBeNull();
  });
});

describe("clients sync", () => {
  it("activates apps whose secret is in env, waits for the rest, retires what left", async () => {
    const database = await createDatabase();
    const auth = await createSigninAuth({
      database: drizzleAdapter(database.db, { provider: "pg", schema }),
      env: BROKER_ENV,
    });
    const apps = [
      { id: "heidi", name: "Heidi", origin: "https://heidi.orangecat.ch" },
      { id: "solon", name: "Solon", origin: "https://solon.orangecat.ch" },
    ];
    const heidiSecret = "h".repeat(43);
    const env = { [secretEnvName("heidi")]: heidiSecret, [secretEnvName("solon")]: "too-short" };
    expect(secretEnvName("surf-your-life")).toBe("SIGNIN_CLIENT_SECRET_SURF_YOUR_LIFE");

    const first = await syncClients(auth, apps, env);
    expect(first).toEqual({ active: ["heidi"], waiting: ["solon"], retired: [] });
    const stored = await database.client.query<{ client_secret: string }>(
      `select client_secret from oauth_client where client_id = 'heidi'`,
    );
    expect(stored.rows[0].client_secret).not.toContain(heidiSecret);

    const again = await syncClients(auth, apps, { ...env, [secretEnvName("solon")]: "s".repeat(43) });
    expect(again.active).toEqual(["heidi", "solon"]);

    const shrunk = await syncClients(auth, apps.slice(0, 1), env);
    expect(shrunk.retired).toEqual(["solon"]);
    const rows = await database.client.query(
      `select client_id, disabled, skip_consent, subject_type, require_pkce, token_endpoint_auth_method from oauth_client order by client_id`,
    );
    expect(rows.rows).toEqual([
      { client_id: "heidi", disabled: false, skip_consent: true, subject_type: "pairwise", require_pkce: true, token_endpoint_auth_method: "client_secret_post" },
      { client_id: "solon", disabled: true, skip_consent: true, subject_type: "pairwise", require_pkce: true, token_endpoint_auth_method: "client_secret_post" },
    ]);
  });
});
