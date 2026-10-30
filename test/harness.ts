import { readFileSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { PGlite } from "@electric-sql/pglite";
import { drizzle } from "drizzle-orm/pglite";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import * as schema from "../lib/db/schema";
import { createSigninAuth, type SigninAuth } from "../lib/auth";
import { createSigninHandler } from "../lib/http";
import { signedOAuthQuery } from "../lib/login";
import { secretEnvName, syncClients } from "../lib/sync-clients";
import type { ClientApp } from "../lib/clients";

export const BROKER = "http://localhost:4100";

export const BROKER_ENV = {
  NODE_ENV: "test",
  SIGNIN_URL: BROKER,
  BETTER_AUTH_SECRET: "test-secret-test-secret-test-secret-0001",
  SIGNIN_PAIRWISE_SECRET: "test-pairwise-test-pairwise-test-pairwise-1",
  GITHUB_CLIENT_ID: "gh-client",
  GITHUB_CLIENT_SECRET: "gh-secret",
  META_APP_ID: "meta-app",
  META_APP_SECRET: "meta-secret",
};

type Handler = (request: Request) => Promise<Response>;

/** A person at an upstream provider. */
export interface Identity {
  id: string;
  login: string;
  name: string;
  email: string;
}

/**
 * Fake GitHub and Meta: the endpoints better-auth's real provider code calls,
 * answering for whichever identity the "browser" chose on the consent step.
 */
export class FakeUpstreams {
  private codes = new Map<string, Identity>();
  private tokens = new Map<string, Identity>();
  seen: { url: string; body?: string }[] = [];

  /** The person approves at the provider: returns the provider's redirect back. */
  approve(authorizeUrl: string, who: Identity): string {
    const url = new URL(authorizeUrl);
    const code = randomBytes(8).toString("hex");
    this.codes.set(code, who);
    const back = new URL(url.searchParams.get("redirect_uri")!);
    back.searchParams.set("code", code);
    back.searchParams.set("state", url.searchParams.get("state")!);
    return back.toString();
  }

  private exchange(code: string | null): Response {
    const who = code ? this.codes.get(code) : undefined;
    if (!who) return Response.json({ error: "bad_verification_code" });
    this.codes.delete(code!);
    const token = randomBytes(8).toString("hex");
    this.tokens.set(token, who);
    return Response.json({ access_token: token, token_type: "bearer", scope: "" });
  }

  private bearer(request: Request): Identity | undefined {
    const auth = request.headers.get("authorization") ?? "";
    return this.tokens.get(auth.replace(/^Bearer\s+/i, ""));
  }

  handles(url: URL): boolean {
    return ["github.com", "api.github.com", "graph.facebook.com"].includes(url.hostname);
  }

  async handle(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const body = request.method === "POST" ? await request.text() : undefined;
    this.seen.push({ url: url.toString(), body });
    if (url.hostname === "github.com" && url.pathname === "/login/oauth/access_token")
      return this.exchange(new URLSearchParams(body).get("code"));
    if (url.hostname === "api.github.com" && url.pathname === "/user") {
      const who = this.bearer(request);
      if (!who) return new Response("{}", { status: 401 });
      return Response.json({
        id: Number(who.id),
        login: who.login,
        name: who.name,
        email: who.email,
        avatar_url: `https://avatars.example/${who.login}.png`,
      });
    }
    if (url.hostname === "api.github.com" && url.pathname === "/user/emails") {
      const who = this.bearer(request);
      return Response.json(who ? [{ email: who.email, primary: true, verified: true }] : []);
    }
    if (url.hostname === "graph.facebook.com" && url.pathname.endsWith("/oauth/access_token"))
      return this.exchange(url.searchParams.get("code") ?? new URLSearchParams(body).get("code"));
    if (url.hostname === "graph.facebook.com" && url.pathname === "/debug_token") {
      const who = this.tokens.get(url.searchParams.get("input_token") ?? "");
      return Response.json({
        data: who
          ? { is_valid: true, app_id: BROKER_ENV.META_APP_ID, user_id: `fb-${who.id}` }
          : { is_valid: false },
      });
    }
    if (url.hostname === "graph.facebook.com" && url.pathname === "/me") {
      const who = this.bearer(request);
      if (!who) return new Response("{}", { status: 401 });
      return Response.json({
        id: `fb-${who.id}`,
        name: who.name,
        email: who.email,
        email_verified: true,
        picture: { data: { url: "https://pics.example/x.png" } },
      });
    }
    return new Response("not faked", { status: 599 });
  }
}

/** Routes every fetch: the broker, any app servers, and the fake upstreams. */
export class Network {
  private origins = new Map<string, Handler>();
  readonly upstreams = new FakeUpstreams();
  private realFetch = globalThis.fetch;

  serve(origin: string, handler: Handler) {
    this.origins.set(new URL(origin).origin, handler);
  }

  fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const request = input instanceof Request ? new Request(input, init) : new Request(input, init);
    const url = new URL(request.url);
    const handler = this.origins.get(url.origin);
    if (handler) return handler(request);
    if (this.upstreams.handles(url)) return this.upstreams.handle(request);
    throw new Error(`test network: nothing serves ${url.origin}`);
  };

  install() {
    globalThis.fetch = this.fetch as typeof fetch;
  }

  uninstall() {
    globalThis.fetch = this.realFetch;
  }
}

/** A browser: one cookie jar per origin, redirects followed by hand. */
export class Browser {
  private jars = new Map<string, Map<string, string>>();
  /** Each browser is its own visitor to the rate limiter, as Caddy reports it. */
  readonly ip = `198.51.100.${Math.floor(Math.random() * 250) + 1}.${Math.random()}`;
  constructor(private network: Network) {}

  private jar(origin: string) {
    let jar = this.jars.get(origin);
    if (!jar) this.jars.set(origin, (jar = new Map()));
    return jar;
  }

  async request(url: string, init: RequestInit = {}): Promise<Response> {
    const target = new URL(url);
    const headers = new Headers(init.headers);
    const cookies = [...this.jar(target.origin)].map(([k, v]) => `${k}=${v}`).join("; ");
    if (cookies) headers.set("cookie", cookies);
    headers.set("sec-fetch-mode", "navigate");
    headers.set("x-forwarded-for", this.ip);
    headers.set("accept", "text/html");
    const response = await this.network.fetch(url, { ...init, headers, redirect: "manual" });
    for (const line of response.headers.getSetCookie()) {
      const [pair, ...attrs] = line.split(";");
      const eq = pair.indexOf("=");
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      const expired = attrs.some((a) => /max-age=0\b/i.test(a)) || value === "";
      if (expired) this.jar(target.origin).delete(name);
      else this.jar(target.origin).set(name, value);
    }
    return response;
  }

  /** Follows same-network redirects until a page, or a host outside `stopAt`. */
  async follow(url: string, stopAt: (u: URL) => boolean, init?: RequestInit) {
    let response = await this.request(url, init);
    let current = url;
    const visited: string[] = [url];
    for (let i = 0; i < 20; i++) {
      const location = response.headers.get("location");
      if (!(response.status >= 300 && response.status < 400 && location)) break;
      current = new URL(location, current).toString();
      visited.push(current);
      if (stopAt(new URL(current))) return { response, url: current, visited, stopped: true };
      response = await this.request(current);
    }
    return { response, url: current, visited, stopped: false };
  }
}

export async function createDatabase() {
  const client = new PGlite();
  const sql = readFileSync(new URL("../drizzle/0000_init.sql", import.meta.url), "utf8");
  for (const statement of sql.split("--> statement-breakpoint")) {
    if (statement.trim()) await client.exec(statement);
  }
  return { client, db: drizzle(client, { schema }) };
}

export interface Broker {
  auth: SigninAuth;
  handle: Handler;
  secrets: Map<string, string>;
  db: Awaited<ReturnType<typeof createDatabase>>;
}

export async function createBroker(
  network: Network,
  apps: readonly ClientApp[],
  env: Record<string, string | undefined> = BROKER_ENV,
): Promise<Broker> {
  // What loki's app-secrets.sh does on the box: one secret per app, written
  // into both the app's env and this service's.
  const secrets = new Map(apps.map((a) => [a.id, randomBytes(32).toString("base64url")]));
  env = { ...env, ...Object.fromEntries(apps.map((a) => [secretEnvName(a.id), secrets.get(a.id)])) };
  const database = await createDatabase();
  const auth = await createSigninAuth({
    database: drizzleAdapter(database.db, { provider: "pg", schema }),
    env,
  });
  const handle = createSigninHandler(auth, env);
  network.serve(BROKER, handle);
  const synced = await syncClients(auth, apps, env);
  if (synced.active.length !== apps.length) throw new Error("harness: a client did not activate");
  return { auth, handle, secrets, db: database };
}

export function pkce() {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

/**
 * What the sign-in page does: read the signed query it was given, then post
 * it with the chosen provider (app/page.tsx renders exactly this form).
 */
export async function choose(
  browser: Browser,
  loginPageUrl: string,
  provider: string,
) {
  const query = signedOAuthQuery(new URL(loginPageUrl).searchParams);
  if (!query) throw new Error(`not a signed login page: ${loginPageUrl}`);
  const form = new URLSearchParams({ provider, oauth_query: query });
  return browser.request(`${BROKER}/start`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", origin: BROKER },
    body: form.toString(),
  });
}
