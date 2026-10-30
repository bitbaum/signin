import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PGlite } from "@electric-sql/pglite";
import { drizzle } from "drizzle-orm/pglite";
import { generateDrizzleJson, generateMigration } from "drizzle-kit/api";
import { authSchema } from "@bitbaum/accountkit/auth/schema";
import { createAuthInstance } from "@bitbaum/accountkit/auth/server";
import { signInMethods, SIGNIN_PROVIDER_ID } from "@bitbaum/accountkit/auth";
import type { ClientApp } from "../lib/clients";
import { BROKER, Browser, choose, createBroker, Network, type Broker, type Identity } from "./harness";

/**
 * The real consumer: an app built on accountkit's own runtime
 * (`createAuthInstance`), configured only through SIGNIN_ISSUER /
 * SIGNIN_CLIENT_ID / SIGNIN_CLIENT_SECRET, exactly as a product is on the box.
 * If this passes, every accountkit app can switch the button on with env alone.
 */
const APP: ClientApp = { id: "causius", name: "Causius", origin: "http://localhost:4203" };
const GRACE: Identity = { id: "4001", login: "grace", name: "Grace Hopper", email: "grace@example.com" };

const network = new Network();
let broker: Broker;
let app: ReturnType<typeof createAuthInstance>;
let appDb: PGlite;

beforeAll(async () => {
  network.install();
  broker = await createBroker(network, [APP]);
  appDb = new PGlite();
  const migration = await generateMigration(
    generateDrizzleJson({}),
    generateDrizzleJson(authSchema as Record<string, unknown>),
  );
  for (const statement of migration) await appDb.exec(statement);
  const env = {
    NODE_ENV: "test",
    BETTER_AUTH_SECRET: "app-secret-app-secret-app-secret-app-secret",
    SIGNIN_ISSUER: BROKER,
    SIGNIN_CLIENT_ID: APP.id,
    SIGNIN_CLIENT_SECRET: broker.secrets.get(APP.id)!,
  };
  expect(signInMethods(env, false).signin).toBe(true);
  app = createAuthInstance({
    site: { url: APP.origin, title: APP.name, slug: APP.id },
    database: drizzle(appDb),
    mail: { configured: false, send: async () => {} },
    env: env as NodeJS.ProcessEnv,
  });
  network.serve(APP.origin, (request) => app.handler(request));
});
afterAll(() => network.uninstall());

async function signInThroughApp(who: Identity) {
  const browser = new Browser(network);
  const begin = await browser.request(`${APP.origin}/api/auth/sign-in/social`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: APP.origin },
    body: JSON.stringify({ provider: SIGNIN_PROVIDER_ID, callbackURL: "/welcome" }),
  });
  expect(begin.status).toBe(200);
  const { url } = await begin.json();
  expect(url.startsWith(`${BROKER}/api/auth/oauth2/authorize`)).toBe(true);
  const authorize = new URL(url);
  expect(authorize.searchParams.get("code_challenge_method")).toBe("S256");

  const login = await browser.follow(url, () => false);
  expect(new URL(login.url).pathname).toBe("/");
  const started = await choose(browser, login.url, "github");
  const back = network.upstreams.approve(started.headers.get("location")!, who);
  const done = await browser.follow(back, (u) => u.origin === APP.origin && u.pathname === "/welcome");
  expect(done.stopped).toBe(true);

  const session = await (
    await browser.request(`${APP.origin}/api/auth/get-session`)
  ).json();
  return { browser, session };
}

describe("an accountkit app signs in through the service", () => {
  it("completes with env alone and lands where the app asked", async () => {
    const { session } = await signInThroughApp(GRACE);
    expect(session?.user?.id).toBeTruthy();
    // accountkit's own rule on the app side: never the provider's address.
    expect(session.user.email).toMatch(/@bitbaum-signin\.invalid$/);
    expect(session.user.name).toBe("");
  });

  it("keys the app's account on the pairwise subject, and finds it again", async () => {
    const first = await signInThroughApp(GRACE);
    const second = await signInThroughApp(GRACE);
    expect(second.session.user.id).toBe(first.session.user.id);
    const accounts = await appDb.query<{ account_id: string; provider_id: string }>(
      `select account_id, provider_id from accounts where user_id = $1`,
      [first.session.user.id],
    );
    expect(accounts.rows).toHaveLength(1);
    expect(accounts.rows[0].provider_id).toBe(SIGNIN_PROVIDER_ID);
    const brokerUsers = await broker.db.client.query<{ id: string }>(`select id from "user"`);
    expect(brokerUsers.rows.map((r) => r.id)).not.toContain(accounts.rows[0].account_id);
  });
});
