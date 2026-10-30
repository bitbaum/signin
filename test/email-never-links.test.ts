import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { redirectUri, type ClientApp } from "../lib/clients";
import { BROKER, Browser, choose, createBroker, Network, pkce, type Broker, type Identity } from "./harness";

const HEIDI: ClientApp = { id: "heidi", name: "Heidi", origin: "http://localhost:4201" };

/** Two different people at two providers who report the SAME verified address. */
const AT_GITHUB: Identity = { id: "2001", login: "owner", name: "Real Owner", email: "shared@example.com" };
const AT_META: Identity = { id: "3001", login: "x", name: "Someone Else", email: "shared@example.com" };

const network = new Network();
let broker: Broker;

beforeAll(async () => {
  network.install();
  broker = await createBroker(network, [HEIDI]);
});
afterAll(() => network.uninstall());

async function subjectFor(provider: "github" | "facebook", who: Identity): Promise<string> {
  const browser = new Browser(network);
  const discovery = await (await fetch(`${BROKER}/.well-known/openid-configuration`)).json();
  const { verifier, challenge } = pkce();
  const authorize = new URL(discovery.authorization_endpoint);
  authorize.search = new URLSearchParams({
    response_type: "code",
    client_id: HEIDI.id,
    redirect_uri: redirectUri(HEIDI),
    scope: "openid profile email",
    state: "s",
    code_challenge: challenge,
    code_challenge_method: "S256",
  }).toString();
  const login = await browser.follow(authorize.toString(), () => false);
  const started = await choose(browser, login.url, provider);
  const back = network.upstreams.approve(started.headers.get("location")!, who);
  const done = await browser.follow(back, (u) => u.port === "4201");
  const code = new URL(done.url).searchParams.get("code")!;
  const tokens = await (
    await fetch(discovery.token_endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri(HEIDI),
        client_id: HEIDI.id,
        client_secret: broker.secrets.get(HEIDI.id)!,
        code_verifier: verifier,
      }).toString(),
    })
  ).json();
  const payload = JSON.parse(Buffer.from(tokens.id_token.split(".")[1], "base64url").toString());
  return payload.sub;
}

describe("a provider's email is never an identity", () => {
  it("keeps two providers reporting one verified address as two people", async () => {
    const owner = await subjectFor("github", AT_GITHUB);
    const other = await subjectFor("facebook", AT_META);
    expect(other).not.toBe(owner);

    const users = await broker.db.client.query(`select id from "user"`);
    expect(users.rows).toHaveLength(2);
    const accounts = await broker.db.client.query<{ provider_id: string; user_id: string }>(
      `select provider_id, user_id from account order by provider_id`,
    );
    expect(accounts.rows.map((r) => r.provider_id)).toEqual(["facebook", "github"]);
    expect(new Set(accounts.rows.map((r) => r.user_id)).size).toBe(2);
  });

  it("gives the same person the same subject on their next sign-in", async () => {
    expect(await subjectFor("github", AT_GITHUB)).toBe(await subjectFor("github", AT_GITHUB));
  });

  it("stores no address, name or picture from any provider", async () => {
    const dump = JSON.stringify(
      (await broker.db.client.query(`select * from "user"`)).rows.concat(
        (await broker.db.client.query(`select * from account`)).rows,
      ),
    );
    expect(dump).not.toContain("shared@example.com");
    expect(dump).not.toContain("Real Owner");
    expect(dump).not.toContain("Someone Else");
    expect(dump).not.toContain("avatars.example");
    const emails = await broker.db.client.query<{ email: string; email_verified: boolean }>(
      `select email, email_verified from "user"`,
    );
    for (const row of emails.rows) {
      expect(row.email).toMatch(/\.invalid$/);
      expect(row.email_verified).toBe(false);
    }
  });
});
