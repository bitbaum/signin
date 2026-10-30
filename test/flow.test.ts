import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createRemoteJWKSet, decodeProtectedHeader, jwtVerify } from "jose";
import { redirectUri, type ClientApp } from "../lib/clients";
import { pairwiseSub, sectorOf } from "../lib/subject";
import { BROKER, BROKER_ENV, Browser, choose, createBroker, Network, pkce, type Broker, type Identity } from "./harness";

const HEIDI: ClientApp = { id: "heidi", name: "Heidi", origin: "http://localhost:4201" };
const SOLON: ClientApp = { id: "solon", name: "Solon", origin: "http://localhost:4202" };

const ADA: Identity = { id: "1001", login: "ada", name: "Ada Lovelace", email: "ada@example.com" };

const network = new Network();
let broker: Broker;
let discovery: Record<string, any>;

beforeAll(async () => {
  network.install();
  broker = await createBroker(network, [HEIDI, SOLON]);
  discovery = await (await fetch(`${BROKER}/.well-known/openid-configuration`)).json();
});
afterAll(() => network.uninstall());

/** One app's whole sign-in, as the app and the browser see it. */
async function signIn(
  app: ClientApp,
  who: Identity,
  options: { browser?: Browser; provider?: string; verifier?: string } = {},
) {
  const browser = options.browser ?? new Browser(network);
  const { verifier, challenge } = pkce();
  const state = crypto.randomUUID();
  const nonce = crypto.randomUUID();
  const authorize = new URL(discovery.authorization_endpoint);
  authorize.search = new URLSearchParams({
    response_type: "code",
    client_id: app.id,
    redirect_uri: redirectUri(app),
    scope: "openid profile email",
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
  }).toString();

  const appHost = new URL(app.origin).host;
  const atUpstreamOrApp = (u: URL) => u.host === appHost || u.hostname === "github.com" || u.hostname.endsWith("facebook.com");
  let hop = await browser.follow(authorize.toString(), atUpstreamOrApp);
  const pages: string[] = [...hop.visited];
  if (!hop.stopped) {
    // A signed-out person lands on the sign-in page and picks a provider.
    expect(new URL(hop.url).pathname).toBe("/");
    const started = await choose(browser, hop.url, options.provider ?? "github");
    expect(started.status).toBe(303);
    const upstream = started.headers.get("location")!;
    pages.push(upstream);
    const back = network.upstreams.approve(upstream, who);
    hop = await browser.follow(back, (u) => u.host === appHost);
    pages.push(...hop.visited);
  }
  expect(hop.stopped).toBe(true);
  const callback = new URL(hop.url);
  expect(callback.origin + callback.pathname).toBe(redirectUri(app));
  expect(callback.searchParams.get("state")).toBe(state);
  const code = callback.searchParams.get("code")!;

  const token = (body: Record<string, string>) =>
    fetch(discovery.token_endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(body).toString(),
    });
  const exchange = {
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri(app),
    client_id: app.id,
    client_secret: broker.secrets.get(app.id)!,
    code_verifier: options.verifier ?? verifier,
  };
  return { browser, pages, code, nonce, exchange, token };
}

async function complete(app: ClientApp, who: Identity, browser?: Browser) {
  const flow = await signIn(app, who, { browser });
  const response = await flow.token(flow.exchange);
  expect(response.status).toBe(200);
  const tokens = await response.json();
  const jwks = createRemoteJWKSet(new URL(discovery.jwks_uri));
  const { payload } = await jwtVerify(tokens.id_token, jwks, {
    issuer: BROKER,
    audience: app.id,
  });
  expect(payload.nonce).toBe(flow.nonce);
  const userinfo = await (
    await fetch(discovery.userinfo_endpoint, {
      headers: { authorization: `Bearer ${tokens.access_token}` },
    })
  ).json();
  return { ...flow, tokens, idToken: payload, userinfo };
}

describe("discovery", () => {
  it("names the origin as issuer and advertises what accountkit's client needs", () => {
    expect(discovery.issuer).toBe(BROKER);
    expect(discovery.subject_types_supported).toContain("pairwise");
    expect(discovery.code_challenge_methods_supported).toEqual(["S256"]);
    expect(discovery.token_endpoint_auth_methods_supported).toContain("client_secret_post");
    expect(discovery.id_token_signing_alg_values_supported).toContain("RS256");
    expect(discovery.scopes_supported).toEqual(expect.arrayContaining(["openid", "profile", "email"]));
    expect(discovery.jwks_uri).toBe(`${BROKER}/api/auth/jwks`);
  });

  it("has no dynamic client registration", () => {
    expect(discovery.registration_endpoint).toBeUndefined();
  });
});

describe("authorization code + PKCE, end to end", () => {
  it("signs a person in through the upstream without a consent screen", async () => {
    const result = await complete(HEIDI, ADA);
    expect(result.pages.some((p) => new URL(p).pathname === "/consent")).toBe(false);
    expect(decodeProtectedHeader(result.tokens.id_token).alg).toBe("RS256");
    expect(result.userinfo.sub).toBe(result.idToken.sub);
  });

  it("refuses an authorize request without PKCE", async () => {
    const browser = new Browser(network);
    const url = new URL(discovery.authorization_endpoint);
    url.search = new URLSearchParams({
      response_type: "code",
      client_id: HEIDI.id,
      redirect_uri: redirectUri(HEIDI),
      scope: "openid",
      state: "s",
    }).toString();
    const response = await browser.request(url.toString());
    const location = new URL(response.headers.get("location")!);
    expect(location.searchParams.get("error")).toBe("invalid_request");
    expect(location.searchParams.get("code")).toBeNull();
  });

  it("refuses a redirect URI that is not the registered one", async () => {
    const browser = new Browser(network);
    const { challenge } = pkce();
    const url = new URL(discovery.authorization_endpoint);
    url.search = new URLSearchParams({
      response_type: "code",
      client_id: HEIDI.id,
      redirect_uri: "https://evil.example/api/auth/callback/bitbaum-signin",
      scope: "openid",
      state: "s",
      code_challenge: challenge,
      code_challenge_method: "S256",
    }).toString();
    const response = await browser.request(url.toString());
    const location = response.headers.get("location") ?? "";
    expect(location.startsWith("https://evil.example")).toBe(false);
  });

  it("refuses the wrong code verifier, and a code used twice", async () => {
    const flow = await signIn(HEIDI, ADA);
    const wrong = await flow.token({ ...flow.exchange, code_verifier: pkce().verifier });
    expect(wrong.status).toBe(400);
    expect((await wrong.json()).access_token).toBeUndefined();

    const again = await signIn(HEIDI, ADA);
    expect((await again.token(again.exchange)).status).toBe(200);
    expect((await again.token(again.exchange)).status).not.toBe(200);
  });

  it("refuses a client secret sent to the wrong client", async () => {
    const flow = await signIn(HEIDI, ADA);
    const response = await flow.token({
      ...flow.exchange,
      client_secret: broker.secrets.get(SOLON.id)!,
    });
    expect(response.ok).toBe(false);
    const body = await response.json();
    expect(body.access_token).toBeUndefined();
  });

  it("does not hand the app the internal user id, the name or any address", async () => {
    const result = await complete(HEIDI, ADA);
    const users = await broker.db.client.query<{ id: string }>(`select id from "user"`);
    const ids = users.rows.map((r) => r.id);
    expect(ids).not.toContain(result.idToken.sub);
    expect(result.idToken.email).toBeUndefined();
    expect(result.userinfo.email).toMatch(/@signin\.invalid$/);
    expect(result.userinfo.email_verified).toBe(false);
    expect(JSON.stringify(result.userinfo)).not.toContain("Ada");
    expect(JSON.stringify(result.userinfo)).not.toContain("ada@example.com");
    // An opaque access token, not a JWT carrying the internal id.
    expect(String(result.tokens.access_token).split(".").length).not.toBe(3);
  });

  it("asks the upstream for nothing but who it is, and keeps none of its tokens", async () => {
    const flow = await signIn(HEIDI, ADA);
    const upstream = new URL(flow.pages.find((p) => p.startsWith("https://github.com/"))!);
    expect(upstream.searchParams.get("scope") ?? "").toBe("");
    const accounts = await broker.db.client.query<Record<string, unknown>>(
      `select access_token, refresh_token, id_token from account`,
    );
    for (const row of accounts.rows) expect(Object.values(row).every((v) => v === null)).toBe(true);
  });
});

describe("pairwise subject", () => {
  it("is stable for one app and different between apps", async () => {
    const browser = new Browser(network);
    const first = await complete(HEIDI, ADA, browser);
    // Same browser: the broker session signs the second app in without the upstream.
    const before = network.upstreams.seen.length;
    const other = await complete(SOLON, ADA, browser);
    expect(network.upstreams.seen.length).toBe(before);
    const again = await complete(HEIDI, ADA, new Browser(network));

    expect(first.idToken.sub).toBe(again.idToken.sub);

    // The subjects the provider issues are exactly lib/subject.ts's root form.
    const owner = await broker.db.client.query<{ user_id: string }>(
      `select user_id from account where provider_id = 'github' and account_id = $1`,
      [ADA.id],
    );
    const userId = owner.rows[0].user_id;
    const secret = BROKER_ENV.SIGNIN_PAIRWISE_SECRET;
    expect(first.idToken.sub).toBe(pairwiseSub({ secret, sector: sectorOf(redirectUri(HEIDI)), userId }));
    expect(other.idToken.sub).toBe(pairwiseSub({ secret, sector: sectorOf(redirectUri(SOLON)), userId }));
    expect(other.userinfo.sub).toBe(other.idToken.sub);
    expect(other.idToken.sub).not.toBe(first.idToken.sub);
    expect(other.userinfo.email).not.toBe(first.userinfo.email);
  });
});

describe("a switched-off client", () => {
  it("cannot start a sign-in", async () => {
    const { adapter } = await broker.auth.$context;
    await adapter.update({ model: "oauthClient", where: [{ field: "clientId", value: SOLON.id }], update: { disabled: true } });
    try {
      const browser = new Browser(network);
      const { challenge } = pkce();
      const url = new URL(discovery.authorization_endpoint);
      url.search = new URLSearchParams({
        response_type: "code",
        client_id: SOLON.id,
        redirect_uri: redirectUri(SOLON),
        scope: "openid",
        state: "s",
        code_challenge: challenge,
        code_challenge_method: "S256",
      }).toString();
      const response = await browser.request(url.toString());
      const location = response.headers.get("location") ?? "";
      expect(location.includes("code=")).toBe(false);
      expect(new URL(location || "http://x/").pathname).not.toBe("/");
    } finally {
      await adapter.update({ model: "oauthClient", where: [{ field: "clientId", value: SOLON.id }], update: { disabled: false } });
    }
  });
});

describe("the sign-in page's post", () => {
  async function loginPage() {
    const browser = new Browser(network);
    const { challenge } = pkce();
    const url = new URL(discovery.authorization_endpoint);
    url.search = new URLSearchParams({
      response_type: "code", client_id: HEIDI.id, redirect_uri: redirectUri(HEIDI),
      scope: "openid", state: "s", code_challenge: challenge, code_challenge_method: "S256",
    }).toString();
    const hop = await browser.follow(url.toString(), () => false);
    return { browser, query: new URL(hop.url).searchParams };
  }
  const post = (browser: Browser, body: URLSearchParams, origin = BROKER) =>
    browser.request(`${BROKER}/start`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", origin },
      body: body.toString(),
    });

  it("is refused from another site", async () => {
    const { browser, query } = await loginPage();
    const { signedOAuthQuery } = await import("../lib/login");
    const response = await post(browser, new URLSearchParams({ provider: "github", oauth_query: signedOAuthQuery(query)! }), "https://evil.example");
    expect(response.headers.get("location")).toBe(`${BROKER}/problem?error=start_failed`);
  });

  it("is refused with a tampered query, and lands on a page with a way back", async () => {
    const { browser, query } = await loginPage();
    const { signedOAuthQuery } = await import("../lib/login");
    const tampered = signedOAuthQuery(query)!.replace("client_id=heidi", "client_id=solon");
    const response = await post(browser, new URLSearchParams({ provider: "github", oauth_query: tampered }));
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe(`${BROKER}/problem?error=start_failed`);
  });

  it("is refused for a provider that is not switched on", async () => {
    const { browser, query } = await loginPage();
    const { signedOAuthQuery } = await import("../lib/login");
    const response = await post(browser, new URLSearchParams({ provider: "google", oauth_query: signedOAuthQuery(query)! }));
    expect(response.headers.get("location")).toBe(`${BROKER}/problem?error=unknown_provider`);
  });
});

describe("rate limits", () => {
  it("slows one visitor starting sign-ins in a loop, not the apps' token calls", async () => {
    const browser = new Browser(network);
    const statuses: number[] = [];
    for (let i = 0; i < 11; i++) {
      const response = await browser.request(`${BROKER}/start`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", origin: BROKER },
        body: "provider=github&oauth_query=x",
      });
      statuses.push(response.status);
    }
    expect(statuses.at(-1)).toBe(429);
    // Every app's server shares the box's address; the token endpoint is not counted per IP.
    for (let i = 0; i < 12; i++) {
      const response = await fetch(discovery.token_endpoint, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", "x-forwarded-for": "203.0.113.9" },
        body: "grant_type=authorization_code&code=nope",
      });
      expect(response.status).not.toBe(429);
    }
  });
});
