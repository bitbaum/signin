// Browser smoke against a running production build (see browser-smoke.yml).
//
// It proves what unit tests cannot: the built server starts with production
// config, reaches its database, publishes discovery for the issuer it was
// given, and a real authorize request from a registered app lands a person on
// that app's sign-in page, readable at phone width.
//
//   node scripts/smoke.mjs --base http://localhost:3000
import { createHash, randomBytes } from "node:crypto";
import { SIGNIN_PROVIDER_ID } from "@bitbaum/accountkit/auth";
import { chromium } from "playwright-core";

const arg = (name) => {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 ? process.argv[i + 1] : undefined;
};
const base = (arg("base") ?? "http://localhost:3000").replace(/\/$/, "");
const issuer = process.env.SIGNIN_URL ?? base;
// The app whose secret the workflow writes; its row in lib/clients.ts.
const app = { id: "solon", name: "Solon", origin: "https://solon.orangecat.ch" };

const failures = [];
const check = (ok, what) => {
  console.log(`${ok ? "ok  " : "FAIL"} ${what}`);
  if (!ok) failures.push(what);
};

const health = await fetch(`${base}/api/health`);
const h = await health.json();
check(health.status === 200 && h.db === "up", `health 200 with db up (got ${health.status}, db ${h.db})`);
check(h.clients >= 1, `at least one active client (got ${h.clients})`);

const discovery = await (await fetch(`${base}/.well-known/openid-configuration`)).json();
check(discovery.issuer === issuer, `discovery issuer is ${issuer} (got ${discovery.issuer})`);
check(
  Array.isArray(discovery.code_challenge_methods_supported) &&
    discovery.code_challenge_methods_supported.includes("S256"),
  "discovery offers PKCE S256",
);

const verifier = randomBytes(32).toString("base64url");
const authorize = new URL(discovery.authorization_endpoint ?? `${base}/api/auth/oauth2/authorize`);
// Discovery names the public issuer; the request goes to the server under test.
const target = new URL(authorize.pathname, base);
for (const [k, v] of Object.entries({
  response_type: "code",
  client_id: app.id,
  redirect_uri: `${app.origin}/api/auth/callback/${SIGNIN_PROVIDER_ID}`,
  scope: "openid",
  state: randomBytes(8).toString("hex"),
  code_challenge: createHash("sha256").update(verifier).digest("base64url"),
  code_challenge_method: "S256",
})) target.searchParams.set(k, v);

const browser = await chromium.launch();
try {
  const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));

  const res = await page.goto(target.toString(), { waitUntil: "networkidle" });
  check(res !== null && res.status() < 400, `authorize lands on a page (status ${res?.status()})`);
  const heading = (await page.locator("h1").first().textContent())?.trim();
  check(heading === `Continue to ${app.name}`, `heading names the app (got "${heading}")`);
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  check(overflow <= 0, `no sideways scroll at 390px (overflow ${overflow}px)`);
  check(errors.length === 0, `no console errors${errors.length ? `: ${errors.join(" | ")}` : ""}`);
  await page.screenshot({ path: "smoke-artifacts/sign-in-390.png", fullPage: true }).catch(() => {});
} finally {
  await browser.close();
}

if (failures.length) {
  console.error(`\n${failures.length} check(s) failed`);
  process.exit(1);
}
console.log("\nsmoke passed");
