import { authBucket, authLimits } from "@bitbaum/accountkit/auth";
import { clientIp, toHeaders } from "limitkit";
import type { SigninAuth } from "./auth";
import { upstreamById } from "./upstreams";

type Env = Record<string, string | undefined>;

/**
 * Every HTTP path the service answers, framework-free: Next's route handlers
 * delegate here, and the tests drive it with plain Requests.
 *
 *   /.well-known/openid-configuration      discovery (issuer = SIGNIN_URL)
 *   /.well-known/oauth-authorization-server the same, RFC 8414
 *   /start                                 POST from the sign-in page: begin a provider
 *   /api/auth/oauth2/authorize | token | userinfo | end-session
 *   /api/auth/jwks                         the id_token signing keys
 *   /api/auth/callback/<provider>          where each provider sends people back
 */

/** App servers call these with client credentials; they share the box's one IP. */
const SERVER_TO_SERVER = new Set(["/oauth2/token", "/oauth2/userinfo", "/jwks", "/oauth2/introspect", "/oauth2/revoke"]);

function tooMany(retryAfterSeconds: number, headers: HeadersInit): Response {
  return Response.json(
    { error: "rate_limited", retryAfterSeconds },
    { status: 429, headers: { ...headers, "Cache-Control": "no-store" } },
  );
}

function limited(request: Request, bucket: "credential" | "auth"): Response | null {
  const key = `${bucket}:${clientIp(request.headers, { trustedProxies: 1 })}`;
  const result = authLimits[bucket].check(key);
  return result.allowed
    ? null
    : tooMany(result.retryAfterSeconds, toHeaders(result) as HeadersInit);
}

async function metadata(body: unknown): Promise<Response> {
  if (body instanceof Response) return body;
  return Response.json(body, {
    headers: { "Cache-Control": "public, max-age=300" },
  });
}

/**
 * The sign-in page posts here: provider + the signed authorize query. The
 * signed query is what lets the provider's callback resume the app's
 * authorize request (oauth-provider verifies its signature).
 */
async function start(
  auth: SigninAuth,
  env: Env,
  origin: string,
  request: Request,
): Promise<Response> {
  // Behind Caddy the request's own URL is the internal one; every redirect
  // is built from the public origin.
  const problem = (error: string) =>
    Response.redirect(`${origin}/problem?error=${encodeURIComponent(error)}`, 303);
  // Only this service's own page may start a sign-in.
  const from = request.headers.get("origin");
  const site = request.headers.get("sec-fetch-site");
  if (from !== origin || (site && site !== "same-origin")) return problem("start_failed");
  const form = await request.formData().catch(() => null);
  const provider = String(form?.get("provider") ?? "");
  const oauthQuery = String(form?.get("oauth_query") ?? "");
  if (!upstreamById(provider, env) || !oauthQuery) return problem("unknown_provider");
  // `oauth_query` is read by oauth-provider's hook on this endpoint (it checks
  // the signature); the core body type does not name it.
  const body = { provider, callbackURL: "/", errorCallbackURL: "/problem", oauth_query: oauthQuery };
  let response: Response;
  try {
    response = await auth.api.signInSocial({
      body: body as { provider: string; callbackURL: string; errorCallbackURL: string },
      headers: request.headers,
      asResponse: true,
    });
  } catch {
    return problem("start_failed");
  }
  const answer = (await response.json().catch(() => null)) as { url?: string } | null;
  if (!response.ok || !answer?.url) return problem("start_failed");
  const headers = new Headers({ Location: answer.url, "Cache-Control": "no-store" });
  for (const cookie of response.headers.getSetCookie()) headers.append("Set-Cookie", cookie);
  return new Response(null, { status: 303, headers });
}

export function createSigninHandler(auth: SigninAuth, env: Env = process.env) {
  const origin = new URL(String(auth.options.baseURL)).origin;
  return async function handle(request: Request): Promise<Response> {
    const { pathname } = new URL(request.url);
    if (pathname === "/.well-known/openid-configuration")
      return metadata(await auth.api.getOpenIdConfig({ headers: request.headers }));
    if (pathname === "/.well-known/oauth-authorization-server")
      return metadata(await auth.api.getOAuthServerConfig({ headers: request.headers }));
    if (pathname === "/start" && request.method === "POST")
      return limited(request, "credential") ?? start(auth, env, origin, request);
    if (pathname.startsWith("/api/auth/")) {
      const path = pathname.slice("/api/auth".length);
      if (!SERVER_TO_SERVER.has(path)) {
        const bucket = authBucket(path) === "credential" ? "credential" : "auth";
        const refused = limited(request, bucket);
        if (refused) return refused;
      }
      return auth.handler(request);
    }
    return new Response("Not found", { status: 404 });
  };
}
