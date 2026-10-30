import "server-only";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { createSigninAuth, type SigninAuth } from "./auth";
import { getDb, schema } from "./db/client";
import { createSigninHandler } from "./http";

/**
 * One auth instance per process, rebuilt monthly: Apple's client secret is a
 * JWT minted at build time of the instance and Apple caps it at six months.
 */
const REBUILD_AFTER_MS = 30 * 24 * 60 * 60 * 1000;
let current: { built: number; auth: Promise<SigninAuth> } | null = null;

export function getAuth(): Promise<SigninAuth> {
  if (!current || Date.now() - current.built > REBUILD_AFTER_MS) {
    const auth = createSigninAuth({
      database: drizzleAdapter(getDb(), { provider: "pg", schema }),
    });
    current = { built: Date.now(), auth };
    auth.catch(() => {
      current = null;
    });
  }
  return current.auth;
}

export async function handle(request: Request): Promise<Response> {
  return createSigninHandler(await getAuth())(request);
}
