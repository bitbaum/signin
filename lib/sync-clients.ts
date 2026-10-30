import { hashClientSecret, SCOPES, type SigninAuth } from "./auth";
import { redirectUri, registryProblems, type ClientApp } from "./clients";
import { MIN_SECRET_LENGTH } from "./config";

type Env = Record<string, string | undefined>;

/**
 * Where an app's client secret lives on this side: one env var per app, the
 * same value as that app's own SIGNIN_CLIENT_SECRET. Both are written by the
 * box (loki `app-secrets.sh`), so no person ever reads or pastes one, and
 * nothing prints it. Rotating = changing both and restarting both.
 */
export function secretEnvName(clientId: string): string {
  return `SIGNIN_CLIENT_SECRET_${clientId.toUpperCase().replace(/-/g, "_")}`;
}

export interface SyncResult {
  /** Registered and holding a secret: can sign people in. */
  active: string[];
  /** Registered but no usable secret in env yet: stored, switched off. */
  waiting: string[];
  /** Stored clients the registry no longer lists: switched off, not deleted. */
  retired: string[];
}

/** The stored client a registry row means. Everything but the secret. */
export function clientRow(app: ClientApp) {
  return {
    clientId: app.id,
    name: app.name,
    uri: app.origin,
    redirectUris: [redirectUri(app)],
    scopes: [...SCOPES],
    // First-party: the person already chose this button inside the app.
    skipConsent: true,
    subjectType: "pairwise",
    tokenEndpointAuthMethod: "client_secret_post",
    requirePKCE: true,
    grantTypes: ["authorization_code", "refresh_token"],
    responseTypes: ["code"],
    applicationType: "web",
  };
}

/**
 * Makes the stored clients match the registry (lib/clients.ts) and the env.
 * Runs at every start (instrumentation.ts), so a registry change ships by PR
 * and a secret change by restart. Idempotent. A client's pairwise subjects
 * depend on its redirect host and the person — never on its secret or row —
 * so none of this can change who anybody is to an app.
 *
 * The rows are written directly, in the plugin's own schema: oauth-provider's
 * admin endpoint wants a signed-in operator, and this service has none. The
 * flow tests sign people in through exactly these rows.
 */
export async function syncClients(
  auth: SigninAuth,
  apps: readonly ClientApp[],
  env: Env = process.env,
): Promise<SyncResult> {
  const problems = registryProblems(apps);
  if (problems.length) throw new Error(`client registry: ${problems.join("; ")}`);
  const { adapter } = await auth.$context;
  const result: SyncResult = { active: [], waiting: [], retired: [] };
  const now = new Date();
  for (const app of apps) {
    const secret = env[secretEnvName(app.id)]?.trim() ?? "";
    const usable = secret.length >= MIN_SECRET_LENGTH;
    const row = {
      ...clientRow(app),
      disabled: !usable,
      ...(usable ? { clientSecret: hashClientSecret(secret) } : {}),
      updatedAt: now,
    };
    const where = [{ field: "clientId", value: app.id }];
    const existing = await adapter.findOne({ model: "oauthClient", where });
    if (existing) await adapter.update({ model: "oauthClient", where, update: row });
    else await adapter.create({ model: "oauthClient", data: { ...row, createdAt: now } });
    (usable ? result.active : result.waiting).push(app.id);
  }
  const listed = new Set(apps.map((a) => a.id));
  const stored = await adapter.findMany<{ clientId: string; disabled: boolean | null }>({
    model: "oauthClient",
  });
  for (const stale of stored.filter((c) => !listed.has(c.clientId) && !c.disabled)) {
    await adapter.update({
      model: "oauthClient",
      where: [{ field: "clientId", value: stale.clientId }],
      update: { disabled: true, updatedAt: now },
    });
    result.retired.push(stale.clientId);
  }
  return result;
}
