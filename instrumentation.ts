/**
 * At every start, bring the stored OIDC clients in line with the registry
 * (lib/clients.ts) and the per-app secrets in env. Names only in the log.
 */
export async function register() {
  if (process.env.NEXT_RUNTIME !== "nodejs") return;
  if (!process.env.DATABASE_URL?.trim()) return;
  const [{ getAuth }, { syncClients }, { CLIENT_APPS }] = await Promise.all([
    import("./lib/server"),
    import("./lib/sync-clients"),
    import("./lib/clients"),
  ]);
  try {
    const result = await syncClients(await getAuth(), CLIENT_APPS);
    console.info(
      `[signin] clients active: ${result.active.join(", ") || "none"}; waiting for a secret: ${result.waiting.join(", ") || "none"}; retired: ${result.retired.join(", ") || "none"}`,
    );
  } catch (error) {
    console.error(`[signin] client sync failed: ${(error as Error).message}`);
  }
}
