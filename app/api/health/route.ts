import { sql } from "drizzle-orm";
import { getDb, isDatabaseConfigured } from "@/lib/db/client";
import { enabledUpstreams } from "@/lib/upstreams";
import { CLIENT_APPS } from "@/lib/clients";

export const dynamic = "force-dynamic";

/** Booleans and names only — never a key, a host or a connection string. */
export async function GET() {
  let db: "up" | "down" | "unconfigured" = "unconfigured";
  let clients = 0;
  if (isDatabaseConfigured()) {
    try {
      const rows = await getDb().execute(
        sql`select count(*)::int as n from oauth_client where disabled is not true`,
      );
      clients = Number((rows.rows[0] as { n: number }).n);
      db = "up";
    } catch {
      db = "down";
    }
  }
  const body = {
    ok: db === "up",
    commit: process.env.GIT_COMMIT ?? null,
    db,
    providers: enabledUpstreams(process.env).map((u) => u.id),
    clients,
    registered: CLIENT_APPS.length,
  };
  return Response.json(body, {
    status: body.ok ? 200 : 503,
    headers: { "Cache-Control": "no-store" },
  });
}
