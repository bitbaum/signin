import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";
import * as schema from "./schema";

let db: ReturnType<typeof drizzle<typeof schema>> | null = null;

export function isDatabaseConfigured(env = process.env): boolean {
  return Boolean(env.DATABASE_URL?.trim());
}

export function getDb() {
  if (db) return db;
  const url = process.env.DATABASE_URL?.trim();
  if (!url) throw new Error("DATABASE_URL is not set");
  db = drizzle(new Pool({ connectionString: url, max: 5 }), { schema });
  return db;
}

export { schema };
