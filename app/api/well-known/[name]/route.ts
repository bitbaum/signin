import { handle } from "@/lib/server";

export const dynamic = "force-dynamic";

const DOCUMENTS = new Set(["openid-configuration", "oauth-authorization-server"]);

/** Served at /.well-known/<name> through the rewrite in next.config.ts. */
export async function GET(request: Request, { params }: { params: Promise<{ name: string }> }) {
  const { name } = await params;
  if (!DOCUMENTS.has(name)) return new Response("Not found", { status: 404 });
  const url = new URL(request.url);
  url.pathname = `/.well-known/${name}`;
  return handle(new Request(url, request));
}
