import { clientApp } from "@/lib/clients";
import { requestingClientId, signedOAuthQuery, type PageSearchParams } from "@/lib/login";
import { enabledUpstreams } from "@/lib/upstreams";

export const dynamic = "force-dynamic";

/**
 * The sign-in page. oauth-provider sends a signed-out person here with the
 * app's authorize request, signed. Each button posts that signed query to
 * /start with one provider; no JavaScript is needed.
 */
export default async function SignIn({ searchParams }: { searchParams: Promise<PageSearchParams> }) {
  const params = await searchParams;
  const query = signedOAuthQuery(params);
  const app = clientApp(requestingClientId(params));
  const upstreams = enabledUpstreams(process.env);

  if (!query || !app) {
    return (
      <main>
        <h1>bitbaum sign-in</h1>
        <p>
          This page signs you in to a bitbaum app. Start from the app: choose
          “Continue with Google, Apple, GitHub, X or Facebook” on its sign-in page.
        </p>
      </main>
    );
  }

  return (
    <main>
      <h1>Continue to {app.name}</h1>
      <p>{app.name} gets an identifier that only it can see. Not your name, not your address.</p>
      {upstreams.length === 0 ? (
        <p>No provider is switched on yet. Go back to {app.name} and use another way in.</p>
      ) : (
        <div className="providers">
          {upstreams.map((u) => (
            <form key={u.id} method="post" action="/start">
              <input type="hidden" name="provider" value={u.id} />
              <input type="hidden" name="oauth_query" value={query} />
              <button type="submit" className="acct-auth-button-quiet">
                Continue with {u.label}
              </button>
            </form>
          ))}
        </div>
      )}
      <p className="small">
        <a href={app.origin}>Back to {app.name}</a>
      </p>
    </main>
  );
}
