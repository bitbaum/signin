/**
 * What the sign-in page needs from the query oauth-provider sends it.
 *
 * oauth-provider redirects a signed-out person to the login page with the
 * app's authorize request, signed (`sig`, `exp`, and `ba_param` naming every
 * signed parameter). The page posts that signed query back with the chosen
 * provider; after the provider's callback, oauth-provider verifies it and
 * finishes the app's authorize request. This mirrors the package's own
 * browser plugin (`buildSignedOAuthQuery`) so the page needs no JavaScript.
 */
const SIGNED_NAMES = "ba_param";

export type PageSearchParams = Record<string, string | string[] | undefined>;

export function toSearchParams(input: PageSearchParams | URLSearchParams): URLSearchParams {
  if (input instanceof URLSearchParams) return new URLSearchParams(input);
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(input)) {
    if (value === undefined) continue;
    for (const v of Array.isArray(value) ? value : [value]) params.append(key, v);
  }
  return params;
}

/** The signed part of the query, or null when the page was not reached from an authorize request. */
export function signedOAuthQuery(input: PageSearchParams | URLSearchParams): string | null {
  const params = toSearchParams(input);
  if (!params.has("sig")) return null;
  const names = new Set(params.getAll(SIGNED_NAMES));
  if (!names.size) return null;
  const signed = new URLSearchParams();
  for (const [key, value] of params.entries())
    if (key === "sig" || key === SIGNED_NAMES || names.has(key)) signed.append(key, value);
  return signed.toString();
}

/** The app asking, by client id, for "Continue to <app>". */
export function requestingClientId(input: PageSearchParams | URLSearchParams): string | null {
  return toSearchParams(input).get("client_id");
}
