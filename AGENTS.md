# Agents

<!-- fleet:rules:begin — generated from bitbaum/fleet templates/agent-rules.md; edit it there, not here -->
## Org rules

Read `bitbaum/fleet` `AGENTS.md`, `SHARED.md` and the registers it names before
inventing a host, a name, a page or a shared behaviour. Do not copy their facts
into this file.

- **Packages first.** If a `@bitbaum/*` package (or `bip-kit`, `limitkit`,
  `threadkit`, `ai-forms`) already does it, use it and fix a defect in the
  package, not in this app. Every chat is `@bitbaum/chatkit`, every search box
  `@bitbaum/searchkit`, every chart `@bitbaum/chartkit`, accounts
  `@bitbaum/accountkit`, model calls `@bitbaum/ai-kit`. Review this product's
  `package-plan.json` before building anything.
- **One shape per kind.** Things of the same kind look the same and sit in the
  same place (fleet `AGENTS.md`, "One shape per kind").
- **Finished work ships by itself.** Open a non-draft pull request; the fleet
  auto-merge sweep is the only merge path. Never merge by hand, through the
  merge API, with `--auto` or with an admin bypass, and never force-push a
  shared branch.
- **Nothing made up.** A fact on a page or in a doc needs a source that was
  opened; where there is none, the line is removed or softened.
- **Bitcoin orange is for Bitcoin and top-of-funnel actions only.**
- **No model identifier** in anything pushed to a repository.
- Before you finish, run `node <fleet>/scripts/ci/docs-truth-audit.mjs --dir .`:
  the same check the sweep runs on every pull request.
<!-- fleet:rules:end -->

# signin

The shared bitbaum sign-in (fleet `STACK.md`, "Identity"): one OIDC provider
that holds the Google, Apple, GitHub, X and Meta credentials once. Every
accountkit app is a client of it through `SIGNIN_ISSUER`, `SIGNIN_CLIENT_ID`
and `SIGNIN_CLIENT_SECRET`.

## Rules that are this repo's alone

- **A provider's email is never an identity.** No provider is asked for one;
  the stored user is `(provider, subject)` with a `.invalid` placeholder. Do
  not add an `email` scope upstream, and never turn on account linking.
- **The subject is pairwise.** Never hand an app the internal user id, a JWT
  access token carrying it, or any value that is the same across apps.
- **`SIGNIN_PAIRWISE_SECRET` is never rotated.** Rotating it gives every
  person a new identity in every app.
- **No passwords, no mail.** This is a broker, not an account system.

## Working here

    pnpm install
    pnpm run verify        # typecheck, tests, build
    pnpm test              # vitest; Postgres is pglite, providers are faked

- `lib/auth.ts` — better-auth + `@better-auth/oauth-provider` + `jwt` (RS256).
- `lib/upstreams.ts` — the providers, each on only when all of its env is set.
- `lib/subject.ts` — the one pairwise-subject derivation; its pinned test
  must never be edited to pass.
- `lib/clients.ts` — the registry of client apps. Adding an app is one row.
- `lib/sync-clients.ts` — registry + env → stored clients, at every start.
- `lib/http.ts` — every route, framework-free; `app/` only delegates.
- `drizzle/` — migrations, applied on deploy by loki `apply-schema.sh`.
- `test/accountkit-client.test.ts` — accountkit's real runtime signs in here.
