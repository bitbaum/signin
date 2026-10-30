import type { PageSearchParams } from "@/lib/login";

export const dynamic = "force-dynamic";

const WORDS: Record<string, string> = {
  unknown_provider: "That provider is not available here.",
  start_failed: "Sign-in could not start from here.",
  access_denied: "The provider did not confirm who you are.",
};

/** Never prints the provider's own code; always offers the way back. */
export default async function Problem({ searchParams }: { searchParams: Promise<PageSearchParams> }) {
  const error = String((await searchParams).error ?? "");
  return (
    <main>
      <h1>Sign-in did not finish</h1>
      <p>{WORDS[error] ?? "Something went wrong between the provider and this page."}</p>
      <p>Go back to the app you came from and choose the button again. Nothing was shared.</p>
    </main>
  );
}
