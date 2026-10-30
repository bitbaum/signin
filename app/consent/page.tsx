/**
 * oauth-provider requires a consent page. Every registered app is first-party
 * and skips it, so a person only lands here if an app is not registered as such.
 */
export default function Consent() {
  return (
    <main>
      <h1>This app is not set up for sign-in yet</h1>
      <p>Go back to the app and use another way in. Nothing was shared.</p>
    </main>
  );
}
