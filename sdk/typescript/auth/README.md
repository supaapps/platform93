# @supaapps/platform93-auth

Headless browser authentication primitives for Platform93, with in-memory tokens by
default and explicit storage or BFF adapters.

Provider PKCE verifiers are separate from tokens. In browsers they use short-lived,
application-namespaced `sessionStorage` so full-page OAuth redirects can complete;
other runtimes use an injectable in-memory authorization-state store.

## Abandoned Provider And Invitation Flows

A provider start reserves one short-lived PKCE request per application and provider.
Invitation-provider onboarding uses the same slot as ordinary provider login. Going
Back or closing an invitation page does not complete that request. Another start
is rejected until the request is cancelled, completed, or expires (at most ten
minutes). This is sessionStorage state, not a login cookie or refresh token.

Use the public recovery methods; never inspect or delete internal storage keys:

```ts
const pending = auth.pendingExternalAuth("google");
// On an explicit Cancel button or deliberate Back-to-login action:
if (pending) auth.cancelExternalAuth("google", pending.requestId);

// Alternatively, a user-selected "Start again" action cancels and starts anew:
const request = await auth.restartExternalAuth("google", {
  redirectUri: "https://app.example/auth/callback",
  flow: "automatic",
}, pending?.requestId);
window.location.assign(request.authorize_url);
```

`restartApplicationInvitationProvider(provider, invitationCredential, requestId?)`
does the equivalent for a fresh invitation-provider attempt. Local cancellation
does **not** revoke the invitation, cancel an already-issued server challenge, or
log out an existing user. A new attempt gets a new PKCE verifier. Old credentials
remain one-time, server-expiring, and PKCE-bound; never mix an old exchange URL with
a new request. Requests and cancellation remain application-scoped.

Starts return a public `requestId`; `pendingExternalAuth` returns only its ID and
expiry, never the verifier. Pass the request ID when calling cancellation or restart
from delayed handlers. Passing an old ID cannot cancel a newer request. Callback
handlers may pass it as the third argument to `completeExternalAuthRedirect` to
reject stale callbacks before provider I/O. Without an ID, that method intentionally
targets the currently pending request; applications must not replay old callback URLs.

Do **not** cancel on every component unmount, page reload, or OAuth page departure:
the callback still needs the verifier. Cancel only when the user explicitly abandons
the flow. On return from Back navigation, show Continue/Cancel/Start again based on
`pendingExternalAuth`, rather than automatically starting another request. Remove
callback credentials from the address bar after reading them and keep retry data
only in memory. Never put one-time credentials into logs or persistent storage.

## Exchange Failures And Retry

Provider exchange failures throw `ExternalAuthRecoveryError`, with `cause` preserving
the underlying error and a `recovery` value:

- `retry`: network failure, timeout, HTTP 408/429, or server 5xx. The verifier is
  retained. Retry the **same exchange** within its validity window; honour any
  application backoff/cooldown rather than starting another provider request.
- `restart`: terminal HTTP rejection, malformed callback, provider error, or a
  failure saving the session after a successful exchange. Its verifier is cleared.
  Show the error and offer a fresh sign-in, not an exchange replay.
- `cancelled`: the request expired, was cancelled, or was replaced while work was
  pending. Ignore its result; do not disturb or restart the newer request.

An interrupted network response may hide a successful server-side exchange. A retry
can then return a terminal rejection because the credential was consumed. Restart
sign-in in that case; the SDK never makes credentials reusable or bypasses PKCE.
If invitation exchange rejects an expired/revoked/consumed invitation, request a new
invitation or use ordinary sign-in for an account already created. Local cancellation
cannot reset invitation acceptance on the server.

Untrusted-provider email continuations have their own PKCE state. Use
`cancelExternalEmailEnrollment(continuation)` when explicitly abandoning them.
Email-code mistakes may be corrected and retried while the challenge remains valid;
do not discard the continuation for a mistyped code. The native Expo adapter clears
its provider request on browser cancellation or dismissal automatically.

```bash
npm install @supaapps/platform93-auth
```

See the [Platform93 repository](https://github.com/supaapps/platform93) for complete
authentication flows.
