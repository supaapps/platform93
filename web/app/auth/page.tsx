"use client";

import { useEffect, useRef, useState, type CSSProperties, type FormEvent } from "react";
import { ProviderIcon } from "../provider-icon";
import "./hosted.css";

type Branding = {
  display_name: string; logo_url?: string; favicon_url?: string;
  accent_color: string; background_color: string; layout: "centered" | "split";
  privacy_url?: string; terms_url?: string; support_url?: string; default_locale: string;
  copy: Record<string, { heading?: string; help?: string }>;
};
type View = {
  interaction_id: string; csrf_token: string; client_name: string; branding: Branding;
  stage: "login" | "email_code" | "mfa" | "external_email" | "consent" | "invitation" | "recovery";
  user?: { name: string; email: string; email_verified: boolean }; consent_required: boolean; mfa_methods: string[];
  requested_scopes: string[]; providers: string[]; password_enabled: boolean;
  passwordless_enabled: boolean; registration_enabled: boolean; ui_locales: string;
  verification_pending?: boolean;
};
type Result = View | { redirect_url: string };
type PasskeyOptions = { options: { publicKey: Omit<PublicKeyCredentialRequestOptions, "challenge" | "allowCredentials"> & { challenge: string; allowCredentials?: { id: string; type: "public-key"; transports?: AuthenticatorTransport[] }[] } } };
type Method = "email" | "password" | "signup" | "recovery" | "invite";

function localizedCopy(b: Branding, requested: string) {
  const locales = [...requested.split(/\s+/), ...navigator.languages, b.default_locale, "en"].filter(Boolean);
  for (const locale of locales) {
    const key = Object.keys(b.copy).find((key) => key.toLowerCase() === locale.toLowerCase()) ?? Object.keys(b.copy).find((key) => key.toLowerCase() === (locale.split("-")[0] ?? locale).toLowerCase());
    if (key) return { ...b.copy[key], locale: key };
  }
  return { heading: "Sign in", help: "Secure access to your application.", locale: "en" };
}

export default function HostedAuthentication() {
  const [view, setView] = useState<View | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [method, setMethod] = useState<Method>("email");
  const recoverySent = view?.stage === "recovery";
  const verificationSent = view?.verification_pending === true;
  const initial = useRef(false);
  const base = useRef("");

  async function request<T>(suffix: string, body?: object, csrf?: string): Promise<T> {
    const response = await fetch(base.current + suffix, {
      method: body ? "POST" : "GET", credentials: "same-origin", cache: "no-store",
      headers: body ? { "Content-Type": "application/json", "X-CSRF-Token": csrf ?? "" } : {},
      body: body ? JSON.stringify(body) : undefined,
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.detail ?? result.message ?? "Sign-in could not be completed. Please try again.");
    return result as T;
  }

  useEffect(() => {
    if (initial.current) return;
    initial.current = true;
    const parameters = new URLSearchParams(window.location.search);
    const id = parameters.get("interaction");
    if (!id || !/^[0-9a-f-]{36}$/.test(id)) { queueMicrotask(() => setError("Start sign-in from your application to open a valid sign-in request.")); return; }
    base.current = `/v1/auth/hosted/interactions/${id}`;
    window.history.replaceState(null, "", `/auth/?interaction=${id}`);
    void (async () => {
      try {
        let state = await request<View>("");
        if (parameters.get("external_auth_error")) throw new Error("The provider did not complete sign-in. Choose a sign-in method to try again.");
        const provider = parameters.get("external_auth_provider");
        const challenge = parameters.get("challenge_id");
        if (challenge || provider || parameters.get("external_auth_exchange")) {
          state = await request<View>("/return", {
            ...(challenge ? { challenge_id: challenge, link_token: parameters.get("link_token") } : {
              provider: provider ?? undefined, code: parameters.get("external_auth_exchange") ?? undefined,
              enrollment: parameters.get("external_auth_email_enrollment") ?? undefined,
            }),
          }, state.csrf_token);
        }
        setView(state); setMethod(state.passwordless_enabled ? "email" : "password");
      } catch (failure) { setError(failure instanceof Error ? failure.message : "Unable to load sign-in."); const state = await request<View>("").catch(() => null); setView(state); }
    })();
  }, []);

  useEffect(() => {
    if (!view) return;
    document.title = `${view.branding.display_name} - Sign in`;
    if (view.branding.favicon_url) {
      const icon = document.createElement("link"); icon.rel = "icon"; icon.href = view.branding.favicon_url; document.head.append(icon);
      return () => icon.remove();
    }
  }, [view]);

  async function action(body: object) {
    if (!view || busy) return;
    setBusy(true); setError(""); setNotice("");
    try {
      const result = await request<Result>("/actions", body, view.csrf_token);
      if ("redirect_url" in result) window.location.assign(result.redirect_url);
      else {
        setView(result);
        if (result.stage === "login") setMethod(result.passwordless_enabled ? "email" : "password");
      }
      return result;
    } catch (failure) { setError(failure instanceof Error ? failure.message : "The request failed."); }
    finally { setBusy(false); }
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const form = event.currentTarget; const fields = Object.fromEntries(new FormData(form));
    const stage = view?.stage;
    const operation = stage === "recovery" ? "reset_verify" : stage === "mfa" ? "mfa" : stage === "email_code" ? "email_verify" : stage === "external_email" ? (fields.code ? "external_email_verify" : "external_email_start") : method === "email" ? "email_start" : method === "recovery" ? "reset_start" : method === "invite" ? "invitation" : method === "signup" ? "signup" : "password";
    const result = await action({ ...fields, action: operation });
    if (result && !('redirect_url' in result)) {
      form.reset();
      if (operation === "reset_start") setNotice("If the account is available, a recovery code has been sent.");
      if (operation === "reset_verify") { setMethod("password"); setNotice("Password updated. Continue to complete sign-in."); }
      if (operation === "external_email_start") setNotice("Enter the code sent to your email address.");
    }
  }

  async function passkey() {
    if (!view || busy) return;
    setBusy(true); setError("");
    const decode = (value: string) => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)).buffer;
    const encode = (value: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    try {
      const result = await request<PasskeyOptions>("/actions", { action: "webauthn_options" }, view.csrf_token);
      const json = result.options.publicKey;
      const credential = await navigator.credentials.get({ publicKey: { ...json, challenge: decode(json.challenge), allowCredentials: json.allowCredentials?.map((item) => ({ ...item, id: decode(item.id) })) } }) as PublicKeyCredential | null;
      if (!credential) throw new Error("Passkey sign-in was cancelled. Try again or use another method.");
      const response = credential.response as AuthenticatorAssertionResponse;
      const state = await request<View>("/actions", { action: "webauthn_verify", credential: { id: credential.id, rawId: encode(credential.rawId), type: credential.type, authenticatorAttachment: credential.authenticatorAttachment, clientExtensionResults: credential.getClientExtensionResults(), response: { clientDataJSON: encode(response.clientDataJSON), authenticatorData: encode(response.authenticatorData), signature: encode(response.signature), userHandle: response.userHandle ? encode(response.userHandle) : null } } }, view.csrf_token);
      setView(state);
    } catch (failure) { setError(failure instanceof Error ? failure.message : "Passkey sign-in failed."); }
    finally { setBusy(false); }
  }

  if (!view) return <main className="hosted-auth"><section className="hosted-card"><p className="hosted-eyebrow">SECURE SIGN-IN</p><h1>{error ? "Sign-in unavailable" : "Preparing sign-in"}</h1><p role={error ? "alert" : "status"}>{error || "Checking your application request..."}</p></section></main>;
  const b = view.branding; const copy = localizedCopy(b, view.ui_locales);
  const style = { "--hosted-accent": b.accent_color, "--hosted-background": b.background_color } as CSSProperties;
  const loginStage = view.stage === "login";
  const hasCredentialMethod = view.passwordless_enabled || view.password_enabled || method === "invite";
  const title = view.stage === "consent" ? "Continue to your application" : view.stage === "mfa" ? "Verify it is you" : view.stage === "email_code" ? "Check your email" : view.stage === "external_email" ? "Verify your email" : copy.heading || "Sign in";

  return <main className={`hosted-auth hosted-${b.layout}`} style={style} lang={copy.locale}>
    <aside className="hosted-brand"><div className="hosted-brand-name">{b.logo_url && <img src={b.logo_url} alt="" referrerPolicy="no-referrer" onError={(event) => { event.currentTarget.hidden = true; }} />}{b.display_name}</div><p>{copy.help}</p><span>Secure identity. Your application.</span></aside>
    <section className="hosted-card" aria-busy={busy}>
      <header><p className="hosted-eyebrow">{view.client_name}</p><h1>{title}</h1><p>{view.stage === "email_code" ? "Enter your eight-character code or open the sign-in link in this browser." : view.stage === "mfa" ? "Use your authenticator or a recovery code to complete sign-in." : loginStage ? "Choose how you want to continue." : ""}</p></header>
      {error && <div className="hosted-feedback hosted-error" role="alert">{error}</div>}
      {notice && <div className="hosted-feedback" role="status">{notice}</div>}
      {view.stage === "consent" ? <div className="hosted-consent">
        <p>Signed in as <strong>{view.user?.name || view.user?.email}</strong><small>{view.user?.email}</small></p>
        {view.user && !view.user.email_verified && <details open={verificationSent}><summary>Verify your email address</summary>{verificationSent ? <form onSubmit={(event) => { event.preventDefault(); const code = new FormData(event.currentTarget).get("code"); void action({ action: "verify_email", code }).then((result) => { if (result) setNotice("Email verified."); }); }}><label>Verification code<input required name="code" maxLength={8} autoComplete="one-time-code" /></label><button disabled={busy}>Verify email</button></form> : <button disabled={busy} onClick={() => void action({ action: "verify_email_start" }).then((result) => { if (result) setNotice("A verification code has been sent."); })}>Send verification code</button>}</details>}
        {view.consent_required && <><p>This application requests:</p><ul>{view.requested_scopes.map((scope) => <li key={scope}>{({ openid: "Your account identifier", email: "Your email and verification status", profile: "Your name and profile", offline_access: "Access while you are away" } as Record<string, string>)[scope] || scope}</li>)}</ul></>}
        {view.requested_scopes.includes("email") && !view.user?.email_verified && <p>Verify your email before sharing it with this application.</p>}
        <button className="hosted-primary" disabled={busy || view.requested_scopes.includes("email") && !view.user?.email_verified} onClick={() => void action({ action: "approve" })}>{busy ? "Continuing..." : "Continue"}</button>
        <div className="hosted-links"><button disabled={busy} onClick={() => void action({ action: "switch_account" })}>Use another account</button><button disabled={busy} onClick={() => void action({ action: "deny" })}>Cancel</button></div>
      </div> : view.stage === "invitation" ? <div><p>Accept your invitation to continue to this application.</p>{view.providers.length ? view.providers.map((provider) => <button className="hosted-primary" disabled={busy} key={provider} onClick={() => void action({ action: "provider", provider })}><ProviderIcon provider={provider} /> Accept with {provider}</button>) : <button className="hosted-primary" disabled={busy} onClick={() => void action({ action: "invitation" })}>{busy ? "Accepting..." : "Accept invitation"}</button>}<button className="hosted-cancel" disabled={busy} onClick={() => void action({ action: "deny" })}>Cancel</button></div> : <>
        {loginStage && view.providers.length > 0 && <div className="hosted-providers">{view.providers.map((provider) => <button key={provider} disabled={busy} onClick={() => void action({ action: "provider", provider })}><ProviderIcon provider={provider} /><span>Continue with {provider.charAt(0).toUpperCase() + provider.slice(1)}</span></button>)}</div>}
        {loginStage && view.providers.length > 0 && hasCredentialMethod && <div className="hosted-divider"><span>or</span></div>}
        {loginStage && <div className="hosted-methods" role="group" aria-label="Sign-in method">{view.passwordless_enabled && <button aria-pressed={method === "email"} disabled={busy} onClick={() => setMethod("email")}>Email code</button>}{view.password_enabled && <button aria-pressed={method === "password"} disabled={busy} onClick={() => setMethod("password")}>Password</button>}</div>}
        {(!loginStage || hasCredentialMethod) && <form key={`${view.stage}-${method}-${recoverySent}`} onSubmit={(event) => void submit(event)}>
          {loginStage && !recoverySent && <label>Email address<input name="email" type="email" autoComplete="email" required /></label>}
          {(recoverySent || loginStage && (method === "password" || method === "signup")) && <label>{recoverySent ? "New password" : "Password"}<input name="password" type="password" autoComplete={recoverySent || method === "signup" ? "new-password" : "current-password"} required minLength={recoverySent || method === "signup" ? 12 : undefined} /></label>}
          {loginStage && method === "signup" && <div className="hosted-name"><label>First name<input name="first_name" autoComplete="given-name" /></label><label>Last name<input name="last_name" autoComplete="family-name" /></label></div>}
          {(recoverySent || view.stage === "email_code" || view.stage === "mfa" || loginStage && method === "invite") && <label>{view.stage === "mfa" ? "Authenticator code" : "Code"}<input name="code" autoComplete="one-time-code" required={view.stage !== "mfa"} maxLength={view.stage === "mfa" ? 6 : 8} /></label>}
          {view.stage === "mfa" && <label>Or recovery code<input name="recovery_code" autoComplete="off" /></label>}
          {view.stage === "mfa" && view.mfa_methods.includes("webauthn") && <button type="button" disabled={busy} onClick={() => void passkey()}>Use a passkey</button>}
          {view.stage === "external_email" && <><label>Email address<input name="email" type="email" autoComplete="email" /></label><label>Verification code<input name="code" autoComplete="one-time-code" maxLength={8} /></label></>}
          <button className="hosted-primary" disabled={busy}>{busy ? "Working..." : recoverySent ? "Set new password" : view.stage === "email_code" || view.stage === "mfa" ? "Verify and continue" : method === "recovery" ? "Send recovery code" : method === "invite" ? "Accept invitation" : method === "signup" ? "Create account" : method === "email" ? "Send sign-in code" : "Continue"}</button>
        </form>}
        {!loginStage && <button className="hosted-cancel" disabled={busy} onClick={() => void action({ action: "restart" })}>Start over</button>}
        {loginStage && <div className="hosted-links">{view.registration_enabled && view.password_enabled && <button disabled={busy} onClick={() => setMethod(method === "signup" ? "password" : "signup")}>{method === "signup" ? "Already have an account?" : "Create account"}</button>}<button disabled={busy} onClick={() => setMethod("invite")}>Have an invitation?</button>{view.password_enabled && <button disabled={busy} onClick={() => setMethod("recovery")}>Forgot password?</button>}</div>}
        <button className="hosted-cancel" disabled={busy} onClick={() => void action({ action: "deny" })}>Cancel sign-in</button>
      </>}
      <footer>{b.privacy_url && <a href={b.privacy_url} target="_blank" rel="noopener noreferrer">Privacy</a>}{b.terms_url && <a href={b.terms_url} target="_blank" rel="noopener noreferrer">Terms</a>}{b.support_url && <a href={b.support_url} target="_blank" rel="noopener noreferrer">Help</a>}</footer>
    </section>
  </main>;
}
