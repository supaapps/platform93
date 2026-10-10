import { expect, test } from "@playwright/test";
import { AxeBuilder } from "@axe-core/playwright";

const interaction = "01900000-0000-7000-8000-000000000201";
const endpoint = `/v1/auth/hosted/interactions/${interaction}`;
const initial = {
  interaction_id: interaction, application_id: "01900000-0000-7000-8000-000000000202", csrf_token: "browser-bound-test-csrf",
  client_name: "Example application", stage: "login", consent_required: false, requested_scopes: ["openid", "email", "profile"],
  providers: ["google", "apple", "microsoft", "facebook", "linkedin"], password_enabled: true, passwordless_enabled: true,
  registration_enabled: true, mfa_methods: [], ui_locales: "en", expires_at: "2030-01-01T00:00:00Z",
  branding: { display_name: "Example", accent_color: "#17261f", background_color: "#f6f8fa", layout: "centered", default_locale: "en", copy: { en: { heading: "Welcome back", help: "Secure access to your application." } } },
};

for (const viewport of [{ name: "desktop", width: 1280, height: 900 }, { name: "mobile", width: 390, height: 844 }]) {
  test(`hosted sign-in, feedback and consent on ${viewport.name}`, async ({ page }, info) => {
    await page.setViewportSize(viewport);
    await page.emulateMedia({ reducedMotion: "reduce" });
    let view: object = initial;
    const actions: Record<string, unknown>[] = [];
    await page.route(`**${endpoint}`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify(view) }));
    await page.route(`**${endpoint}/actions`, async (route) => {
      expect(route.request().headers()["x-csrf-token"]).toBe(initial.csrf_token);
      const input = route.request().postDataJSON() as Record<string, unknown>; actions.push(input);
      if (input.action === "password" && input.password === "incorrect") return route.fulfill({ status: 401, contentType: "application/problem+json", body: JSON.stringify({ detail: "The email or password is incorrect." }) });
      if (input.action === "password") view = { ...initial, stage: "consent", consent_required: true, user: { name: "Example User", email: "user@example.test", email_verified: true } };
      if (input.action === "switch_account") view = initial;
      return route.fulfill({ contentType: "application/json", body: JSON.stringify(view) });
    });
    await page.goto(`/auth/?interaction=${interaction}`);
    await expect(page.getByRole("heading", { name: "Welcome back" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Continue with Google" })).toBeVisible();
    const accessibility = await new AxeBuilder({ page }).analyze();
    expect(accessibility.violations.filter((violation) => ["critical", "serious"].includes(violation.impact ?? ""))).toEqual([]);
    await page.screenshot({ path: info.outputPath(`hosted-login-${viewport.name}.png`), fullPage: true });
    await page.getByRole("button", { name: "Password", exact: true }).click();
    await page.getByLabel("Email address").fill("user@example.test");
    await page.getByLabel("Password", { exact: true }).fill("incorrect");
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await expect(page.getByText("The email or password is incorrect.")).toBeVisible();
    await page.getByLabel("Password", { exact: true }).fill("correct-password");
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await expect(page.getByText("Your email and verification status")).toBeVisible();
    await page.screenshot({ path: info.outputPath(`hosted-consent-${viewport.name}.png`), fullPage: true });
    await page.reload();
    await expect(page.getByText("Signed in as")).toBeVisible();
    await page.getByRole("button", { name: "Use another account" }).click();
    await expect(page.getByLabel("Email address")).toBeVisible();
    expect(actions.some((action) => action.action === "switch_account")).toBe(true);
    expect(await page.evaluate(() => localStorage.length)).toBe(0);
  });
}

test("cleans one-time provider return credentials before exchange and supports restart", async ({ page }) => {
  let exchanged: Record<string, unknown> | undefined;
  await page.route(`**${endpoint}`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify(initial) }));
  await page.route(`**${endpoint}/return`, async (route) => {
    expect(page.url()).not.toContain("external_auth_exchange"); exchanged = route.request().postDataJSON();
    await route.fulfill({ status: 401, contentType: "application/problem+json", body: JSON.stringify({ detail: "The provider exchange expired. Start again." }) });
  });
  await page.goto(`/auth/?interaction=${interaction}&external_auth_exchange=one-time-exchange`);
  await expect(page.getByText("The provider exchange expired. Start again.")).toBeVisible();
  expect(exchanged).toEqual({ code: "one-time-exchange" });
  await expect(page.getByRole("button", { name: "Continue with Google" })).toBeEnabled();
});

test("provider-only applications do not show unavailable password or email forms", async ({ page }) => {
  await page.route(`**${endpoint}`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ ...initial, password_enabled: false, passwordless_enabled: false }) }));
  await page.goto(`/auth/?interaction=${interaction}`);
  await expect(page.getByRole("button", { name: "Continue with Google" })).toBeVisible();
  await expect(page.getByLabel("Email address")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Forgot password?" })).toHaveCount(0);
  await page.getByRole("button", { name: "Have an invitation?" }).click();
  await expect(page.getByLabel("Email address")).toBeVisible();
  await expect(page.getByLabel("Code", { exact: true })).toBeVisible();
});

test("password recovery resumes its code and new-password form after reload", async ({ page }) => {
  let view: object = initial;
  await page.route(`**${endpoint}`, (route) => route.fulfill({ json: view }));
  await page.route(`**${endpoint}/actions`, async (route) => {
    const body = route.request().postDataJSON();
    if (body.action === "reset_start") view = { ...initial, stage: "recovery" };
    else { expect(body).toMatchObject({ action: "reset_verify", code: "ABCDEFGH", password: "New disposable password!" }); view = initial; }
    await route.fulfill({ json: view });
  });
  await page.goto(`/auth/?interaction=${interaction}`);
  await page.getByRole("button", { name: "Forgot password?" }).click();
  await page.getByLabel("Email address").fill("user@example.test");
  await page.getByRole("button", { name: "Send recovery code" }).click();
  await expect(page.getByLabel("New password")).toBeVisible();
  await page.reload();
  await expect(page.getByLabel("Email address")).toHaveCount(0);
  await page.getByLabel("Code", { exact: true }).fill("ABCDEFGH");
  await page.getByLabel("New password").fill("New disposable password!");
  await page.getByRole("button", { name: "Set new password" }).click();
  await expect(page.getByText("Password updated. Sign in with your new password.")).toBeVisible();
});
