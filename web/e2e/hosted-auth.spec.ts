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

test("email invitations request independent identity proof before acceptance", async ({page}) => {
  let view={...initial,stage:"invitation",providers:[] as string[]};
  const actions:Record<string,unknown>[]=[];
  await page.route(`**${endpoint}`,route=>route.fulfill({json:view}));
  await page.route(`**${endpoint}/actions`,route=>{const body=route.request().postDataJSON();actions.push(body);if(body.action==="invitation")view={...view,stage:"email_code"};return route.fulfill({json:view});});
  await page.goto(`/auth/?interaction=${interaction}`);
  await expect(page.getByRole("button",{name:"Accept invitation",exact:true})).toHaveCount(0);
  await expect(page.getByText(/accepting by email resets its existing password/)).toBeVisible();
  await page.getByRole("button",{name:"Send verification code",exact:true}).click();
  await page.getByLabel("Code",{exact:true}).fill("ABCD2345");
  await page.getByRole("button",{name:"Verify and continue",exact:true}).click();
  expect(actions[0]).toEqual({action:"invitation"});
  expect(actions[1]).toMatchObject({action:"email_verify",code:"ABCD2345"});
});

test("resource consent cannot select unavailable contexts and ordinary approve stays unchanged", async ({ page }) => {
  const view = { ...initial, stage: "consent", user: { name: "User", email: "user@example.test", email_verified: true } };
  let resource = true;
  let submitted: unknown;
  await page.route(`**${endpoint}`, (route) => route.fulfill({ json: { ...view, ...(resource ? { resource_consent: { resource: { id: "resource-1", name: "Resource", uri: "https://resource.example.test" }, capabilities: [{ key: "personal:read", name: "Personal", context: "personal" }, { key: "team:read", name: "Team", context: "workspace" }], personal_access_available: false, workspaces: [] } } : {}) } }));
  await page.route(`**${endpoint}/actions`, (route) => { submitted = route.request().postDataJSON(); return route.fulfill({ json: view }); });
  await page.goto(`/auth/?interaction=${interaction}`);
  await expect(page.getByLabel(/^Personal/)).toBeDisabled();
  await expect(page.getByLabel(/^Team/)).toBeDisabled();
  await expect(page.getByRole("button", { name: "Approve selected access" })).toBeDisabled();
  resource = false;
  await page.reload();
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  expect(submitted).toEqual({ action: "approve" });
});

for (const width of [1280, 390]) {
  test(`resource consent is explicit and reducible (${width}px)`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    const actions: Record<string, unknown>[] = [];
    const view = { ...initial, stage: "consent", user: { name: "Example User", email: "user@example.test", email_verified: true }, resource_consent: {
      resource: { id: "resource-1", name: "Document service", uri: "https://resource.example.test" },
      capabilities: [{ key: "documents:read", name: "Read documents", context: "workspace" }, { key: "profile:read", name: "Read personal profile", context: "personal" }],
      workspaces: [{ id: "workspace-1", key: "first", name: "First workspace" }, { id: "workspace-2", key: "second", name: "Second workspace" }], personal_access_available: true,
    } };
    await page.route(`**${endpoint}`, (route) => route.fulfill({ json: view }));
    await page.route(`**${endpoint}/actions`, (route) => { actions.push(route.request().postDataJSON()); return route.fulfill({ json: view }); });
    await page.goto(`/auth/?interaction=${interaction}`);
    const approve = page.getByRole("button", { name: "Approve selected access" });
    await expect(approve).toBeDisabled();
    await expect(page.getByRole("checkbox", { checked: true })).toHaveCount(0);
    await page.getByLabel(/^Read documents/).check();
    await expect(approve).toBeDisabled();
    await page.getByLabel(/^First workspace/).check();
    await approve.click();
    expect(actions[0]).toEqual({ action: "approve", approved_capabilities: ["documents:read"], personal_access: false, workspace_ids: ["workspace-1"] });
    await page.getByLabel(/^Read documents/).uncheck();
    await page.getByLabel(/^Read personal profile/).check();
    await expect(approve).toBeDisabled();
    await page.getByLabel("Allow personal access").check();
    await approve.click();
    expect(actions[1]).toEqual({ action: "approve", approved_capabilities: ["profile:read"], personal_access: true, workspace_ids: [] });
    await page.reload();
    await expect(approve).toBeDisabled();
    await expect(page.getByRole("checkbox", { checked: true })).toHaveCount(0);
    const accessibility = await new AxeBuilder({ page }).analyze();
    expect(accessibility.violations.filter((item) => ["critical", "serious"].includes(item.impact ?? ""))).toEqual([]);
  });
}

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
      if (input.action === "signup" || input.action === "invitation") view = { ...initial, stage: "consent", consent_required: true, user: { name: "Example User", email: "user@example.test", email_verified: true } };
      if (input.action === "switch_account") view = initial;
      return route.fulfill({ contentType: "application/json", body: JSON.stringify(view) });
    });
    await page.goto(`/auth/?interaction=${interaction}`);
    await expect(page.getByRole("heading", { name: "Welcome back" })).toBeVisible();
    await expect(page.getByText("Secure access to your application.", { exact: true })).toBeVisible();
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
    await expect(page.getByRole("button", { name: "Send sign-in code", exact: true })).toBeVisible();
    for (const mode of ["signup", "invitation"]) {
      await page.getByRole("button", { name: mode === "signup" ? "Create account" : "Have an invitation?", exact: true }).click();
      await page.getByLabel("Email address").fill("user@example.test");
      if (mode === "signup") await page.getByLabel("Password", { exact: true }).fill("correct-password");
      else await page.getByLabel("Code", { exact: true }).fill("ABCDEFGH");
      await page.locator("form").getByRole("button", { name: mode === "signup" ? "Create account" : "Accept invitation", exact: true }).click();
      await page.getByRole("button", { name: "Use another account" }).click();
      await expect(page.getByRole("button", { name: "Send sign-in code", exact: true })).toBeVisible();
      await expect(page.getByLabel("Code", { exact: true })).toHaveCount(0);
    }
    expect(actions.find((action) => action.action === "signup")?.locale).toBe(await page.evaluate(() => navigator.language));
    expect(await page.evaluate(() => localStorage.length)).toBe(0);
  });
}

test("split branding keeps its tagline accessible on an allowed gray background", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.route(`**${endpoint}`, (route) => route.fulfill({ json: { ...initial, branding: { ...initial.branding, layout: "split", background_color: "#909090" } } }));
  await page.goto(`/auth/?interaction=${interaction}`);
  await expect(page.locator(".hosted-brand > span")).toHaveCSS("color", "rgb(17, 24, 39)");
  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(accessibility.violations.filter((violation) => violation.id === "color-contrast")).toEqual([]);
});

test("hosted email signup carries browser locale without putting it into verification credentials", async ({ page }) => {
  const actions: Record<string, unknown>[] = [];
  await page.route(`**${endpoint}`, (route) => route.fulfill({ json: initial }));
  await page.route(`**${endpoint}/actions`, (route) => {
    const input = route.request().postDataJSON();
    actions.push(input);
    return route.fulfill({ json: { ...initial, stage: input.action === "email_start" ? "email_code" : "consent" } });
  });
  await page.goto(`/auth/?interaction=${interaction}`);
  await page.getByLabel("Email address").fill("new@example.test");
  await page.getByRole("button", { name: "Send sign-in code", exact: true }).click();
  expect(actions[0]).toMatchObject({ action: "email_start", email: "new@example.test", locale: await page.evaluate(() => navigator.language) });
  await page.getByLabel("Code", { exact: true }).fill("ABCDEFGH");
  await page.getByRole("button", { name: "Verify and continue", exact: true }).click();
  expect(actions[1]).not.toHaveProperty("locale");
});

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
    else { expect(body).toMatchObject({ action: "reset_verify", code: "ABCDEFGH", password: "New disposable password!" }); view = { ...initial, stage: "consent", user: { name: "Example User", email: "user@example.test", email_verified: true } }; }
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
  await expect(page.getByText("Password updated. Continue to complete sign-in.")).toBeVisible();
  await expect(page.getByText("Signed in as")).toBeVisible();
});

test("email verification resumes its pending code after reload", async ({ page }) => {
  let view = { ...initial, stage: "consent", user: { name: "Example User", email: "user@example.test", email_verified: false }, verification_pending: false };
  await page.route(`**${endpoint}`, (route) => route.fulfill({ json: view }));
  await page.route(`**${endpoint}/actions`, async (route) => {
    const body = route.request().postDataJSON();
    if (body.action === "verify_email_start") view = { ...view, verification_pending: true };
    else {
      expect(body).toMatchObject({ action: "verify_email", code: "ABCDEFGH" });
      view = { ...view, verification_pending: false, user: { ...view.user, email_verified: true } };
    }
    await route.fulfill({ json: view });
  });
  await page.goto(`/auth/?interaction=${interaction}`);
  await page.getByText("Verify your email address", { exact: true }).click();
  await page.getByRole("button", { name: "Send verification code" }).click();
  await page.reload();
  await page.getByLabel("Verification code").fill("ABCDEFGH");
  await page.getByRole("button", { name: "Verify email", exact: true }).click();
  await expect(page.getByText("Email verified.", { exact: true })).toBeVisible();
});
