import { expect, test } from "@playwright/test";
import { AxeBuilder } from "@axe-core/playwright";

async function expectNoSeriousAccessibilityViolations(page: import("@playwright/test").Page) {
  const result = await new AxeBuilder({ page }).analyze();
  expect(result.violations.filter((violation) => violation.impact === "critical" || violation.impact === "serious")).toEqual([]);
}

test("consumes a Platform user magic link and removes it from the URL", async ({ page }) => {
  let verification: Record<string, unknown> | undefined;
  await page.route("**/v1/setup/status", (route) => route.fulfill({
    contentType: "application/json",
    body: JSON.stringify({ available: false, control_user_email_login_available: true, control_auth_methods: { email_code: true, magic_link: true, password: true, providers: [] } }),
  }));
  await page.route("**/v1/control/auth/email/verify", async (route) => {
    verification = route.request().postDataJSON() as Record<string, unknown>;
    await route.fulfill({ contentType: "application/json", body: "{}" });
  });
  await page.route("**/v1/control/organizations?*", (route) => route.fulfill({
    contentType: "application/json",
    body: JSON.stringify({ items: [], next_cursor: null }),
  }));

  await page.goto("/?challenge_id=01900000-0000-7000-8000-000000000001&link_token=p93_control_link_test&control_user_challenge=true");

  await expect.poll(() => verification).toEqual({
    challenge_id: "01900000-0000-7000-8000-000000000001",
    link_token: "p93_control_link_test",
  });
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByText("Create the first boundary")).toBeVisible();
});

test("creates and renames organization and application boundaries", async ({ page }) => {
  const organizationID = "01900000-0000-7000-8000-000000000101";
  const applicationID = "01900000-0000-7000-8000-000000000102";
  const createdOrganizationID = "01900000-0000-7000-8000-000000000103";
  let organization = { id: organizationID, name: "Test Organization", slug: "test-organization", role: "owner", version: 1 };
  let application = { id: applicationID, organization_id: organizationID, name: "Test Application", slug: "test-application", issuer: "http://localhost:8093/oidc", version: 1 };
  let createdOrganization: Record<string, unknown> | undefined;
  await page.route("**/v1/setup/status", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ available: false, control_user_email_login_available: false }) }));
  await page.route("**/v1/control/organizations?*", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [organization], next_cursor: null, installation_role: "owner" }) }));
  await page.route("**/v1/control/organizations", async (route) => {
    createdOrganization = route.request().postDataJSON() as Record<string, unknown>;
    await route.fulfill({ contentType: "application/json", body: JSON.stringify({ id: createdOrganizationID, ...createdOrganization, role: "owner", version: 1 }) });
  });
  await page.route(`**/v1/control/organizations/${organizationID}`, async (route) => {
    const input = route.request().postDataJSON() as { name: string };
    organization = { ...organization, name: input.name, version: organization.version + 1 };
    await route.fulfill({ status: 204 });
  });
  await page.route("**/v1/control/organizations/*/applications?*", (route) => {
    const items = route.request().url().includes(organizationID) ? [application] : [];
    return route.fulfill({ contentType: "application/json", body: JSON.stringify({ items, next_cursor: null }) });
  });
  await page.route(`**/v1/control/organizations/${organizationID}/applications/${applicationID}`, async (route) => {
    const input = route.request().postDataJSON() as { name: string };
    application = { ...application, name: input.name, version: application.version + 1 };
    await route.fulfill({ status: 204 });
  });
  await page.route(`**/v1/control/applications/${applicationID}/statistics`, (route) => route.fulfill({ contentType: "application/json", body: "{}" }));
  await page.route(`**/v1/control/applications/${applicationID}`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify(application) }));

  await page.goto("/");
  await page.getByRole("button", { name: "Add organization" }).click();
  await page.getByLabel("Organization name").fill("Second Organization");
  await page.getByLabel("Organization slug").fill("second-organization");
  await page.getByRole("button", { name: "Create organization" }).click();
  await expect.poll(() => createdOrganization).toEqual({ name: "Second Organization", slug: "second-organization" });
  await expect(page.getByRole("heading", { name: "Second Organization" })).toBeVisible();

  await page.getByLabel("Access context").selectOption(`organization:${organizationID}`);
  await page.getByLabel("Organization name").fill("Renamed Organization");
  await page.getByRole("button", { name: "Rename organization" }).click();
  await expect(page.getByRole("status")).toContainText("Organization renamed.");
  await expect(page.getByLabel("Access context").locator(`option[value="organization:${organizationID}"]`)).toHaveText("Renamed Organization");

  await page.getByLabel("Access context").selectOption(`application:${applicationID}`);
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await page.getByLabel("Application name").fill("Renamed Application");
  await page.getByRole("button", { name: "Rename application" }).click();
  await expect(page.getByRole("status")).toContainText("Application renamed.");
  await expect(page.locator(".context-header")).toContainText("Renamed Application");
});

test("renders accessible compact actions with stable spacing", async ({ page }) => {
  const active = { id: "01900000-0000-7000-8000-000000000110", name: "Active Organization", slug: "active-organization", role: "owner", version: 1 };
  const retired = { id: "01900000-0000-7000-8000-000000000111", name: "Retired Organization", slug: "retired-organization", role: "owner", version: 1, retired_at: "2026-08-09T12:00:00Z" };
  await page.route("**/v1/setup/status", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ available: false, control_user_email_login_available: false }) }));
  await page.route("**/v1/control/organizations?*", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [active, retired], next_cursor: null, installation_role: "owner" }) }));
  await page.route("**/v1/control/organizations/*/applications?*", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [], next_cursor: null }) }));

  await page.goto("/");
  const open = page.getByRole("button", { name: "Open Active Organization", exact: true });
  const archive = page.getByRole("button", { name: "Retire Active Organization", exact: true });
  const restore = page.getByRole("button", { name: "Restore Retired Organization", exact: true });
  await expect(open).toBeVisible();
  await expect(archive).toBeVisible();
  await expect(restore).toBeVisible();
  await expect(open.locator("svg")).toHaveCount(1);
  await expect(archive.locator("svg")).toHaveCount(1);
  await expect(restore.locator("svg")).toHaveCount(1);
  await expect(archive).toHaveAttribute("title", "Retire Active Organization");
  const [openBox, archiveBox, restoreBox] = await Promise.all([open.boundingBox(), archive.boundingBox(), restore.boundingBox()]);
  for (const box of [openBox, archiveBox, restoreBox]) {
    expect(box?.width).toBeGreaterThanOrEqual(40);
    expect(box?.height).toBeGreaterThanOrEqual(40);
  }
  expect((archiveBox?.x ?? 0) - ((openBox?.x ?? 0) + (openBox?.width ?? 0))).toBeGreaterThanOrEqual(7);
  await expectNoSeriousAccessibilityViolations(page);
});

test("toggles installation provider inheritance after creation", async ({ page }) => {
  const smtpID = "01900000-0000-7000-8000-000000000121";
  const stripeID = "01900000-0000-7000-8000-000000000122";
  const storageID = "01900000-0000-7000-8000-000000000123";
  const auth = { id: "01900000-0000-7000-8000-000000000120", provider: "google", client_id: "google-client", scope: "installation", inheritable: true };
  const smtp = { id: smtpID, provider: "smtp", name: "Installation SMTP", sender_email: "mail@example.test", scope: "installation", inheritable: true };
  const stripe = { id: stripeID, provider: "stripe", public_id: "p93_stripe_test", status: "active", scope: "installation", inheritable: true };
  const storage = { id: storageID, name: "Installation storage", endpoint: "https://s3.example.test", public_bucket: "public-assets", status: "active", verified_at: "2026-08-09T12:00:00Z", scope: "installation", inheritable: true };
  const updates: { path: string; body: unknown }[] = [];
  await page.route("**/v1/setup/status", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ available: false, control_user_email_login_available: true }) }));
  await page.route("**/v1/control/organizations?*", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [], next_cursor: null, installation_role: "owner" }) }));
  await page.route("**/v1/control/auth/sessions", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [], next_cursor: null }) }));
  await page.route("**/v1/control/installation/users", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [], next_cursor: null }) }));
  await page.route("**/v1/control/installation/management-api", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ enabled: false, can_manage: true, active_clients: 0, token_endpoint: "http://localhost:8093/oidc/token", api_base: "http://localhost:8093/v1/management" }) }));
  await page.route("**/v1/control/installation/management-clients", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [], next_cursor: null }) }));
  await page.route("**/v1/control/installation/notification-templates", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [], next_cursor: null }) }));
  for (const [path, item] of [["auth/providers", auth], ["notification-providers", smtp], ["billing/providers", stripe], ["storage/providers", storage]] as const) {
    await page.route(`**/v1/control/installation/${path}`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [item], next_cursor: null }) }));
  }
  await page.route("**/v1/control/installation/storage/objects**", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [], next_cursor: null }) }));
  await page.route("**/v1/control/installation/auth/providers/google", async (route) => {
    updates.push({ path: new URL(route.request().url()).pathname, body: route.request().postDataJSON() });
    auth.inheritable = false;
    await route.fulfill({ status: 204 });
  });
  await page.route(`**/v1/control/installation/notification-providers/${smtpID}`, async (route) => {
    updates.push({ path: new URL(route.request().url()).pathname, body: route.request().postDataJSON() });
    smtp.inheritable = false;
    await route.fulfill({ contentType: "application/json", body: JSON.stringify(smtp) });
  });
  await page.route(`**/v1/control/installation/billing/providers/${stripeID}`, async (route) => {
    updates.push({ path: new URL(route.request().url()).pathname, body: route.request().postDataJSON() });
    stripe.inheritable = false;
    await route.fulfill({ status: 204 });
  });
  await page.route(`**/v1/control/installation/storage/providers/${storageID}`, async (route) => {
    updates.push({ path: new URL(route.request().url()).pathname, body: route.request().postDataJSON() });
    storage.inheritable = false;
    await route.fulfill({ contentType: "application/json", body: JSON.stringify(storage) });
  });

  await page.goto("/");
  await page.getByRole("button", { name: "Providers", exact: true }).click();
  await page.getByText("Configure Google", { exact: true }).click();
  await expect(page.locator(".provider-callback-box code").filter({ hasText: "/v1/auth/providers/google/callback" })).toHaveCount(1);
  await expect(page.locator(".provider-callback-box").filter({ hasText: "Google OAuth callback" })).toContainText("Add this exact installation-wide URL once");
  await page.getByText("Configure Apple", { exact: true }).click();
  await expect(page.locator(".provider-callback-box code").filter({ hasText: "/v1/auth/providers/apple/callback" })).toHaveCount(1);
  await expect(page.locator(".provider-settings")).not.toContainText("{application_id}");
  const cards = page.locator(".provider-cards article");
  await cards.filter({ hasText: "google" }).getByRole("checkbox", { name: "Global default for organizations and applications" }).click();
  await expect(cards.filter({ hasText: "google" }).getByRole("checkbox", { name: "Global default for organizations and applications" })).not.toBeChecked();
  await expect(page.getByRole("status")).toContainText("Google login is now limited to the installation scope.");
  await cards.filter({ hasText: "Installation SMTP" }).getByRole("checkbox").click();
  await expect(cards.filter({ hasText: "Installation SMTP" }).getByRole("checkbox")).not.toBeChecked();
  await expect(page.getByRole("status")).toContainText("SMTP is now limited to the installation scope.");
  await cards.filter({ hasText: "p93_stripe_test" }).getByRole("checkbox").click();
  await expect(cards.filter({ hasText: "p93_stripe_test" }).getByRole("checkbox")).not.toBeChecked();
  await expect(page.getByRole("status")).toContainText("Stripe is now limited to the installation scope.");
  await cards.filter({ hasText: "Installation storage" }).getByRole("checkbox").click();
  await expect(cards.filter({ hasText: "Installation storage" }).getByRole("checkbox")).not.toBeChecked();
  await expect(page.getByRole("status")).toContainText("Storage is now limited to the installation scope.");
  await expect.poll(() => updates).toEqual([
    { path: "/v1/control/installation/auth/providers/google", body: { inheritable: false } },
    { path: `/v1/control/installation/notification-providers/${smtpID}`, body: { inheritable: false } },
    { path: `/v1/control/installation/billing/providers/${stripeID}`, body: { inheritable: false } },
    { path: `/v1/control/installation/storage/providers/${storageID}`, body: { inheritable: false } },
  ]);
});

test("activates provisioning and applies installation-owned organization governance", async ({ page }) => {
  const organizationID = "01900000-0000-7000-8000-000000000130";
  const organization = { id: organizationID, name: "Governed Organization", slug: "governed-organization", role: "owner", version: 1 };
  let managementEnabled = false;
  let createdClient: Record<string, unknown> | undefined;
  let policyUpdate: Record<string, unknown> | undefined;
  let policyIfMatch = "";
  let policy = {
    organization_id: organizationID,
    max_applications: null,
    max_users: null,
    enabled_settings: {
      public_registration: true, password_authentication: true, passwordless_authentication: true,
      personal_api_keys: true, delegation: true, organization_provider_overrides: true,
      application_provider_overrides: true, custom_events: true, webhooks: true,
    },
    usage: { applications: 1, users: 24 },
    version: 1,
  };
  await page.route("**/v1/setup/status", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ available: false, control_user_email_login_available: true }) }));
  await page.route("**/v1/control/organizations?*", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [organization], next_cursor: null, installation_role: "owner" }) }));
  await page.route(`**/v1/control/organizations/${organizationID}/applications?*`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [], next_cursor: null }) }));
  await page.route("**/v1/control/auth/sessions", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [], next_cursor: null }) }));
  await page.route("**/v1/control/installation/users", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [], next_cursor: null }) }));
  await page.route("**/v1/control/installation/notification-templates", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [], next_cursor: null }) }));
  await page.route("**/v1/control/installation/management-api", async (route) => {
    if (route.request().method() === "PATCH") managementEnabled = Boolean((route.request().postDataJSON() as { enabled: boolean }).enabled);
    await route.fulfill({ contentType: "application/json", body: JSON.stringify({ enabled: managementEnabled, can_manage: true, active_clients: createdClient ? 1 : 0, token_endpoint: "http://localhost:8093/oidc/token", api_base: "http://localhost:8093/v1/management" }) });
  });
  await page.route("**/v1/control/installation/management-clients", async (route) => {
    if (route.request().method() === "POST") {
      createdClient = route.request().postDataJSON() as Record<string, unknown>;
      await route.fulfill({ contentType: "application/json", body: JSON.stringify({ id: "01900000-0000-7000-8000-000000000131", ...createdClient, allowed_scopes: ["/management/organizations/*"], client_secret: "p93_mgmt_once", secret_returned_once: true, version: 1 }) });
      return;
    }
    await route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [], next_cursor: null }) });
  });
  for (const path of ["auth/providers", "notification-providers", "billing/providers"]) {
    await page.route(`**/v1/control/installation/${path}`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [], next_cursor: null }) }));
    await page.route(`**/v1/control/organizations/${organizationID}/${path}`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [], next_cursor: null }) }));
  }
  await page.route(`**/v1/control/organizations/${organizationID}/members`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [], next_cursor: null }) }));
  await page.route(`**/v1/control/organizations/${organizationID}/invitations`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [], next_cursor: null }) }));
  await page.route(`**/v1/control/organizations/${organizationID}/policy`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify(policy) }));
  await page.route(`**/v1/control/installation/organizations/${organizationID}/policy`, async (route) => {
    policyUpdate = route.request().postDataJSON() as Record<string, unknown>;
    policyIfMatch = route.request().headers()["if-match"] ?? "";
    policy = { ...policy, ...(policyUpdate as typeof policy), version: 2 };
    await route.fulfill({ status: 204 });
  });

  await page.goto("/");
  await page.getByRole("button", { name: "Management API", exact: true }).click();
  await page.getByRole("button", { name: "Activate API" }).click();
  await expect(page.getByRole("status")).toContainText("Organization management API activated.");
  await page.getByPlaceholder("provisioning-production").fill("external-provisioner");
  await page.getByPlaceholder("Provisioning service").fill("External provisioning");
  await page.getByRole("button", { name: "Create client" }).click();
  await expect.poll(() => createdClient).toEqual({ client_id: "external-provisioner", name: "External provisioning" });
  await expect(page.getByRole("status")).toContainText("p93_mgmt_once");

  await page.getByLabel("Access context").selectOption(`organization:${organizationID}`);
  await expect(page.locator(".context-picker small")).toHaveText("Organization");
  await page.getByRole("button", { name: "Policy", exact: true }).click();
  await page.getByLabel("Maximum applications").fill("3");
  await page.getByLabel("Maximum users").fill("100");
  const webhooksSetting = page.locator(".policy-settings label").filter({ hasText: "Outgoing webhooks" });
  await webhooksSetting.getByRole("checkbox").uncheck();
  await page.getByRole("button", { name: "Save installation policy" }).click();
  await expect.poll(() => policyUpdate).toMatchObject({ max_applications: 3, max_users: 100, enabled_settings: { webhooks: false } });
  expect(policyIfMatch).toBe('"v1"');
  await expect(page.getByRole("status")).toContainText("Governance policy for Governed Organization updated.");
});

test("brand returns to the highest accessible context", async ({ page }) => {
  const organizationID = "01900000-0000-7000-8000-000000000104";
  const applicationID = "01900000-0000-7000-8000-000000000105";
  const organization = { id: organizationID, name: "Scoped Organization", slug: "scoped-organization", role: "owner", version: 1 };
  const application = { id: applicationID, organization_id: organizationID, name: "Scoped Application", slug: "scoped-application", issuer: "http://localhost:8093/oidc", version: 1 };
  let installationRole: "owner" | null = null;
  await page.route("**/v1/setup/status", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ available: false, control_user_email_login_available: false, control_auth_methods: { email_code: false, magic_link: false, password: true, providers: [] } }) }));
  await page.route("**/v1/control/organizations?*", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [organization], next_cursor: null, installation_role: installationRole }) }));
  await page.route(`**/v1/control/organizations/${organizationID}/applications?*`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [application], next_cursor: null }) }));
  await page.route(`**/v1/control/applications/${applicationID}`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify(application) }));
  await page.route(`**/v1/control/applications/${applicationID}/statistics`, (route) => route.fulfill({ contentType: "application/json", body: "{}" }));

  await page.goto("/");
  const context = page.getByLabel("Access context");
  await expect(context).toHaveValue(`organization:${organizationID}`);
  await expect(context.locator('option[value="platform"]')).toHaveCount(0);
  await context.selectOption(`application:${applicationID}`);
  await page.getByRole("button", { name: "Go to highest accessible home" }).click();
  await expect(context).toHaveValue(`organization:${organizationID}`);

  installationRole = "owner";
  await page.reload();
  await expect(context.locator('option[value="platform"]')).toHaveCount(1);
  await context.selectOption(`application:${applicationID}`);
  await page.getByRole("button", { name: "Go to highest accessible home" }).click();
  await expect(context).toHaveValue("platform");
});

test("manages the Platform user account and logs out from the footer", async ({ page }) => {
  const controlUserID = "01900000-0000-7000-8000-000000000108";
  let profileUpdate: Record<string, unknown> | undefined;
  let passwordUpdate: Record<string, unknown> | undefined;
  let loggedOut = false;
  await page.route("**/v1/setup/status", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ available: false, control_user_email_login_available: false, control_auth_methods: { email_code: false, magic_link: false, password: true, providers: [] } }) }));
  await page.route("**/v1/control/organizations?*", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [], next_cursor: null, installation_role: "owner" }) }));
  await page.route("**/v1/control/auth/me", async (route) => {
    if (route.request().method() === "PATCH") {
      profileUpdate = route.request().postDataJSON() as Record<string, unknown>;
      await route.fulfill({ status: 204 });
      return;
    }
    await route.fulfill({ contentType: "application/json", body: JSON.stringify({ id: controlUserID, email: "owner@example.test", display_name: "Installation Owner", status: "active", installation_role: "owner", organizations: [], sign_in_methods: { email_code: true, magic_link: true, password: false, external_identities: [] } }) });
  });
  await page.route("**/v1/control/auth/password", async (route) => {
    passwordUpdate = route.request().postDataJSON() as Record<string, unknown>;
    await route.fulfill({ status: 204 });
  });
  await page.route("**/v1/control/auth/logout", async (route) => {
    loggedOut = true;
    await route.fulfill({ status: 204 });
  });

  await page.goto("/");
  await page.getByRole("button", { name: "Account" }).click();
  await expect(page.getByRole("dialog", { name: "Platform user account" })).toBeVisible();
  await expect(page.getByText("owner@example.test")).toBeVisible();
  await page.getByLabel("Display name").fill("Renamed Owner");
  await page.getByRole("button", { name: "Save profile" }).click();
  await expect.poll(() => profileUpdate).toEqual({ display_name: "Renamed Owner" });
  await page.getByLabel("New password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Add password" }).click();
  await expect.poll(() => passwordUpdate).toEqual({ current_password: null, new_password: "correct horse battery staple" });
  await page.getByRole("button", { name: "Close" }).click();
  await page.getByRole("button", { name: "Log out" }).click();
  await expect.poll(() => loggedOut).toBe(true);
  await expect(page.getByRole("button", { name: "Sign in with password" })).toBeVisible();
});

test("validates public configuration and applies internal application policy", async ({ page }) => {
  const organizationID = "01900000-0000-7000-8000-000000000106";
  const applicationID = "01900000-0000-7000-8000-000000000107";
  let application = {
    id: applicationID,
    organization_id: organizationID,
    name: "Policy Application",
    slug: "policy-application",
    issuer: "http://localhost:8093/oidc",
    version: 1,
    auth_config: {},
    public_config: {},
    internal_config: {
      registration_mode: "public",
      password_enabled: true,
      passwordless_enabled: true,
      personal_api_keys_enabled: false,
      delegation_enabled: false,
    },
  };
  let publicUpdate: Record<string, unknown> | undefined;
  let internalUpdate: Record<string, unknown> | undefined;
  let publicIfMatch = "";
  let internalIfMatch = "";
  await page.route("**/v1/setup/status", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ available: false, control_user_email_login_available: false }) }));
  await page.route("**/v1/control/organizations?*", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [{ id: organizationID, name: "Policy Organization", slug: "policy-organization", role: "owner" }], next_cursor: null }) }));
  await page.route(`**/v1/control/organizations/${organizationID}/applications?*`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [application], next_cursor: null }) }));
  await page.route(`**/v1/control/applications/${applicationID}`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify(application) }));
  await page.route(`**/v1/control/applications/${applicationID}/statistics`, (route) => route.fulfill({ contentType: "application/json", body: "{}" }));
  await page.route(`**/v1/control/applications/${applicationID}/public-config`, async (route) => {
    publicUpdate = route.request().postDataJSON() as Record<string, unknown>;
    publicIfMatch = route.request().headers()["if-match"] ?? "";
    application = { ...application, public_config: publicUpdate, version: 2 };
    await route.fulfill({ status: 204 });
  });
  await page.route(`**/v1/control/applications/${applicationID}/internal-config`, async (route) => {
    internalUpdate = route.request().postDataJSON() as Record<string, unknown>;
    internalIfMatch = route.request().headers()["if-match"] ?? "";
    application = { ...application, internal_config: { ...application.internal_config, ...internalUpdate }, version: 3 };
    await route.fulfill({ status: 204 });
  });

  await page.goto("/");
  await page.getByLabel("Access context").selectOption({ label: "Policy Application" });
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  const publicConfigURL = `${new URL(page.url()).origin}/v1/applications/${applicationID}/public-config`;
  await expect(page.getByRole("link", { name: publicConfigURL })).toHaveAttribute("href", publicConfigURL);
  await expect(page.getByText("client.application().publicConfig()", { exact: true })).toBeVisible();
  const publicEditor = page.getByLabel("JSON object");
  await publicEditor.fill('{"support_url":');
  await expect(publicEditor).toHaveAttribute("aria-invalid", "true");
  await expect(page.getByRole("button", { name: "Save public config" })).toBeDisabled();
  await publicEditor.fill('{"support_url":"https://example.test/help","brand_name":"Example"}');
  await page.getByRole("button", { name: "Save public config" }).click();
  await expect.poll(() => publicUpdate).toEqual({ support_url: "https://example.test/help", brand_name: "Example" });
  expect(publicIfMatch).toBe('"v1"');
  await expect(page.getByRole("status")).toContainText("Public application configuration saved.");

  await page.getByLabel("Registration").selectOption("invite_only");
  await page.getByLabel("Personal API keys").check();
  await page.getByLabel("Platform user delegation").check();
  await page.getByRole("button", { name: "Save access policy" }).click();
  await expect.poll(() => internalUpdate).toEqual({
    registration_mode: "invite_only",
    password_enabled: true,
    passwordless_enabled: true,
    personal_api_keys_enabled: true,
    delegation_enabled: true,
    user_invitations_enabled: false,
    custom_token_claim_keys: [],
  });
  expect(internalIfMatch).toBe('"v2"');
  await expect(page.getByRole("status")).toContainText("Application access policy saved and enforced.");
  await expectNoSeriousAccessibilityViolations(page);
});

test("shows persistent labels in the product price detail form", async ({ page }) => {
  const organizationID = "01900000-0000-7000-8000-000000000010";
  const applicationID = "01900000-0000-7000-8000-000000000011";
  const productID = "01900000-0000-7000-8000-000000000012";
  const booleanFeatureID = "01900000-0000-7000-8000-000000000013";
  const quantityFeatureID = "01900000-0000-7000-8000-000000000014";
  const freeFormFeatureID = "01900000-0000-7000-8000-000000000016";
  let productUpdate: Record<string, unknown> | undefined;
  let priceCreate: Record<string, unknown> | undefined;
  await page.route("**/v1/setup/status", (route) => route.fulfill({
    contentType: "application/json",
    body: JSON.stringify({ available: false, control_user_email_login_available: false }),
  }));
  await page.route("**/v1/control/organizations?*", (route) => route.fulfill({
    contentType: "application/json",
    body: JSON.stringify({ items: [{ id: organizationID, name: "Test Organization", slug: "test-organization", role: "owner" }], next_cursor: null }),
  }));
  await page.route(`**/v1/control/organizations/${organizationID}/applications?*`, (route) => route.fulfill({
    contentType: "application/json",
    body: JSON.stringify({ items: [{ id: applicationID, organization_id: organizationID, name: "Test Application", slug: "test-application", issuer: "http://localhost:8093/oidc" }], next_cursor: null }),
  }));
  await page.route(`**/v1/control/applications/${applicationID}`, (route) => route.fulfill({
    contentType: "application/json",
    body: JSON.stringify({ id: applicationID, organization_id: organizationID, name: "Test Application", slug: "test-application", issuer: "http://localhost:8093/oidc", public_config: {}, internal_config: {}, version: 1 }),
  }));
  await page.route(`**/v1/control/applications/${applicationID}/statistics`, (route) => route.fulfill({ contentType: "application/json", body: "{}" }));
  await page.route(`**/v1/control/applications/${applicationID}/products`, (route) => route.fulfill({
    contentType: "application/json",
    body: JSON.stringify({ items: [{ id: productID, name: "Standard", key: "standard" }], next_cursor: null }),
  }));
  await page.route(`**/v1/control/applications/${applicationID}/features`, (route) => route.fulfill({
    contentType: "application/json",
    body: JSON.stringify({ items: [
      { id: booleanFeatureID, key: "advanced_export", name: "Advanced export", value_type: "boolean" },
      { id: quantityFeatureID, key: "projects", name: "Projects", value_type: "quantity" },
      { id: freeFormFeatureID, key: "rules", name: "Rules", value_type: "free_form", free_form_format: "json" },
    ], next_cursor: null }),
  }));
  await page.route(`**/v1/control/applications/${applicationID}/products/${productID}`, async (route) => {
    if (route.request().method() === "PATCH") {
      productUpdate = route.request().postDataJSON() as Record<string, unknown>;
      await route.fulfill({ status: 204 });
      return;
    }
    await route.fulfill({
      contentType: "application/json",
      headers: { ETag: '"v1"' },
      body: JSON.stringify({ id: productID, name: "Standard", key: "standard", version: 1, entitlement_config: {}, features: [] }),
    });
  });
  await page.route(`**/v1/control/applications/${applicationID}/products/${productID}/prices`, async (route) => {
    priceCreate = route.request().postDataJSON() as Record<string, unknown>;
    await route.fulfill({ contentType: "application/json", body: JSON.stringify({ id: "01900000-0000-7000-8000-000000000015" }) });
  });

  await page.goto("/");
  await page.getByLabel("Access context").selectOption({ label: "Test Application" });
  await expect(page.locator(".context-picker small")).toHaveText("Application");
  await page.getByRole("button", { name: "Catalog", exact: true }).click();
  await page.getByRole("button", { name: "Details", exact: true }).click();

  await expect(page.getByLabel("Advanced export (advanced_export)")).toBeVisible();
  await page.getByLabel("Advanced export (advanced_export)").selectOption("true");
  await page.getByLabel("Projects (projects)").fill("5");
  const rules = page.getByLabel("Rules (rules)");
  await rules.fill('{"regions":');
  await expect(rules).toHaveAttribute("aria-invalid", "true");
  await page.getByRole("button", { name: "Save entitlement defaults" }).click();
  expect(productUpdate).toBeUndefined();
  await rules.fill('{"regions":["CH","DE"]}');
  await expect(rules).toHaveAttribute("aria-invalid", "false");
  await expect(page.getByText("Valid JSON", { exact: true })).toBeVisible();
  await page.getByLabel("Entitlement configuration (JSON)").fill('{"support_level":"standard"}');
  await page.getByRole("button", { name: "Save entitlement defaults" }).click();
  await expect.poll(() => productUpdate).toEqual({
    entitlement_config: { support_level: "standard" },
    features: [
      { feature_id: booleanFeatureID, boolean_value: true },
      { feature_id: quantityFeatureID, quantity_value: 5 },
      { feature_id: freeFormFeatureID, free_form_value: { regions: ["CH", "DE"] } },
    ],
  });

  const amount = page.getByLabel("Amount in minor units");
  await expect(amount).toBeVisible();
  await expect(amount).toHaveAttribute("placeholder", "e.g. 1990");
  await expect(page.getByText("For EUR, 1990 means EUR 19.90.")).toBeVisible();
  await page.getByLabel("Price mode").selectOption("local");
  await expect(page.getByLabel("Local validity in seconds")).toBeVisible();
  await expect(page.getByLabel("Billing interval")).toHaveCount(0);
  await page.getByLabel("Price key").fill("local-standard");
  await amount.fill("1990");
  await page.getByLabel("Local validity in seconds").fill("2592000");
  await page.getByRole("button", { name: "Create price" }).click();
  await expect.poll(() => priceCreate).toMatchObject({ key: "local-standard", mode: "local", amount_minor: 1990 });
  expect(priceCreate).not.toHaveProperty("features");
  expect(priceCreate).not.toHaveProperty("entitlement_config");
  await page.setViewportSize({ width: 700, height: 900 });
  await expect(amount).toBeVisible();
  await expect(page.getByText("Amount in minor units", { exact: true })).toBeVisible();
});

test("registers custom events and selects webhook subscriptions from known types", async ({ page }) => {
  const organizationID = "01900000-0000-7000-8000-000000000020";
  const applicationID = "01900000-0000-7000-8000-000000000021";
  const platformEvent = {
    id: "01900000-0000-7000-8000-000000000022", name: "user.created", description: "A user account was created.",
    source: "platform93", status: "active", schema_version: "1.0", version: 1, event_count: 4,
    data_schema: { type: "object", required: ["user_id"], properties: { user_id: { type: "string" } } },
    example_subject: "user/01900000-0000-7000-8000-000000000099",
    example_data: { user_id: "01900000-0000-7000-8000-000000000099", email_verified: false, is_org_verified: false },
    example_event: { specversion: "1.0", id: "01900000-0000-7000-8000-000000000098", source: `platform93://applications/${applicationID}`, type: "user.created", contract_source: "platform93", time: "2026-01-01T00:00:00Z", application_id: applicationID, schema_version: "1.0", subject: "user/01900000-0000-7000-8000-000000000099", data: { user_id: "01900000-0000-7000-8000-000000000099", email_verified: false, is_org_verified: false } },
  };
  let registeredEvent: Record<string, unknown> | undefined;
  let createdWebhook: Record<string, unknown> | undefined;
  await page.route("**/v1/setup/status", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ available: false, control_user_email_login_available: false }) }));
  await page.route("**/v1/control/organizations?*", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [{ id: organizationID, name: "Test Organization", slug: "test-organization", role: "owner" }], next_cursor: null }) }));
  await page.route(`**/v1/control/organizations/${organizationID}/applications?*`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [{ id: applicationID, organization_id: organizationID, name: "Test Application", slug: "test-application", issuer: "http://localhost:8093/oidc" }], next_cursor: null }) }));
  await page.route(`**/v1/control/applications/${applicationID}`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ id: applicationID, organization_id: organizationID, name: "Test Application", slug: "test-application", issuer: "http://localhost:8093/oidc", public_config: {}, internal_config: {}, version: 1 }) }));
  await page.route(`**/v1/control/applications/${applicationID}/statistics`, (route) => route.fulfill({ contentType: "application/json", body: "{}" }));
  await page.route(`**/v1/control/applications/${applicationID}/event-types`, async (route) => {
    if (route.request().method() === "POST") {
      registeredEvent = route.request().postDataJSON() as Record<string, unknown>;
      await route.fulfill({ contentType: "application/json", body: JSON.stringify({ id: "01900000-0000-7000-8000-000000000024" }) });
      return;
    }
    await route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [
      platformEvent,
      { id: "01900000-0000-7000-8000-000000000023", name: "vehicle.created", description: "A vehicle was created.", source: "application", status: "active", schema_version: "1.0", event_count: 0 },
    ], next_cursor: null }) });
  });
  await page.route(`**/v1/control/applications/${applicationID}/event-types/${platformEvent.id}`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify(platformEvent) }));
  await page.route(`**/v1/control/applications/${applicationID}/webhooks`, async (route) => {
    if (route.request().method() === "POST") {
      createdWebhook = route.request().postDataJSON() as Record<string, unknown>;
      await route.fulfill({ contentType: "application/json", body: JSON.stringify({ id: "01900000-0000-7000-8000-000000000025", secret: "p93_whsec_test" }) });
      return;
    }
    await route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [], next_cursor: null }) });
  });

  await page.goto("/");
  await page.getByLabel("Access context").selectOption({ label: "Test Application" });
  await expect(page.locator(".context-picker small")).toHaveText("Application");
  await page.getByRole("button", { name: "Events", exact: true }).click();
  await page.getByRole("button", { name: "Details", exact: true }).first().click();
  await expect(page.getByText("Webhook example", { exact: true })).toBeVisible();
  await expect(page.getByText("v1.0", { exact: true })).toBeVisible();
  await expect(page.locator(".event-contract-view pre").first()).toContainText('"contract_source": "platform93"');
  await page.getByRole("button", { name: "Close", exact: true }).click();
  await page.getByRole("button", { name: "Register custom event" }).click();
  await page.getByLabel("Event type", { exact: true }).fill("vehicle.created");
  await page.getByLabel("Description").fill("A vehicle was created.");
  await page.getByLabel("Data schema (JSON)").fill('{"type":"object","required":["vehicle_id"]}');
  await page.getByLabel("Example subject").fill("vehicle/veh_123");
  await page.getByLabel("Example data (JSON)").fill('{"vehicle_id":"veh_123"}');
  await page.getByRole("button", { name: "Register custom event" }).click();
  await expect.poll(() => registeredEvent).toMatchObject({ name: "vehicle.created", schema_version: "1.0", data_schema: { type: "object", required: ["vehicle_id"] }, example_subject: "vehicle/veh_123", example_data: { vehicle_id: "veh_123" } });

  await page.getByRole("button", { name: "Webhooks", exact: true }).click();
  await page.getByRole("button", { name: "Create webhook" }).click();
  await expect(page.getByText("vehicle.created · v1.0", { exact: true })).toBeVisible();
  await expect(page.getByText("A vehicle was created. · application · 0 observed", { exact: true })).toBeVisible();
  await page.getByLabel("Subscribe to every active event type").uncheck();
  await page.getByLabel("HTTPS endpoint").fill("https://example.com/webhooks/platform93");
  await page.getByLabel("vehicle.created").check();
  await page.getByRole("button", { name: "Create webhook" }).click();
  await expect.poll(() => createdWebhook).toEqual({ uri: "https://example.com/webhooks/platform93", event_filters: ["vehicle.created"] });
});

test("composes notification templates with built-in and custom codes", async ({ page }) => {
  const organizationID = "01900000-0000-7000-8000-000000000030";
  const applicationID = "01900000-0000-7000-8000-000000000031";
  let createdTemplate: Record<string, unknown> | undefined;
  await page.route("**/v1/setup/status", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ available: false, control_user_email_login_available: false }) }));
  await page.route("**/v1/control/organizations?*", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [{ id: organizationID, name: "Test Organization", slug: "test-organization", role: "owner" }], next_cursor: null }) }));
  await page.route(`**/v1/control/organizations/${organizationID}/applications?*`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [{ id: applicationID, organization_id: organizationID, name: "Test Application", slug: "test-application", issuer: "http://localhost:8093/oidc" }], next_cursor: null }) }));
  await page.route(`**/v1/control/applications/${applicationID}`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ id: applicationID, organization_id: organizationID, name: "Test Application", slug: "test-application", issuer: "http://localhost:8093/oidc", public_config: {}, internal_config: {}, version: 1 }) }));
  await page.route(`**/v1/control/applications/${applicationID}/statistics`, (route) => route.fulfill({ contentType: "application/json", body: "{}" }));
  await page.route(`**/v1/control/applications/${applicationID}/notifications`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [], next_cursor: null }) }));
  await page.route(`**/v1/control/applications/${applicationID}/notification-template-variables`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [
    { key: "application_name", label: "Application name", description: "Application display name.", type: "string", availability: "always", sample: "Sample Application" },
    { key: "first_name", label: "First name", description: "Current user first name.", type: "string", availability: "user", sample: "Ada" },
    { key: "last_name", label: "Last name", description: "Current user last name.", type: "string", availability: "user", sample: "Lovelace" },
  ], next_cursor: null }) }));
  await page.route(`**/v1/control/applications/${applicationID}/notification-templates`, async (route) => {
    if (route.request().method() === "POST") {
      createdTemplate = route.request().postDataJSON() as Record<string, unknown>;
      await route.fulfill({ status: 201, contentType: "application/json", body: JSON.stringify({ id: "01900000-0000-7000-8000-000000000032", version: 1, status: "draft" }) });
      return;
    }
    await route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [], next_cursor: null }) });
  });
  await page.route(`**/v1/control/applications/${applicationID}/storage/providers`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [], next_cursor: null }) }));
  await page.route(`**/v1/control/applications/${applicationID}/storage/objects**`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [], next_cursor: null }) }));

  await page.goto("/");
  await page.getByLabel("Access context").selectOption({ label: "Test Application" });
  await expect(page.locator(".context-picker small")).toHaveText("Application");
  await page.getByRole("button", { name: "Notifications", exact: true }).click();
  await page.getByRole("button", { name: "Templates", exact: true }).click();
  await page.getByRole("button", { name: "Create template", exact: true }).click();
  await page.getByLabel("Template key").fill("welcome_email");
  await page.getByLabel("Subject").fill("Welcome ");
  await page.locator(".code-list > button").filter({ hasText: "First name" }).click();
  await expect(page.getByLabel("Subject")).toHaveValue("Welcome {{first_name}}");
  await expect(page.getByText("Requires user_id", { exact: false }).first()).toBeVisible();
  await page.getByPlaceholder("order_number").fill("order_number");
  await page.getByPlaceholder("Order number").fill("Order number");
  await page.getByPlaceholder("Example value").fill("P93-1007");
  await page.getByRole("button", { name: "Add code", exact: true }).click();
  await expect(page.getByText("{{order_number}}", { exact: true })).toBeVisible();
  await expect(page.frameLocator('iframe[title="Email preview"]').locator("body")).toContainText("Thanks for joining Test Application.");
  await page.getByRole("button", { name: "Create draft", exact: true }).click();
  await expect.poll(() => createdTemplate).toMatchObject({
    key: "welcome_email",
    subject_template: "Welcome {{first_name}}",
    variable_schema: {
      properties: { order_number: { type: "string", title: "Order number", example: "P93-1007" } },
      required: [],
    },
  });
});

test("manages user locale and creates a template localization draft", async ({ page }) => {
  const organizationID = "01900000-0000-7000-8000-000000000140";
  const applicationID = "01900000-0000-7000-8000-000000000141";
  const userID = "01900000-0000-7000-8000-000000000142";
  const templateID = "01900000-0000-7000-8000-000000000143";
  const organization = { id: organizationID, name: "Localized Organization", slug: "localized-organization", role: "owner", version: 1 };
  const application = { id: applicationID, organization_id: organizationID, name: "Localized Application", slug: "localized-application", issuer: "http://localhost:8093/oidc", public_config: {}, internal_config: {}, version: 1 };
  const user = { id: userID, application_id: applicationID, email: "ada@example.test", first_name: "Ada", last_name: "Lovelace", username: null, locale: "en", email_verified: true, is_org_verified: false, status: "active", custom_attributes: {}, version: 1 };
  const template = { id: templateID, key: "welcome_email", locale: "en", category: "transactional", version: 2, subject_template: "Welcome {{first_name}}", text_template: "Welcome {{first_name}}", html_template: "<p>Welcome {{first_name}}</p>", variable_schema: {}, status: "published", scope: "application", inherited: false, available_locales: ["de", "en"] };
  let userUpdate: Record<string, unknown> | undefined;
  let localizationDraft: Record<string, unknown> | undefined;

  await page.route("**/v1/setup/status", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ available: false, control_user_email_login_available: false }) }));
  await page.route("**/v1/control/organizations?*", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [organization], next_cursor: null }) }));
  await page.route(`**/v1/control/organizations/${organizationID}/applications?*`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [application], next_cursor: null }) }));
  await page.route(`**/v1/control/applications/${applicationID}`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify(application) }));
  await page.route(`**/v1/control/applications/${applicationID}/statistics`, (route) => route.fulfill({ contentType: "application/json", body: "{}" }));
  await page.route(`**/v1/control/applications/${applicationID}/users`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [user], next_cursor: null }) }));
  await page.route(`**/v1/control/applications/${applicationID}/users/${userID}`, async (route) => {
    if (route.request().method() === "PATCH") {
      userUpdate = route.request().postDataJSON() as Record<string, unknown>;
      await route.fulfill({ status: 204 });
      return;
    }
    await route.fulfill({ contentType: "application/json", headers: { ETag: '"v1"' }, body: JSON.stringify(user) });
  });
  for (const suffix of ["sessions", "addresses"]) {
    await page.route(`**/v1/control/applications/${applicationID}/users/${userID}/${suffix}`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [], next_cursor: null }) }));
  }
  await page.route(`**/v1/control/applications/${applicationID}/notifications`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [], next_cursor: null }) }));
  await page.route(`**/v1/control/applications/${applicationID}/notification-template-variables`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [], next_cursor: null }) }));
  await page.route(`**/v1/control/applications/${applicationID}/notification-templates`, async (route) => {
    if (route.request().method() === "POST") {
      localizationDraft = route.request().postDataJSON() as Record<string, unknown>;
      await route.fulfill({ status: 201, contentType: "application/json", body: JSON.stringify({ id: "01900000-0000-7000-8000-000000000144", key: "welcome_email", locale: "fr-CH", version: 1, status: "draft" }) });
      return;
    }
    await route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [template], next_cursor: null }) });
  });
  await page.route(`**/v1/control/applications/${applicationID}/notification-templates/${templateID}`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify(template) }));
  await page.route(`**/v1/control/applications/${applicationID}/storage/providers`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [], next_cursor: null }) }));
  await page.route(`**/v1/control/applications/${applicationID}/storage/objects**`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [], next_cursor: null }) }));

  await page.goto("/");
  await page.getByLabel("Access context").selectOption({ label: "Localized Application" });
  await expect(page.locator(".context-picker small")).toHaveText("Application");
  await page.getByRole("button", { name: "Identity", exact: true }).click();
  await page.getByRole("button", { name: "Details", exact: true }).click();
  await page.getByLabel("Preferred locale").fill("de-CH");
  await page.getByRole("button", { name: "Save locale" }).click();
  await expect.poll(() => userUpdate).toEqual({ locale: "de-CH" });
  await expect(page.getByRole("status")).toContainText("User locale set to de-CH");
  await page.getByRole("button", { name: "Close", exact: true }).click();

  await page.getByRole("button", { name: "Notifications", exact: true }).click();
  await page.getByRole("button", { name: "Templates", exact: true }).click();
  await page.getByRole("button", { name: "Details", exact: true }).click();
  await expect(page.locator(".locale-chips")).toContainText("de");
  await expect(page.locator(".locale-chips")).toContainText("en");
  await page.getByRole("button", { name: "Add localization" }).click();
  await page.getByLabel("New locale").fill("fr-CH");
  await page.getByRole("button", { name: "Create translation draft" }).click();
  await expect.poll(() => localizationDraft).toMatchObject({ key: "welcome_email", locale: "fr-CH", category: "transactional" });
  await expect(page.getByRole("status")).toContainText("Localization fr-CH created as a draft");
});

test("bootstraps a clean installation and creates its first application", async ({ context, page }) => {
  const credential = process.env.PLATFORM93_BOOTSTRAP_TOKEN;
  test.skip(!credential, "PLATFORM93_BOOTSTRAP_TOKEN is required for the destructive clean-install scenario");
  if (!credential) return;

  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Make the platform yours." })).toBeVisible();
  await page.getByLabel("Bootstrap credential").fill(credential);
  await page.getByLabel("Platform user email").fill("control_user@platform93.test");
  await page.getByLabel("Display name").fill("Platform User");
  await page.getByRole("button", { name: "Establish Platform user" }).click();

  await expect(page.getByLabel("Enable emails now")).not.toBeChecked();
  await expect(page.getByText("Email delivery will remain disabled.", { exact: false })).toBeVisible();
  await page.getByLabel("Initial owner password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Complete installation" }).click();
  await expect(page.getByText("Create the first boundary")).toBeVisible();

  await page.getByRole("button", { name: "Platform users", exact: true }).click();
  const installationAccess = page.locator(".control-scope").first();
  await expect(installationAccess.getByRole("heading", { name: "Platform users" })).toBeVisible();
  await installationAccess.getByLabel("Email", { exact: true }).fill("installation-admin@platform93.test");
  await installationAccess.locator('select[name="role"]').selectOption("admin");
  await installationAccess.getByRole("button", { name: "Invite Platform user" }).click();
  await expect(page.getByRole("status")).toContainText("Platform user invitation created.");
  await expect(installationAccess.getByText("installation-admin@platform93.test", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Overview", exact: true }).click();

  await page.getByLabel("Organization name").fill("Platform93 Test");
  await page.getByLabel("Organization slug").fill("platform93-test");
  await page.getByLabel("Application name").fill("Development");
  await page.getByLabel("Application slug").fill("development");
  await page.getByRole("button", { name: "Create organization and application" }).click();

  await expect(page.locator(".context-header").getByText("Development", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await expect(page.getByText("Active users")).toBeVisible();
  await expect(page.getByText("Events / 24h")).toBeVisible();
  await expect(page.getByRole("button", { name: "Platform users", exact: true })).toHaveCount(0);
  await expectNoSeriousAccessibilityViolations(page);

  await page.getByLabel("Access context").selectOption({ label: "Platform93 Test" });
  await expect(page.getByRole("button", { name: "Catalog", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Platform users", exact: true }).click();
  const organizationAccess = page.locator(".control-scope").first();
  await organizationAccess.getByLabel("Email", { exact: true }).fill("organization-admin@platform93.test");
  await organizationAccess.locator('select[name="role"]').selectOption("admin");
  await organizationAccess.getByRole("button", { name: "Invite Platform user" }).click();
  await expect(page.getByRole("status")).toContainText("Invitation queued.");
  const invitationResult = await page.getByRole("status").textContent();
  const invitationCredential = invitationResult?.match(/p93_org_invite_[A-Za-z0-9_-]{43}/)?.[0];
  expect(invitationCredential).toBeTruthy();
  await page.getByLabel("Access context").selectOption({ label: "Development" });

  await page.route("**/products", async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 350));
    await route.continue();
  }, { times: 1 });
  await page.getByRole("button", { name: "Catalog", exact: true }).click();
  const networkActivity = page.getByTestId("network-activity");
  await expect(networkActivity).toHaveAttribute("data-active", "true");
  await expect(networkActivity.getByText("Working")).toBeVisible();
  await expect(networkActivity).toHaveAttribute("data-active", "false");
  await page.getByRole("button", { name: "Features", exact: true }).click();
  await page.getByRole("button", { name: "Create feature", exact: true }).click();
  await page.getByLabel("Key").fill("tokens");
  await page.getByLabel("Name").fill("Tokens");
  await page.getByLabel("Value type").selectOption("quantity");
  await page.getByRole("button", { name: "Create feature", exact: true }).click();
  const featureSuccess = page.getByRole("status");
  await expect(featureSuccess).toContainText("Create feature completed.");
  await expect(featureSuccess).toHaveClass(/toast-success/);
  await expect(featureSuccess).toHaveCSS("background-color", "rgb(23, 107, 74)");
  await expect(page.getByText("Tokens", { exact: true })).toBeVisible();
  await expect(featureSuccess).toBeHidden({ timeout: 6000 });
  await page.getByRole("button", { name: "Create feature", exact: true }).click();
  await expect(page.getByLabel("Free-form format")).toHaveCount(0);
  await page.getByLabel("Value type").selectOption("free_form");
  await expect(page.getByLabel("Free-form format")).toBeVisible();
  await page.getByLabel("Free-form format").selectOption("json");
  await page.getByRole("button", { name: "Close", exact: true }).click();
  await page.getByRole("button", { name: "Overview", exact: true }).click();

  await context.clearCookies({ name: "p93_control_access" });
  const sessionRefresh = page.waitForResponse((response) =>
    response.url().endsWith("/v1/control/auth/token/refresh") && response.status() === 200,
  );
  const statisticsReload = page.waitForResponse((response) =>
    response.url().endsWith("/statistics") && response.status() === 200,
  );
  await page.getByRole("button", { name: "Refresh metrics", exact: true }).click();
  await sessionRefresh;
  await statisticsReload;
  await expect(page.getByText("Active users")).toBeVisible();

  await page.getByLabel("Access context").selectOption({ label: "Platform93 Test" });
  await page.getByPlaceholder("Application name").fill("Testing");
  await page.getByPlaceholder("application-slug").fill("testing");
  await page.getByRole("button", { name: "Create application", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("Application created.");
  await expect(page.locator(".context-header").getByText("Testing", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await page.getByLabel("Access context").selectOption({ label: "Platform93 Test" });
  const developmentCard = page.locator(".application-list > article").filter({ hasText: "Development" });
  await developmentCard.getByRole("button", { name: "Retire Development", exact: true }).click();
  await expect(page.getByText("Application retired and live credentials revoked.")).toBeVisible();
  await developmentCard.getByRole("button", { name: "Restore Development", exact: true }).click();
  await expect(page.getByText("Application restored. Previously revoked credentials remain revoked.")).toBeVisible();
  await page.getByLabel("Access context").selectOption({ label: "Development" });
  await expect(page.locator(".context-header").getByText("Development", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await expectNoSeriousAccessibilityViolations(page);

  await context.clearCookies();
  await page.reload();
  await expect(page.getByLabel("Invitation credential")).toHaveCount(0);
  await page.getByRole("button", { name: "Use an invitation", exact: true }).click();
  await page.getByLabel("Invitation credential").fill(invitationCredential!);
  await page.getByLabel("Required onboarding method").selectOption("email");
  await page.getByLabel("Display name").fill("Organization Admin");
  await page.getByRole("button", { name: "Accept with email" }).click();
  await expect(page.locator(".context-header").getByText("Platform93 Test", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
});
