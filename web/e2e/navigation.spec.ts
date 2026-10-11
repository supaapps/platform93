import { expect, test, type Page } from "@playwright/test";

const org = { id: "01900000-0000-7000-8000-000000000101", name: "Navigation Org", slug: "nav", role: "owner" };
const app = { id: "01900000-0000-7000-8000-000000000102", organization_id: org.id, name: "Navigation App", slug: "nav-app", issuer: "http://localhost:8093/oidc" };
const product = { id: "01900000-0000-7000-8000-000000000103", key: "standard", name: "Standard", version: 1 };

test("catalog products can be activated, archived and restored with version checks", async ({ page }) => {
  await mockAdmin(page);
  let status = "draft";
  let version = 17;
  await page.route(`**/v1/control/applications/${app.id}/products`, (route) => route.fulfill({ json: { items: [{ ...product, status, version }], next_cursor: null } }));
  await page.route(`**/v1/control/applications/${app.id}/products/${product.id}`, async (route) => {
    expect(route.request().method()).toBe("PATCH");
    expect(route.request().headers()["if-match"]).toBe(`"v${version.toString(16)}"`);
    status = route.request().postDataJSON().status;
    version += 1;
    await route.fulfill({ json: { ...product, status, version } });
  });
  await page.goto(`/?context=application&application_id=${app.id}&section=catalog&resource=products`);
  for (const [action, nextStatus] of [["Activate product", "active"], ["Archive product", "archived"], ["Restore product", "active"]] as const) {
    await page.getByRole("button", { name: action, exact: true }).click();
    await expect.poll(() => status).toBe(nextStatus);
    await expect(page.locator(".toast-success")).toContainText(`${action} completed.`);
    await expect(page.locator(".table article").filter({ hasText: "Standard" }).locator("small")).toHaveText(nextStatus);
  }
});

for (const viewport of [{ width: 1440, height: 900 }, { width: 390, height: 700 }]) {
  test(`drawers cover the viewport outside animated containers (${viewport.width}px)`, async ({ page }) => {
    await page.setViewportSize(viewport);
    await mockAdmin(page);
    const templateID = "01900000-0000-7000-8000-000000000104";
    await page.route(`**/v1/control/installation/notification-templates/${templateID}`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ id: templateID, key: "platform93.login", status: "draft", version: 1 }) }));
    for (const destination of [
      `/?context=application&application_id=${app.id}&section=identity&resource=clients&id=public-client`,
      "/?context=platform&section=overview&panel=account",
      `/?context=platform&section=email&resource=notification-templates&id=${templateID}`,
    ]) {
      await page.goto(destination);
      const dialog = page.getByRole("dialog");
      await expect(dialog).toBeVisible();
      const backdrop = page.locator(".detail-backdrop, .account-backdrop");
      await expect.poll(() => backdrop.evaluate((element) => element.parentElement === document.body)).toBe(true);
      await expect.poll(async () => Math.round((await backdrop.boundingBox())!.height)).toBe(viewport.height);
      expect(await backdrop.boundingBox()).toEqual({ x: 0, y: 0, width: viewport.width, height: viewport.height });
      await expect.poll(async () => {
        const bounds = (await dialog.boundingBox())!;
        return Math.round(bounds.x + bounds.width);
      }).toBeLessThanOrEqual(viewport.width);
      const bounds = (await dialog.boundingBox())!;
      expect(bounds.y).toBe(0);
      expect(Math.round(bounds.height)).toBe(viewport.height);
      expect(bounds.x).toBeGreaterThanOrEqual(0);
      expect(Math.round(bounds.x + bounds.width)).toBeLessThanOrEqual(viewport.width);
      await dialog.evaluate((element) => { element.scrollTop = element.scrollHeight; });
      await expect.poll(() => dialog.evaluate((element) => element.scrollTop)).toBeGreaterThan(0);
      await dialog.evaluate((element) => { element.scrollTop = 0; });
      await expect(dialog.getByRole("button", { name: "Close", exact: true })).toBeInViewport();
      await dialog.getByRole("button", { name: "Close", exact: true }).click();
      await expect(dialog).toHaveCount(0);
    }
  });
}

for (const scope of ["installation", "organization", "application"] as const) {
  test(`social provider forms restrict Platform login fields to installation (${scope})`, async ({ page }) => {
    await mockAdmin(page);
    const context = scope === "installation" ? "platform" : scope;
    const contextID = scope === "application" ? `&application_id=${app.id}` : scope === "organization" ? `&organization_id=${org.id}` : "";
    const basePath = scope === "installation" ? "/v1/control/installation" : scope === "organization" ? `/v1/control/organizations/${org.id}` : `/v1/control/applications/${app.id}`;
    await page.route("**/auth/providers/*", async (route) => {
      expect(route.request().method()).toBe("PUT");
      const provider = new URL(route.request().url()).pathname.split("/").at(-1);
      const payload = route.request().postDataJSON();
      expect(new URL(route.request().url()).pathname).toBe(`${basePath}/auth/providers/${provider}`);
      if (scope === "installation") expect(payload.control_login_enabled).toBe(provider !== "google");
      else expect(payload).not.toHaveProperty("control_login_enabled");
      await route.fulfill({ contentType: "application/json", body: "{}" });
    });
    await page.goto(`/?context=${context}${contextID}&section=providers`);
    for (const provider of ["Google", "Apple", "Microsoft", "Facebook", "LinkedIn"]) {
      await page.getByRole("link", { name: `Configure ${provider}`, exact: true }).click();
      const form = page.locator("form").filter({ has: page.getByRole("button", { name: `Save ${provider}`, exact: true }) });
      await form.locator('[name="client_id"]').fill("test-client-id");
      if (provider === "Apple") {
        await form.locator('[name="team_id"]').fill("test-team-id");
        await form.locator('[name="key_id"]').fill("test-key-id");
        await form.locator('[name="private_key_pem"]').fill("test-only-private-key-placeholder");
      } else await form.locator('[name="client_secret"]').fill("test-client-secret");
      const controlLogin = form.locator('[name="control_login_enabled"]');
      if (scope === "installation") {
        await expect(controlLogin).toBeVisible();
        if (provider !== "Google") await controlLogin.check();
      } else await expect(controlLogin).toHaveCount(0);
      const response = page.waitForResponse((response) => response.request().method() === "PUT" && response.url().endsWith(`/auth/providers/${provider.toLowerCase()}`));
      await form.getByRole("button", { name: `Save ${provider}`, exact: true }).click();
      await response;
      await expect(page.locator(".toast-success")).toContainText(`${provider} login provider saved`);
    }
  });
}

async function mockAdmin(page: Page) {
  await page.route("**/version", (route) => route.fulfill({ json: { version: "0.2.1" } }));
  await page.route("https://api.github.com/repos/supaapps/platform93/releases/latest", (route) => route.fulfill({ json: { tag_name: "v0.2.1", draft: false, prerelease: false } }));
  await page.route("**/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let body: unknown = { items: [], next_cursor: null };
    if (path === "/v1/setup/status") body = { available: false, control_auth_methods: { email_code: true, magic_link: true, password: true, providers: ["google", "apple", "microsoft", "facebook", "linkedin"] } };
    if (path === "/v1/control/organizations") body = { items: [org], installation_role: "owner", next_cursor: null };
    if (path === `/v1/control/organizations/${org.id}/applications`) body = { items: [app], next_cursor: null };
    if (path === `/v1/control/applications/${app.id}`) body = app;
    if (path.endsWith("/products")) body = { items: [product], next_cursor: null };
    if (path.endsWith(`/products/${product.id}`)) body = product;
    if (path.endsWith("/clients")) body = { items: [{ id: "database-id", client_id: "public-client", name: "Browser", client_type: "public" }], next_cursor: null };
    if (path.endsWith("/clients/public-client")) body = { client_id: "public-client", name: "Browser", redirect_uris: [] };
    if (path === "/v1/control/auth/me") body = { id: "control-id", email: "owner@example.test", display_name: "Owner", status: "active", installation_role: "owner", organizations: [], sign_in_methods: { email_code: true, magic_link: true, password: true, external_identities: [] } };
    if (path === "/v1/control/auth/methods") body = { email_code: true, magic_link: true, password: true, providers: [] };
    if (path.endsWith("/auth-branding")) body = { configuration: {}, version: 0, effective: { display_name: "Platform93" } };
    await route.fulfill({ contentType: "application/json", body: JSON.stringify(body) });
  });
}

test("hosted branding validates responses and saves localized previews", async ({ page }) => {
  await mockAdmin(page);
  let settings = { configuration: { display_name: "Local name", copy: { en: { heading: "Local heading" } } } as Record<string, unknown>, version: 0, inherited: { display_name: "Parent name", copy: { en: { heading: "Parent heading", help: "Inherited secure access" } } }, effective: { display_name: "Local name", copy: { en: { heading: "Local heading", help: "Inherited secure access" } } } as Record<string, unknown> };
  await page.route("**/auth-branding", async (route) => {
    if (route.request().method() === "PUT") {
      expect(route.request().headers()["if-match"]).toBe('"v0"');
      const configuration = route.request().postDataJSON();
      settings = { ...settings, configuration, version: 1, effective: configuration };
      return route.fulfill({ status: 204 });
    }
    await route.fulfill({ json: settings });
  });
  await page.goto("/?context=platform&section=providers");
  await page.getByText("Hosted authentication branding", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "Local heading", exact: true })).toBeVisible();
  await expect(page.getByLabel("Hosted sign-in preview")).toContainText("Inherited secure access");
  await page.getByLabel(/^Display name/).fill("");
  await expect(page.getByLabel("Hosted sign-in preview")).toContainText("Parent name");
  await page.getByLabel(/^Localized heading and help/).fill('{}');
  await expect(page.getByRole("heading", { name: "Parent heading", exact: true })).toBeVisible();
  await page.getByLabel(/^Localized heading and help/).fill('{"en":{"heading":"Edited heading"}}');
  await expect(page.getByRole("heading", { name: "Edited heading", exact: true })).toBeVisible();
  await expect(page.getByLabel("Hosted sign-in preview")).toContainText("Inherited secure access");
  await page.getByLabel(/^Display name/).fill("Example identity");
  await page.getByLabel(/^Default language tag/).fill("fr-CA");
  await page.getByLabel(/^Localized heading and help/).fill('{"FR":{"heading":"Bienvenue","help":"Accès sécurisé"}}');
  await expect(page.getByRole("heading", { name: "Bienvenue", exact: true })).toBeVisible();
  await expect(page.getByLabel("Hosted sign-in preview")).toContainText("Accès sécurisé");
  await page.getByLabel(/^Default language tag/).fill("en");
  await page.getByLabel(/^Localized heading and help/).fill('{"en":{"heading":"Welcome to Example","help":"Your secure account"}}');
  await expect(page.getByRole("heading", { name: "Welcome to Example", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Save branding", exact: true }).click();
  await expect(page.locator(".toast-success")).toContainText("Hosted authentication branding saved.");
  expect(settings.configuration.display_name).toBe("Example identity");
});

test("malformed branding settings do not crash provider configuration", async ({ page }) => {
  await mockAdmin(page);
  await page.route("**/auth-branding", (route) => route.fulfill({ json: { items: [] } }));
  await page.goto("/?context=platform&section=providers");
  await page.getByText("Hosted authentication branding", { exact: true }).click();
  await expect(page.getByText("Branding settings returned an invalid response. Reload to try again.")).toBeVisible();
  await page.getByRole("link", { name: "Configure Google", exact: true }).click();
  await expect(page.getByRole("button", { name: "Save Google", exact: true })).toBeVisible();
});

test("sidebar transitions never canonicalize resources using the previous section", async ({ page }) => {
  await mockAdmin(page);
  await page.goto(`/?context=application&application_id=${app.id}&section=catalog&resource=features`);
  await expect(page.getByRole("link", { name: "Features", exact: true })).toHaveClass(/active/);
  for (const [label, section, resource] of [
    ["Entitlements", "entitlements", "entitlements"],
    ["Identity", "identity", "users"],
    ["Billing", "billing", "billing/subscriptions"],
    ["Notifications", "notifications", "notifications"],
    ["Webhooks", "webhooks", "webhooks"],
    ["Events", "events", "event-types"],
    ["Audit", "audit", "audit-logs"],
    ["Operations", "operations", "webhook-deliveries"],
    ["Catalog", "catalog", "products"],
    ["Requests", "requests", "local-entitlement-requests"],
    ["Workspaces", "workspaces", "workspaces"],
  ]) {
    await page.getByRole("link", { name: label, exact: true }).click();
    await expect(page.getByRole("heading", { name: label, exact: true })).toBeVisible();
    await expect.poll(() => new URL(page.url()).searchParams.get("section")).toBe(section);
    await expect.poll(() => new URL(page.url()).searchParams.get("resource")).toBe(resource);
    await expect(page.locator(".toast-error")).toHaveCount(0);
  }
  await page.goBack();
  await expect(page.getByRole("heading", { name: "Requests", exact: true })).toBeVisible();
  await expect.poll(() => new URL(page.url()).searchParams.get("resource")).toBe("local-entitlement-requests");
  await expect(page.locator(".toast-error")).toHaveCount(0);
  await page.goForward();
  await expect(page.getByRole("heading", { name: "Workspaces", exact: true })).toBeVisible();
  await expect.poll(() => new URL(page.url()).searchParams.get("resource")).toBe("workspaces");
  await expect(page.locator(".toast-error")).toHaveCount(0);
  await page.getByLabel("Access context").selectOption("platform");
  await expect(page.getByRole("heading", { name: "Overview", exact: true })).toBeVisible();
  expect(new URL(page.url()).searchParams.has("resource")).toBe(false);
  await expect(page.locator(".toast-error")).toHaveCount(0);
});

test("a late detail error cannot rewrite the newly selected section", async ({ page }) => {
  await mockAdmin(page);
  let releaseDetail!: () => void;
  const detailPending = new Promise<void>((resolve) => { releaseDetail = resolve; });
  let detailStarted!: () => void;
  const detailRequested = new Promise<void>((resolve) => { detailStarted = resolve; });
  await page.route(`**/v1/control/applications/${app.id}/products/${product.id}`, async (route) => {
    detailStarted();
    await detailPending;
    await route.fulfill({ status: 404, contentType: "application/problem+json", body: JSON.stringify({ status: 404, title: "Old detail unavailable", code: "not_found" }) });
  });
  await page.goto(`/?context=application&application_id=${app.id}&section=catalog&resource=products&id=${product.id}`);
  await detailRequested;
  await page.getByRole("link", { name: "Entitlements", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Entitlements", exact: true })).toBeVisible();
  const response = page.waitForResponse((response) => response.url().endsWith(`/products/${product.id}`));
  releaseDetail();
  await response;
  await expect.poll(() => new URL(page.url()).searchParams.get("resource")).toBe("entitlements");
  await expect(page.locator(".toast-error")).toHaveCount(0);
  expect(new URL(page.url()).searchParams.has("id")).toBe(false);
});

for (const scenario of [
  { running: "0.2.1", latest: "v0.2.1", label: "Latest version (0.2.1)" },
  { running: "0.2.1", latest: "v0.3.0", label: "Update available (0.2.1)" },
  { running: "0.2.9", latest: "v0.2.10", label: "Update available (0.2.9)" },
  { running: "0.3.0-rc.1", latest: "v0.3.0", label: "Update available (0.3.0-rc.1)" },
  { running: "0.4.0", latest: "v0.3.0", label: "Ahead of latest release (0.4.0)" },
  { running: "dev", latest: "v0.3.0", label: "Development build" },
  { running: "invalid", latest: "v0.3.0", label: "Version check unavailable" },
  { running: "0.2.1", latest: "v0.3.0", label: "Version check unavailable", status: 403 },
]) {
  test(`release status: ${scenario.running} against ${scenario.latest} (${scenario.label})`, async ({ page }) => {
    await mockAdmin(page);
    await page.route("**/version", (route) => route.fulfill({ json: { version: scenario.running } }));
    await page.route("https://api.github.com/repos/supaapps/platform93/releases/latest", async (route) => {
      expect(route.request().headers()).not.toHaveProperty("authorization");
      expect(route.request().headers()).not.toHaveProperty("cookie");
      await route.fulfill({ status: scenario.status ?? 200, json: { tag_name: scenario.latest, draft: false, prerelease: false, html_url: "https://untrusted.example/" } });
    });
    await page.goto("/?context=platform&section=overview");
    const status = page.locator(".release-status");
    await expect(status).toHaveText(scenario.label);
    if (scenario.label.startsWith("Latest version")) {
      await expect(status).toHaveClass(/release-status-current/);
    } else if (scenario.label.startsWith("Update available")) {
      await expect(status).toHaveClass(/release-status-update/);
    }
    const href = scenario.label === "Development build" || scenario.label === "Version check unavailable"
      ? "https://github.com/supaapps/platform93/releases"
      : `https://github.com/supaapps/platform93/releases/tag/${scenario.latest}`;
    await expect(status.getByRole("link")).toHaveAttribute("href", href);
  });
}

test("restores application details and browser history", async ({ page }) => {
  await mockAdmin(page);
  await page.goto(`/?context=application&application_id=${app.id}&section=catalog&resource=products&id=${product.id}`);
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.reload();
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.getByRole("button", { name: "Close", exact: true }).click();
  await expect(page).not.toHaveURL(/&id=/);
  await expect(page).toHaveURL(/application_id=.*section=catalog/);
  await page.getByRole("link", { name: "Features", exact: true }).click();
  await expect(page).toHaveURL(/resource=features/);
  await page.goBack();
  await expect(page.getByRole("link", { name: "Products", exact: true })).toHaveClass(/active/);
  await page.goBack();
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.goForward();
  await expect(page.getByRole("dialog")).toHaveCount(0);
});

test("uses the OAuth client ID in shareable detail links", async ({ page }) => {
  await mockAdmin(page);
  await page.goto(`/?context=application&application_id=${app.id}&section=identity&resource=clients`);
  await page.getByRole("link", { name: "Details", exact: true }).click();
  await expect(page).toHaveURL(/id=public-client/);
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.reload();
  await expect(page.getByRole("dialog")).toBeVisible();
});

test("rejects inaccessible platform and application destinations for organization users", async ({ page }) => {
  await mockAdmin(page);
  await page.route("**/v1/control/organizations?*", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [org], installation_role: null, next_cursor: null }) }));
  await page.goto("/?context=platform&section=identity");
  await expect(page).toHaveURL(/context=organization/);
  await expect(page.locator(".toast-error")).toContainText("unavailable");
  await expect(page.getByLabel("Access context").locator('option[value="platform"]')).toHaveCount(0);
  await page.goto("/?context=application&application_id=another-app&section=identity");
  await expect(page).toHaveURL(/context=organization/);
  await expect(page.locator(".context-header")).toContainText(org.name);
});

test("recovers malformed resource tabs and missing detail records", async ({ page }) => {
  await mockAdmin(page);
  await page.goto(`/?context=application&application_id=${app.id}&section=catalog&resource=unknown&id=missing`);
  await expect(page).toHaveURL(/resource=products/);
  await expect(page.locator(".toast-error")).toContainText("This resource tab is unavailable");
  await expect(page).not.toHaveURL(/&id=/);
  await page.route(`**/v1/control/applications/${app.id}/products/missing`, (route) => route.fulfill({ status: 404, contentType: "application/problem+json", body: JSON.stringify({ status: 404, title: "Product unavailable", code: "not_found" }) }));
  await page.goto(`/?context=application&application_id=${app.id}&section=catalog&resource=products&id=missing`);
  await expect(page.locator(".toast-error")).toContainText("Product unavailable");
  await expect(page).not.toHaveURL(/&id=/);
  await expect(page.getByRole("link", { name: "Products", exact: true })).toHaveClass(/active/);
});

test("recovers unavailable contexts and navigates account and sessions", async ({ page }) => {
  await mockAdmin(page);
  await page.goto("/?context=application&application_id=missing&section=billing");
  await expect(page.locator(".toast-error")).toContainText("unavailable");
  await expect(page).toHaveURL(/context=platform/);
  await page.getByRole("link", { name: "Account", exact: true }).click();
  await expect(page).toHaveURL(/panel=account/);
  await page.reload();
  await expect(page.getByRole("dialog", { name: "Platform user account" })).toBeVisible();
  await page.getByRole("button", { name: "Manage sessions" }).click();
  await expect(page).toHaveURL(/section=sessions/);
  await expect(page.getByRole("dialog")).toHaveCount(0);
});

test("preserves a destination through password sign-in and shows provider icons", async ({ page }) => {
  await mockAdmin(page);
  let authenticated = false;
  await page.route("**/v1/control/organizations?*", (route) => authenticated
    ? route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [org], installation_role: "owner", next_cursor: null }) })
    : route.fulfill({ status: 401, contentType: "application/problem+json", body: JSON.stringify({ status: 401, title: "Sign in", code: "unauthorized" }) }));
  await page.route("**/v1/control/auth/token/refresh", (route) => route.fulfill({ status: 401 }));
  await page.route("**/v1/control/auth/password", (route) => { authenticated = true; return route.fulfill({ contentType: "application/json", body: "{}" }); });
  await page.goto(`/?context=application&application_id=${app.id}&section=catalog&resource=features`);
  for (const provider of ["Google", "Apple", "Microsoft", "Facebook", "LinkedIn"]) {
    await expect(page.getByRole("button", { name: provider, exact: true }).locator('svg[aria-hidden="true"]')).toBeVisible();
  }
  await page.getByRole("button", { name: "Use password instead" }).click();
  await page.getByLabel("Platform user email").fill("owner@example.test");
  await page.getByLabel("Password", { exact: true }).fill("correct horse battery staple");
  await page.getByRole("button", { name: "Sign in with password" }).click();
  await expect(page.getByRole("heading", { name: "Catalog", exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Features", exact: true })).toHaveClass(/active/);
});

test("restores provider configuration and settings selections", async ({ page }) => {
  await mockAdmin(page);
  await page.goto(`/?context=application&application_id=${app.id}&section=providers&panel=provider-google`);
  await expect(page.getByLabel("OAuth client ID", { exact: true })).toBeVisible();
  await page.getByRole("link", { name: "Configure Apple", exact: true }).click();
  await expect(page).toHaveURL(/panel=provider-apple/);
  await page.goBack();
  await expect(page.getByLabel("OAuth client ID", { exact: true })).toBeVisible();
  await page.getByRole("link", { name: "Settings", exact: true }).click();
  await page.getByRole("link", { name: "Access policy", exact: true }).click();
  await expect(page).toHaveURL(/panel=settings-internal/);
  await page.reload();
  await expect(page.getByRole("link", { name: "Access policy", exact: true })).toHaveClass(/active/);
});

test("preserves unsaved provider values while panels are hidden", async ({ page }) => {
  await mockAdmin(page);
  await page.goto(`/?context=application&application_id=${app.id}&section=providers&panel=provider-google`);
  const clientID = page.getByLabel("OAuth client ID", { exact: true });
  const clientSecret = page.getByLabel("OAuth client secret", { exact: true });
  await clientID.fill("draft-client-id");
  await clientSecret.fill("draft-client-secret");
  await page.getByRole("link", { name: "Configure Google", exact: true }).click();
  await expect(clientID).toBeHidden();
  await expect(clientID).toHaveValue("draft-client-id");
  await page.getByRole("link", { name: "Configure Google", exact: true }).click();
  await expect(clientID).toBeVisible();
  await expect(clientSecret).toHaveValue("draft-client-secret");
  await page.getByRole("link", { name: "Configure Apple", exact: true }).click();
  await page.getByLabel("Team ID", { exact: true }).fill("draft-team-id");
  await expect(clientID).toBeHidden();
  await page.goBack();
  await expect(clientID).toBeVisible();
  await expect(clientID).toHaveValue("draft-client-id");
  await page.getByRole("link", { name: "Account", exact: true }).click();
  const account = page.getByRole("dialog", { name: "Platform user account" });
  await expect(account).toBeVisible();
  await expect(clientID).toBeHidden();
  await account.getByRole("button", { name: "Close", exact: true }).click();
  await page.getByRole("link", { name: "Configure Google", exact: true }).click();
  await expect(clientID).toHaveValue("draft-client-id");
  await expect(clientSecret).toHaveValue("draft-client-secret");
  await page.getByRole("link", { name: "Configure Apple", exact: true }).click();
  await expect(page.getByLabel("Team ID", { exact: true })).toHaveValue("draft-team-id");
  expect(page.url()).not.toContain("draft-");
  expect(await page.evaluate(() => JSON.stringify({ ...sessionStorage, ...localStorage }))).not.toContain("draft-");
});

test("restores a destination after an external provider returns to the root", async ({ page }) => {
  await mockAdmin(page);
  let authenticated = false;
  await page.route("**/v1/control/organizations?*", (route) => authenticated
    ? route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [org], installation_role: "owner", next_cursor: null }) })
    : route.fulfill({ status: 401, contentType: "application/problem+json", body: JSON.stringify({ status: 401, title: "Sign in", code: "unauthorized" }) }));
  await page.route("**/v1/control/auth/token/refresh", (route) => route.fulfill({ status: 401 }));
  await page.route("**/v1/control/auth/providers/google/start", (route) => {
    authenticated = true;
    return route.fulfill({ contentType: "application/json", body: JSON.stringify({ authorize_url: `${new URL(page.url()).origin}/?control_provider=google&status=success` }) });
  });
  await page.goto(`/?context=application&application_id=${app.id}&section=catalog&resource=features`);
  await page.getByRole("button", { name: "Google", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Catalog", exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Features", exact: true })).toHaveClass(/active/);
  expect(new URL(page.url()).searchParams.has("control_provider")).toBe(false);
  expect(await page.evaluate(() => sessionStorage.getItem("p93_admin_destination"))).toBeNull();
});
