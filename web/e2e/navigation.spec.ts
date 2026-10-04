import { expect, test, type Page } from "@playwright/test";

const org = { id: "01900000-0000-7000-8000-000000000101", name: "Navigation Org", slug: "nav", role: "owner" };
const app = { id: "01900000-0000-7000-8000-000000000102", organization_id: org.id, name: "Navigation App", slug: "nav-app", issuer: "http://localhost:8093/oidc" };
const product = { id: "01900000-0000-7000-8000-000000000103", key: "standard", name: "Standard", version: 1 };

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
    await route.fulfill({ contentType: "application/json", body: JSON.stringify(body) });
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
