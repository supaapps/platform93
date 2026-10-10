import { expect, test, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { chooseSelect, nativeSelect } from "./select-control";

const id = (value: number) => `01900000-0000-7000-8000-${String(value).padStart(12, "0")}`;
const org = { id: id(1), name: "Example Studio", slug: "example", role: "owner", version: 1 };
const app = { id: id(2), organization_id: org.id, name: "Customer portal", slug: "portal", issuer: "https://platform.example.test/oidc", version: 1, auth_config: { flows: {} }, public_config: { brand_name: "Example Studio" }, internal_config: { registration_mode: "public", password_enabled: true, passwordless_enabled: true, personal_api_keys_enabled: false, delegation_enabled: false, user_invitations_enabled: true, custom_token_claim_keys: [] } };
const user = { id: id(3), first_name: "Alex", last_name: "Morgan", email: "alex@example.test", status: "active", locale: "en", version: 1 };
const workspace = { id: id(4), key: "design", name: "Design team", owner_user_id: user.id, version: 1 };
const feature = { id: id(5), key: "projects", name: "Projects", value_type: "quantity" };
const product = { id: id(6), key: "standard", name: "Standard", status: "active", version: 1, features: [{ feature_id: feature.id, quantity_value: 5 }], entitlement_config: { support: "standard" }, prices: [] };
const client = { id: id(7), client_id: "portal-web", name: "Portal browser", client_type: "public", redirect_uris: ["https://portal.example.test/callback"], allowed_grants: ["authorization_code", "refresh_token"], allowed_scopes: ["openid", "profile", "email"], version: 1 };
const template = { id: id(8), key: "platform93.login", name: "Sign-in email", locale: "en", category: "security", status: "draft", version: 1, subject_template: "Sign in to {{ application.name }}", text_template: "Your code is {{ code }}.", html_template: "<h1>Welcome back</h1><p>Your sign-in code is <strong>{{ code }}</strong>.</p>", variables_schema: { type: "object", properties: {} } };
const account = { id: id(9), email: "owner@example.test", display_name: "Jamie Taylor", status: "active", installation_role: "owner", organizations: [], sign_in_methods: { email_code: true, magic_link: true, password: true, external_identities: [] } };
const methods = { email_code: true, magic_link: true, password: true, providers: ["google", "apple", "microsoft", "facebook", "linkedin"] };
const applicationRoute = (section: string, resource: string) => `/?context=application&organization_id=${org.id}&application_id=${app.id}&section=${section}&resource=${resource}`;

async function mock(page: Page, mode: "admin" | "login" | "setup" = "admin") {
  await page.route("**/version", (route) => route.fulfill({ json: { version: "0.3.0" } }));
  await page.route("https://api.github.com/**", (route) => route.fulfill({ json: { tag_name: "v0.3.0", draft: false, prerelease: false } }));
  await page.route("**/oidc/.well-known/openid-configuration", (route) => route.fulfill({ json: { issuer: app.issuer } }));
  await page.route("**/v1/**", async (route) => {
    const url = new URL(route.request().url());
    const resource = url.pathname.split("/").at(-1)!;
    let body: unknown = { items: [], next_cursor: null };
    if (url.pathname === "/v1/setup/status") body = { available: mode === "setup", control_auth_methods: methods, control_user_email_login_available: true };
    else if (url.pathname === "/v1/control/organizations") {
      if (mode === "login") { await route.fulfill({ status: 401, json: { status: 401, title: "Sign in required", code: "control_access_required" } }); return; }
      body = { items: [org], next_cursor: null, installation_role: "owner" };
    } else if (resource === "applications") body = { items: [app], next_cursor: null };
    else if (resource === app.id) body = app;
    else if (resource === "methods") body = methods;
    else if (url.pathname.endsWith("/auth/me")) body = account;
    else if (resource === "policy") body = { organization_id: org.id, max_applications: 10, max_users: 1000, enabled_settings: {}, usage: { applications: 1, users: 128 }, version: 1 };
    else if (resource === "statistics") body = { users: { active: 128, suspended: 2 }, workspaces: 12, active_entitlements: 96, pending_local_requests: 3, live_subscriptions: 42, active_products: 4, notification_failures: 1, webhook_failures: 0, events_last_24_hours: 185 };
    else if (resource === "management-api") body = { enabled: false, can_manage: true, active_clients: 0, token_endpoint: "https://platform.example.test/oidc/token", api_base: "https://platform.example.test/v1" };
    else if (resource === "auth-policy") body = { email_code_enabled: true, magic_link_enabled: true, password_enabled: true };
    else if (url.pathname.endsWith(`/notification-templates/${template.id}`)) body = template;
    else if (url.pathname.endsWith(`/products/${product.id}`)) body = product;
    else if (url.pathname.endsWith(`/users/${user.id}`)) body = user;
    else if (url.pathname.endsWith(`/workspaces/${workspace.id}`)) body = workspace;
    else if (resource === client.client_id) body = client;
    else {
      const rows: Record<string, unknown[]> = {
        users: [user], workspaces: [workspace], features: [feature], products: [product], clients: [client],
        roles: [{ id: id(10), key: "editor", name: "Editor", scope: "workspace", permissions: ["documents:read", "documents:write"] }],
        "audit-logs": [{ id: id(20), action: "user.updated", actor_type: "user", actor_id: user.id, target_type: "user", target_id: user.id, reason: "Profile corrected", created_at: "2026-10-09T09:30:00Z", changes: { method: "PATCH", path: `/v1/applications/${app.id}/me` } }],
        "role-assignments": [{ id: id(21), user_id: user.id, role_id: id(10), role_key: "editor", role_scope: "workspace", workspace_id: workspace.id, created_at: "2026-10-09T09:30:00Z" }],
        "permission-grants": [{ id: id(22), subject_type: "user", subject_id: user.id, workspace_id: workspace.id, permission: "documents:read", canonical_scope: `/applications/${app.id}/workspaces/${workspace.id}/documents/read`, status: "active", version: 1 }],
        entitlements: [{ id: id(23), subject_type: "user", subject_id: user.id, product_id: product.id, source_type: "manual", expires_at: "2027-01-09T09:30:00Z", created_at: "2026-10-09T09:30:00Z" }],
        events: [{ id: id(24), type: "user.created", subject: `user/${user.id}`, created_at: "2026-10-09T09:30:00Z" }],
        notifications: [{ id: id(25), recipient: "alex@example.test", status: "delivered", attempt_count: 1, created_at: "2026-10-09T09:30:00Z" }],
        invitations: [{ id: id(26), email: "sam@example.test", workspace_id: workspace.id, workspace_role_keys: ["editor"], status: "pending", expires_at: "2026-10-16T09:30:00Z", created_at: "2026-10-09T09:30:00Z" }],
        "webhook-deliveries": [{ id: id(27), webhook_id: id(28), event_id: id(24), status: "failed", attempt_count: 3, response_status: 503, last_error: "Destination unavailable", created_at: "2026-10-09T09:30:00Z" }],
        subscriptions: [{ id: id(40), provider_subscription_id: "sub_example", subject_type: "workspace", subject_id: workspace.id, status: "active", created_at: "2026-10-09T09:30:00Z" }],
        invoices: [{ id: id(41), provider_invoice_id: "in_example", subject_type: "workspace", subject_id: workspace.id, status: "paid", currency: "eur", total_minor: 1900, created_at: "2026-10-09T09:30:00Z" }],
        payments: [{ id: id(42), provider_payment_id: "pi_example", subject_type: "user", subject_id: user.id, status: "succeeded", currency: "eur", amount_minor: 1900, created_at: "2026-10-09T09:30:00Z" }],
        refunds: [{ id: id(43), provider_refund_id: "re_example", status: "succeeded", currency: "eur", amount_minor: 500, created_at: "2026-10-09T09:30:00Z" }],
        disputes: [{ id: id(44), provider_dispute_id: "dp_example", status: "needs_response", currency: "eur", amount_minor: 1900, created_at: "2026-10-09T09:30:00Z" }],
        "provider-events": [{ id: id(45), provider_event_id: "evt_example", event_type: "invoice.paid", status: "processed", created_at: "2026-10-09T09:30:00Z" }],
        "notification-templates": [template],
        "event-types": [{ id: id(11), name: "user.created", description: "An application user was created", source: "platform93", schema_version: "1.0", status: "active", version: 1 }],
      };
      const query = url.searchParams.get("query")?.toLowerCase() ?? "";
      body = { items: (rows[resource] ?? []).filter((entry) => JSON.stringify(entry).toLowerCase().includes(query)), next_cursor: null };
    }
    await route.fulfill({ json: body });
  });
}

test("overview counts and resource rows explain records rather than repeat UUIDs", async ({ page }) => {
  await mock(page);
  await page.goto("/?context=platform&section=overview");
  await expect(page.getByLabel("Example Studio usage")).toContainText("1 active apps");
  await expect(page.getByLabel("Example Studio usage")).toContainText("128 users");
  await page.goto(`/?context=organization&organization_id=${org.id}&section=overview`);
  await expect(page.locator(".application-list")).toContainText("128 active users");
  await expect(page.locator(".application-list")).toContainText("12 workspaces");
  await page.goto(applicationRoute("audit", "audit-logs"));
  const audit = page.locator(".table article").first();
  await expect(audit.locator(".resource-summary strong")).toHaveText("user updated");
  await expect(audit).toContainText("Alex Morgan");
  await expect(audit).toContainText("Profile corrected");
  await expect(audit.locator("time")).toBeVisible();
  await expect(audit.locator("code")).not.toBeVisible();
  await audit.getByText("Record ID", { exact: true }).click();
  await expect(audit.locator("code")).toHaveText(id(20));
  await page.goto(applicationRoute("identity", "role-assignments"));
  await expect(page.locator(".table article").first()).toContainText("editor");
  await expect(page.locator(".table article").first()).toContainText("Alex Morgan");
  await expect(page.locator(".table article").first()).toContainText("Design team");
  await page.goto(applicationRoute("entitlements", "entitlements"));
  await expect(page.locator(".table article").first()).toContainText("Standard");
  await expect(page.locator(".table article").first()).toContainText("Alex Morgan");
  await page.goto(applicationRoute("workspaces", "invitations"));
  await expect(page.locator(".table article").first()).toContainText("sam@example.test");
  await expect(page.locator(".table article").first()).toContainText("Design team");
  await expect(page.locator(".table article").first()).toContainText("editor");
});

test("unavailable references retain meaningful context without hiding rows", async ({ page }) => {
  await mock(page);
  await page.route("**/users?query=**", (route) => route.fulfill({ status: 403, json: { status: 403, title: "Forbidden" } }));
  await page.goto(applicationRoute("identity", "role-assignments"));
  await expect(page.locator(".table article").first()).toContainText("editor");
  await expect(page.locator(".table article").first()).toContainText("user · 00000003");
  await expect(page.locator(".table article").first()).toContainText("Design team");
});

test("audit actor types, delivery failures and billing amounts stay understandable", async ({ page }) => {
  await mock(page);
  await page.route(`**/v1/control/applications/${app.id}/audit-logs`, (route) => route.fulfill({ json: { items: [
    { id: id(30), action: "product.updated", actor_type: "control_user", actor_id: account.id, target_type: "product", target_id: product.id, created_at: "2026-10-09T09:30:00Z" },
    { id: id(31), action: "notification.delivered", actor_type: "system", target_type: "notification", created_at: "2026-10-09T09:31:00Z" },
    { id: id(32), action: "workspace.updated", actor_type: "client", actor_id: client.id, target_type: "workspace", target_id: workspace.id, created_at: "2026-10-09T09:32:00Z" },
  ], next_cursor: "next-page" } }));
  await page.goto(applicationRoute("audit", "audit-logs"));
  const rows = page.locator(".table article");
  await expect(rows.nth(0)).toContainText("Platform user");
  await expect(rows.nth(0)).toContainText("Standard");
  await expect(rows.nth(1)).toContainText("Actor: System");
  await expect(rows.nth(2)).toContainText("Portal browser");
  await expect(rows.nth(2)).toContainText("Design team");
  await expect(page.getByLabel("Loaded records summary")).toContainText("3 loaded · more available");
  await expect(page.locator(".toast-error")).toHaveCount(0);

  await page.route(`**/v1/control/applications/${app.id}/webhook-deliveries`, (route) => route.fulfill({ json: { items: [{ id: id(33), webhook_id: id(34), event_id: id(35), status: "failed", attempt_count: 3, response_status: 503, last_error: "Destination unavailable", created_at: "2026-10-09T09:30:00Z" }], next_cursor: null } }));
  await page.goto(applicationRoute("webhooks", "webhook-deliveries"));
  await expect(rows.first()).toContainText("Webhook delivery");
  await expect(rows.first()).toContainText("HTTP 503");
  await expect(rows.first()).toContainText("3 attempts");
  await expect(rows.first()).toContainText("Destination unavailable");

  await page.route(`**/v1/control/applications/${app.id}/billing/payments`, (route) => route.fulfill({ json: { items: [{ id: id(36), provider_payment_id: "pi_example", subject_type: "user", subject_id: user.id, amount_minor: 1250, currency: "eur", status: "succeeded", created_at: "2026-10-09T09:30:00Z" }], next_cursor: null } }));
  await page.goto(applicationRoute("billing", "billing/payments"));
  await expect(rows.first()).toContainText("pi_example");
  await expect(rows.first()).toContainText("Alex Morgan");
  await expect(rows.first()).toContainText("12.50");
  await expect(rows.first()).not.toContainText("1250");
});

test("controls use floating overlays, stable layout, keyboard selection and form semantics", async ({ page }) => {
  await page.goto("/design-system/");
  const recipientType = page.getByLabel("Recipient type").first();
  const recipient = page.getByRole("combobox", { name: "Recipient", exact: true });
  const before = await recipient.evaluate((element) => element.getBoundingClientRect().top + window.scrollY);
  await chooseSelect(recipientType, "workspace");
  await expect(nativeSelect(recipientType)).toHaveValue("workspace");
  await recipient.fill("Alex");
  await expect(page.getByRole("option")).toHaveCount(2);
  expect(await recipient.evaluate((element) => element.getBoundingClientRect().top + window.scrollY)).toEqual(before);
  const popover = page.locator(".reference-results");
  await expect.poll(() => popover.evaluate((element) => !element.closest("form"))).toBe(true);
  await recipient.press("ArrowDown");
  await recipient.press("Enter");
  await expect(page.getByRole("button", { name: "Remove Alex Morgan" })).toBeVisible();
  await expect(popover).toHaveCount(0);
  await recipient.fill("Sam");
  await expect(popover).toBeVisible();
  await recipient.press("Escape");
  await expect(popover).toHaveCount(0);
  await recipient.click();
  await expect(popover).toBeVisible();
  await page.locator("h1").click();
  await expect(popover).toHaveCount(0);
  await page.getByRole("button", { name: "Save changes", exact: true }).click();
  await expect(page.getByRole("status")).toContainText('"subject_type":"workspace"');
  await page.getByRole("button", { name: "Reset form" }).click();
  await expect(nativeSelect(recipientType)).toHaveValue("user");
  const disabledToggle = page.getByRole("switch", { name: "Preview disabled fieldset" });
  await disabledToggle.focus();
  await disabledToggle.press("Space");
  await expect(disabledToggle).toBeChecked();
  await expect(recipientType).toBeDisabled();
  await expect(recipient).toBeDisabled();
  await page.getByLabel("Preview disabled fieldset").uncheck();
  await expect(recipientType).toBeEnabled();
  await page.getByRole("button", { name: "Validate choice", exact: true }).click();
  const requiredError = page.getByRole("alert").filter({ hasText: "Choose required choice." });
  await expect(requiredError).toBeVisible();
  await chooseSelect(page.getByLabel("Required choice", { exact: true }), "standard");
  await expect(requiredError).toHaveCount(0);
  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(accessibility.violations).toEqual([]);
});

test("admin design gallery", async ({ page }) => {
  test.skip(!process.env.PLATFORM93_DESIGN_GALLERY_DIR, "Enable explicitly when generating the visual review gallery.");
  test.setTimeout(180_000);
  const directory = process.env.PLATFORM93_DESIGN_GALLERY_DIR!;
  await mkdir(directory, { recursive: true });
  await mock(page);
  const captures: { title: string; file: string; width: number; note: string }[] = [];
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  async function capture(title: string, route: string, width = 1440, action?: () => Promise<void>) {
    await page.setViewportSize({ width, height: width < 700 ? 844 : 1000 });
    await page.goto(route);
    if (route === "/design-system/") await expect(page.getByRole("heading", { name: /Calm controls/ })).toBeVisible();
    else await expect(page.locator(".context-picker")).toBeVisible();
    if (action) await action();
    await page.evaluate(() => document.fonts.ready);
    if (route !== "/design-system/") await expect(page.locator('[data-testid="network-activity"]')).not.toHaveAttribute("data-active", "true");
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    const file = `${String(captures.length + 1).padStart(2, "0")}-${title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}-${width}.png`;
    await page.screenshot({ path: path.join(directory, file), fullPage: true, animations: "disabled" });
    captures.push({ title, file, width, note: "Actual static admin with synthetic API fixtures; not a live-provider test." });
  }
  const applicationRoute = (section: string, resource?: string, detail?: string) => `/?context=application&application_id=${app.id}&section=${section}${resource ? `&resource=${resource}` : ""}${detail ? `&id=${detail}` : ""}`;
  await capture("Component foundation", "/design-system/");
  await capture("Component foundation mobile", "/design-system/", 390);
  await capture("Select overlay", "/design-system/", 1440, () => page.getByLabel("Recipient type").first().click());
  await capture("Search overlay", "/design-system/", 1440, async () => { await page.getByRole("combobox", { name: "Recipient", exact: true }).fill("Alex"); await expect(page.getByRole("option")).toHaveCount(2); });
  for (const [context, section] of [["platform", "overview"], ["platform", "platform-users"], ["platform", "identity"], ["platform", "providers"], ["platform", "email"], ["platform", "management-api"], ["organization", "overview"], ["organization", "policy"], ["organization", "providers"]]) {
    await capture(`${context} ${section}`, `/?context=${context}&section=${section}${context === "organization" ? `&organization_id=${org.id}` : ""}`);
  }
  for (const [section, resource] of [["overview"], ["settings"], ["providers"], ["storage"], ["identity", "users"], ["identity", "roles"], ["identity", "role-assignments"], ["identity", "permission-grants"], ["identity", "clients"], ["workspaces", "workspaces"], ["workspaces", "invitations"], ["catalog", "products"], ["catalog", "features"], ["billing", "billing/subscriptions"], ["entitlements", "entitlements"], ["requests", "local-entitlement-requests"], ["notifications", "notification-templates"], ["webhooks", "webhooks"], ["events", "event-types"], ["audit", "audit-logs"], ["operations", "webhook-deliveries"]]) {
    await capture(`Application ${resource ?? section}`, applicationRoute(section!, resource));
  }
  for (const [section, resource] of [["identity", "oauth-consents"], ["identity", "domains"], ["workspaces", "delegations"], ["billing", "billing/invoices"], ["billing", "billing/payments"], ["billing", "billing/refunds"], ["billing", "billing/disputes"], ["billing", "billing/provider-events"], ["billing", "billing/reconciliation-runs"], ["notifications", "notifications"], ["notifications", "sender-identities"], ["webhooks", "webhook-deliveries"], ["events", "events"]]) {
    await capture(`Application ${resource}`, applicationRoute(section!, resource));
  }
  for (const width of [1440, 390]) {
    await capture("Readable audit records", applicationRoute("audit", "audit-logs"), width);
    await capture("Readable role assignments", applicationRoute("identity", "role-assignments"), width);
    await capture("Application access policy", `${applicationRoute("settings")}&panel=settings-internal`, width);
    await capture("Public application configuration", `${applicationRoute("settings")}&panel=settings-public`, width);
    await capture("Social provider configuration", `${applicationRoute("providers")}&panel=provider-apple`, width, async () => { await expect(page.getByLabel("Team ID", { exact: true })).toBeVisible(); });
    await capture("SMTP configuration", `/?context=platform&section=providers&panel=provider-smtp`, width, async () => { await expect(page.getByLabel("TLS", { exact: true })).toBeVisible(); });
    await capture("Storage provider configuration", `${applicationRoute("providers")}&panel=provider-storage`, width, async () => { await expect(page.getByLabel("Region", { exact: true })).toBeVisible(); });
    await capture("Manual grant form", applicationRoute("entitlements", "entitlements"), width, () => page.getByRole("button", { name: "Grant entitlement", exact: true }).click());
    await capture("Manual grant search", applicationRoute("entitlements", "entitlements"), width, async () => { await page.getByRole("button", { name: "Grant entitlement", exact: true }).click(); await page.getByRole("combobox", { name: "Recipient", exact: true }).fill("Alex"); await expect(page.locator(".reference-results .ui-option")).toContainText("Alex Morgan"); });
    await capture("OAuth client drawer", applicationRoute("identity", "clients", client.client_id), width, async () => { await expect(page.getByRole("dialog")).toBeVisible(); });
    await capture("Role assignment form", applicationRoute("identity", "role-assignments"), width, () => page.getByRole("button", { name: "Assign role", exact: true }).click());
    await capture("Product configuration drawer", applicationRoute("catalog", "products", product.id), width, async () => { await expect(page.getByRole("dialog")).toBeVisible(); });
    await capture("User detail drawer", applicationRoute("identity", "users", user.id), width, async () => { await expect(page.getByRole("dialog")).toBeVisible(); });
    await capture("Workspace detail drawer", applicationRoute("workspaces", "workspaces", workspace.id), width, async () => { await expect(page.getByRole("dialog")).toBeVisible(); });
    await capture("Email template editor", applicationRoute("notifications", "notification-templates", template.id), width);
    await capture("Platform account", `/?context=platform&section=overview&panel=account`, width);
    await capture("Application settings", applicationRoute("settings"), width);
  }
  await page.unroute("**/v1/**");
  await mock(page, "login");
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: width < 700 ? 844 : 1000 });
    await page.goto("/");
    await expect(page.getByRole("button", { name: "Google", exact: true })).toBeVisible();
    const file = `login-${width}.png`;
    await page.screenshot({ path: path.join(directory, file), fullPage: true, animations: "disabled" });
    captures.push({ title: "Platform sign in", file, width, note: "Synthetic available-provider configuration." });
  }
  expect(errors).toEqual([]);
  await writeFile(path.join(directory, "manifest.json"), JSON.stringify(captures, null, 2));
  const cards = captures.map((entry) => `<a class="shot" href="${entry.file}" target="_blank"><img src="${entry.file}" loading="lazy" alt="${entry.title}"><strong>${entry.title}</strong><small>${entry.width}px</small></a>`).join("");
  await writeFile(path.join(directory, "index.html"), `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Platform93 design review</title><style>*{box-sizing:border-box}body{margin:0;background:#f6f8fb;color:#101623;font:15px system-ui}header{background:#101623;color:white;padding:40px}header span{color:#3be8a0}h1{font-size:38px;margin:12px 0}p{max-width:850px;line-height:1.6;color:#b9c4d4}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:24px;padding:32px}.shot{display:block;color:inherit;text-decoration:none;background:white;border:1px solid #dce3ec;border-radius:8px;overflow:hidden}.shot img{width:100%;height:230px;object-fit:cover;object-position:top;border-bottom:1px solid #dce3ec}.shot strong,.shot small{display:block;margin:14px 16px}.shot small{color:#4a576d}.shot:hover{outline:2px solid #176b4a}footer{padding:24px 32px;color:#4a576d}</style><header><span>PLATFORM93 / DESIGN REVIEW</span><h1>One visual language. Every boundary.</h1><p>Component foundations, floating selectors, forms, and the full admin surface. Click any screenshot to inspect the original. All accounts and records are synthetic; these captures verify UI rendering, not live provider integrations.</p></header><main class="grid">${cards}</main><footer>${captures.length} captures · desktop 1440px · mobile 390px</footer></html>`);
});
