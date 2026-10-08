import { expect, test, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { calendarExpiry } from "../app/manual-grant-form";

const id = (value: number) => `01900000-0000-7000-8000-${value.toString().padStart(12, "0")}`;
const organization = { id: id(1), name: "Reference Org", slug: "references", role: "owner" };
const application = { id: id(2), organization_id: organization.id, name: "Reference App", slug: "references", issuer: "http://localhost:8093/oidc" };
const user = { id: id(3), email: "alex@example.test", first_name: "Alex", last_name: "Example", status: "active" };
const workspace = { id: id(4), key: "team", name: "Team", owner_user_id: user.id };
const appRole = { id: id(5), key: "reader", name: "Reader", scope: "application" };
const workspaceRole = { id: id(6), key: "editor", name: "Editor", scope: "workspace" };
const client = { id: id(7), client_id: "service", name: "Service", client_type: "machine" };
const feature = { id: id(8), key: "projects", name: "Projects", value_type: "quantity" };
const price = { id: id(9), key: "monthly", active: true, mode: "recurring", amount_minor: 1000, currency: "EUR", currency_exponent: 2, entitlement_config: { support: "priority" }, features: [{ feature_id: feature.id, quantity_value: 10 }] };
const product = { id: id(10), name: "Standard", key: "standard", status: "active", entitlement_config: { support: "basic" }, features: [{ feature_id: feature.id, quantity_value: 5 }], prices: [price] };

async function setup(page: Page) {
  await page.route("**/version", (route) => route.fulfill({ json: { version: "dev" } }));
  await page.route("https://api.github.com/**", (route) => route.fulfill({ status: 503 }));
  await page.route("**/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let body: unknown = { items: [], next_cursor: null };
    if (path === "/v1/setup/status") body = { available: false };
    else if (path === "/v1/control/organizations") body = { items: [organization], installation_role: "owner", next_cursor: null };
    else if (path === `/v1/control/organizations/${organization.id}/applications`) body = { items: [application], next_cursor: null };
    else if (path === `/v1/control/applications/${application.id}`) body = application;
    else {
      const resources: Record<string, unknown[]> = { users: [user], workspaces: [workspace], roles: [appRole, workspaceRole], clients: [client], features: [feature], products: [product] };
      const resource = path.split("/").at(-1)!;
      body = { items: resources[resource] ?? [], next_cursor: null };
    }
    await route.fulfill({ json: body });
  });
}
async function select(page: Page, label: string, option: string) {
  const input = page.getByRole("combobox", { name: label, exact: true });
  await input.fill(option);
  await page.getByRole("option").filter({ hasText: option }).first().click();
}
async function navigate(page: Page, section: string, resource: string) {
  await page.goto(`/?context=application&application_id=${application.id}&section=${section}&resource=${resource}`);
}

test("role assignment selects user/client, role scope and workspace without UUID typing", async ({ page }) => {
  await setup(page);
  const requests: Record<string, unknown>[] = [];
  await page.route("**/role-assignments", async (route) => {
    if (route.request().method() === "POST") requests.push(route.request().postDataJSON());
    await route.fulfill({ json: { items: [], next_cursor: null } });
  });
  await navigate(page, "identity", "role-assignments");
  await page.getByRole("button", { name: "Assign role", exact: true }).click();
  await select(page, "User", "Alex");
  await select(page, "Role", "Reader");
  await expect(page.getByRole("combobox", { name: "Workspace", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Assign role", exact: true }).click();
  await expect.poll(() => requests.length).toBe(1);
  expect(requests[0]).toEqual({ user_id: user.id, role_id: appRole.id });
  await page.getByRole("button", { name: "Assign role", exact: true }).click();
  await page.getByLabel("Recipient type").selectOption("client");
  await select(page, "Machine client", "Service");
  await select(page, "Role", "Editor");
  await select(page, "Workspace", "Team");
  await page.getByRole("button", { name: "Assign role", exact: true }).click();
  await expect.poll(() => requests.length).toBe(2);
  expect(requests[1]).toEqual({ client_id: client.id, role_id: workspaceRole.id, workspace_id: workspace.id });
});

test("manual grant loads defaults, overrides configuration and requires chosen expiry", async ({ page }) => {
  await setup(page);
  let submitted: Record<string, unknown> | undefined;
  await page.route("**/entitlements", async (route) => {
    if (route.request().method() === "POST") submitted = route.request().postDataJSON();
    await route.fulfill({ json: { items: [], next_cursor: null } });
  });
  await navigate(page, "entitlements", "entitlements");
  await page.getByRole("button", { name: "Grant entitlement", exact: true }).click();
  await select(page, "Recipient", "Alex");
  await select(page, "Product", "Standard");
  await expect(page.getByLabel("Projects (projects)")).toHaveValue("5");
  await page.getByLabel("Price", { exact: true }).selectOption(price.id);
  await expect(page.getByLabel("Projects (projects)")).toHaveValue("10");
  await expect(page.getByLabel("Configuration (JSON object)")).toHaveValue(/priority/);
  await expect(page.getByLabel("Expires at")).toHaveValue("");
  await page.getByRole("button", { name: "3 months", exact: true }).click();
  await page.getByLabel("Projects (projects)").fill("42");
  await page.getByLabel("Configuration (JSON object)").fill('{"support":"custom"}');
  await page.getByRole("button", { name: "Review grant", exact: true }).click();
  await expect(page.getByRole("region", { name: "Grant review" })).toContainText("42");
  await page.getByRole("button", { name: "Confirm grant", exact: true }).click();
  await expect.poll(() => submitted?.subject_id).toBe(user.id);
  expect(submitted).toMatchObject({ product_id: product.id, price_id: price.id, feature_values: { projects: 42 }, configuration: { support: "custom" } });
  expect(new Date(String(submitted?.expires_at)).getTime()).toBeGreaterThan(Date.now());
  await expect(page.getByText("Entitlement granted. No payment or automatic renewal was created.")).toBeVisible();
});

test("workspace invitation uses role key multiselects and scoped workspace search", async ({ page }) => {
  await setup(page);
  let submitted: Record<string, unknown> | undefined;
  await page.route("**/invitations", async (route) => {
    if (route.request().method() === "POST") submitted = route.request().postDataJSON();
    await route.fulfill({ json: { items: [], next_cursor: null } });
  });
  await navigate(page, "workspaces", "invitations");
  await page.getByRole("button", { name: "Create invitation", exact: true }).click();
  await page.getByLabel("Email", { exact: true }).fill("invited@example.test");
  await select(page, "Workspace", "Team");
  await select(page, "Application roles", "Reader");
  await select(page, "Workspace roles", "Editor");
  await page.getByRole("button", { name: "Create invitation", exact: true }).click();
  await expect.poll(() => submitted?.workspace_id).toBe(workspace.id);
  expect(submitted).toMatchObject({ application_role_keys: ["reader"], workspace_role_keys: ["editor"] });
});

test("picker supports pagination, exact ID search, keyboard and mobile accessibility", async ({ page }) => {
  await setup(page);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.route("**/users?**", async (route) => {
    const url = new URL(route.request().url());
    const second = { ...user, id: id(30), email: "second@example.test" };
    const isSecond = url.searchParams.has("cursor") || url.searchParams.get("query") === second.id;
    await route.fulfill({ json: { items: [isSecond ? second : user], next_cursor: isSecond ? null : user.id } });
  });
  await navigate(page, "workspaces", "workspaces");
  await page.getByRole("button", { name: "Create workspace", exact: true }).click();
  const picker = page.getByRole("combobox", { name: "Owner", exact: true });
  await picker.click();
  await page.getByRole("button", { name: "Load more results" }).click();
  await expect(page.locator('.reference-results [role="option"]')).toHaveCount(2);
  await picker.fill(id(30));
  await expect(page.locator('.reference-results [role="option"]')).toHaveCount(1);
  await picker.press("Enter");
  await expect(page.locator('input[name="owner_user_id"]')).toHaveValue(id(30));
  await picker.press("Escape");
  const accessibility = await new AxeBuilder({ page }).include(".create-panel").analyze();
  expect(accessibility.violations).toEqual([]);
});

test("calendar quick fills clamp month ends and preserve local wall-clock time", () => {
  const january = new Date(2028, 0, 31, 14, 30);
  const february = calendarExpiry(january, 1);
  expect([february.getFullYear(), february.getMonth(), february.getDate(), february.getHours()]).toEqual([2028, 1, 29, 14]);
  const nextYear = calendarExpiry(new Date(2028, 1, 29, 10), 12);
  expect([nextYear.getFullYear(), nextYear.getMonth(), nextYear.getDate()]).toEqual([2029, 1, 28]);
});

test("direct scopes use recipient/workspace selection and effective-access IDs", async ({ page }) => {
  await setup(page);
  let submitted: Record<string, unknown> | undefined;
  await page.route("**/permission-grants", async (route) => {
    if (route.request().method() === "POST") submitted = route.request().postDataJSON();
    await route.fulfill({ json: { items: [], next_cursor: null } });
  });
  await page.route("**/permission-grants/effective?**", async (route) => {
    const params = new URL(route.request().url()).searchParams;
    expect(params.get("subject_id")).toBe(user.id);
    expect(params.get("workspace_id")).toBe(workspace.id);
    await route.fulfill({ json: { roles: { application: [], workspaces: {} }, scopes: [], provenance: [] } });
  });
  await navigate(page, "identity", "permission-grants");
  await select(page, "Recipient", "Alex");
  await select(page, "Workspace (optional)", "Team");
  await page.getByLabel("Permission segments").fill("documents:read");
  await page.getByRole("button", { name: "View effective access" }).click();
  await page.getByRole("button", { name: "Grant direct scope" }).click();
  await expect.poll(() => submitted?.subject_id).toBe(user.id);
  expect(submitted).toMatchObject({ subject_type: "user", workspace_id: workspace.id, permission: "documents:read" });
  await page.getByLabel("Subject type").selectOption("client");
  await expect(page.getByRole("button", { name: "View effective access" })).toBeDisabled();
});

test("typed but unselected references never submit, failed searches retry", async ({ page }) => {
  await setup(page);
  let failed = true;
  let created = false;
  await page.route("**/users?**", (route) => route.fulfill(failed ? { status: 503, json: { title: "Unavailable", status: 503, detail: "Try again." } } : { json: { items: [user], next_cursor: null } }));
  await page.route("**/workspaces", (route) => {
    if (route.request().method() === "POST") created = true;
    return route.fulfill({ json: { items: [], next_cursor: null } });
  });
  await navigate(page, "workspaces", "workspaces");
  await page.getByRole("button", { name: "Create workspace", exact: true }).click();
  const owner = page.getByRole("combobox", { name: "Owner", exact: true });
  await owner.fill("Alex");
  await expect(page.getByRole("button", { name: "Retry search" })).toBeVisible();
  await page.getByLabel("Key", { exact: true }).fill("new-team");
  await page.getByLabel("Name", { exact: true }).fill("New team");
  await page.getByRole("button", { name: "Create workspace", exact: true }).click();
  expect(created).toBe(false);
  failed = false;
  await page.getByRole("button", { name: "Retry search" }).click();
  await page.locator('.reference-results [role="option"]').first().click();
  await page.getByRole("button", { name: "Create workspace", exact: true }).click();
  await expect.poll(() => created).toBe(true);
});

test("workspace members and ownership recovery use user and role searches", async ({ page }) => {
  await setup(page);
  await page.route(`**/workspaces/${workspace.id}`, (route) => route.fulfill({ json: workspace }));
  let member: Record<string, unknown> | undefined;
  let transfer: Record<string, unknown> | undefined;
  await page.route(`**/workspaces/${workspace.id}/members/${user.id}`, async (route) => {
    member = route.request().postDataJSON(); await route.fulfill({ json: {} });
  });
  await page.route(`**/workspaces/${workspace.id}/owner-transfer`, async (route) => {
    transfer = route.request().postDataJSON(); await route.fulfill({ json: {} });
  });
  await page.goto(`/?context=application&application_id=${application.id}&section=workspaces&resource=workspaces&id=${workspace.id}`);
  await select(page, "Member", "Alex");
  await select(page, "Workspace roles", "Editor");
  await page.getByRole("button", { name: "Apply roles" }).click();
  await expect.poll(() => member?.role_keys).toEqual(["editor"]);
  await select(page, "New owner", "Alex");
  await page.getByRole("button", { name: "Transfer ownership" }).click();
  await expect.poll(() => transfer?.new_owner_user_id).toBe(user.id);
});

test("abandoned search responses cannot replace a newer query", async ({ page }) => {
  await setup(page);
  let release: (() => void) | undefined;
  let started = false;
  await page.route("**/users?**", async (route) => {
    const query = new URL(route.request().url()).searchParams.get("query");
    if (query === "old") { started = true; await new Promise<void>((resolve) => { release = resolve; }); }
    await route.fulfill({ json: { items: [{ ...user, first_name: query === "old" ? "Old result" : "New result" }], next_cursor: null } });
  });
  await navigate(page, "workspaces", "workspaces");
  await page.getByRole("button", { name: "Create workspace", exact: true }).click();
  const picker = page.getByRole("combobox", { name: "Owner", exact: true });
  await picker.fill("old");
  await expect.poll(() => started).toBe(true);
  await picker.fill("new");
  await expect(page.locator('.reference-results [role="option"]')).toContainText("New result");
  release!();
  await expect(page.locator('.reference-results [role="option"]')).toContainText("New result");
  await expect(page.getByText("Old result", { exact: true })).toHaveCount(0);
});

test("editing a grant cannot change catalog selection without confirming reset", async ({ page }) => {
  await setup(page);
  await navigate(page, "entitlements", "entitlements");
  await page.getByRole("button", { name: "Grant entitlement", exact: true }).click();
  await select(page, "Product", "Standard");
  await page.getByLabel("Projects (projects)").fill("42");
  page.once("dialog", (dialog) => dialog.dismiss());
  await page.getByLabel("Price", { exact: true }).selectOption(price.id);
  await expect(page.getByLabel("Price", { exact: true })).toHaveValue("");
  await expect(page.getByLabel("Projects (projects)")).toHaveValue("42");
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByLabel("Price", { exact: true }).selectOption(price.id);
  await expect(page.getByLabel("Projects (projects)")).toHaveValue("10");
  await page.getByLabel("Configuration (JSON object)").fill("[]");
  await expect(page.getByRole("alert").filter({ hasText: "Enter a JSON object." })).toBeVisible();
  await expect(page.getByRole("button", { name: "Review grant" })).toBeDisabled();
});

test("free-form grants preserve empty text and validate JSON before review", async ({ page }) => {
  await setup(page);
  const notes = { id: id(11), key: "notes", name: "Notes", value_type: "free_form", free_form_format: "text" };
  const settings = { id: id(12), key: "settings", name: "Settings", value_type: "free_form", free_form_format: "json" };
  await page.route("**/features", (route) => route.fulfill({ json: { items: [feature, notes, settings], next_cursor: null } }));
  await page.route("**/products?**", (route) => route.fulfill({ json: { items: [{ ...product, features: [...product.features, { feature_id: notes.id, free_form_value: "" }, { feature_id: settings.id, free_form_value: { enabled: true } }] }], next_cursor: null } }));
  let submitted: Record<string, unknown> | undefined;
  await page.route("**/entitlements", async (route) => {
    if (route.request().method() === "POST") submitted = route.request().postDataJSON();
    await route.fulfill({ json: { items: [], next_cursor: null } });
  });
  await navigate(page, "entitlements", "entitlements");
  await page.getByRole("button", { name: "Grant entitlement", exact: true }).click();
  await select(page, "Recipient", "Alex");
  await select(page, "Product", "Standard");
  await expect(page.getByLabel("Include Notes")).toBeChecked();
  await page.getByRole("button", { name: "1 month", exact: true }).click();
  await page.getByLabel("Settings (settings)").fill("broken");
  await expect(page.getByLabel("Settings (settings)")).toHaveAttribute("aria-invalid", "true");
  await page.getByRole("button", { name: "Review grant", exact: true }).click();
  await expect(page.getByRole("button", { name: "Confirm grant" })).toHaveCount(0);
  await page.getByLabel("Settings (settings)").fill('{"enabled":false}');
  await page.getByRole("button", { name: "Review grant", exact: true }).click();
  await page.getByRole("button", { name: "Confirm grant", exact: true }).click();
  await expect.poll(() => submitted?.feature_values).toEqual({ projects: 5, notes: "", settings: { enabled: false } });
});
