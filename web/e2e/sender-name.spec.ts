import { expect, test } from "@playwright/test";
import { AxeBuilder } from "@axe-core/playwright";

test("edits and resets an app sender without changing inherited SMTP", async ({ page }) => {
  const organizationID = "01900000-0000-7000-8000-000000000201";
  const applicationID = "01900000-0000-7000-8000-000000000202";
  const base = `/v1/control/applications/${applicationID}`;
  const updates: { body: unknown; version: string | undefined }[] = [];
  let failSave = false;
  let providerWrites = 0;
  let application = {
    id: applicationID, organization_id: organizationID, name: "Sender Application", slug: "sender-app", version: 1,
    auth_config: {}, internal_config: { email_sender_name: "", registration_mode: "invite_only" },
  };
  await page.route("**/v1/setup/status", (route) => route.fulfill({ json: { available: false, control_user_email_login_available: false } }));
  await page.route("**/v1/control/organizations?*", (route) => route.fulfill({ json: { items: [{ id: organizationID, name: "Organization", role: "owner" }], installation_role: "owner" } }));
  await page.route(`**/v1/control/organizations/${organizationID}/applications?*`, (route) => route.fulfill({ json: { items: [application] } }));
  await page.route(`**${base}/**`, (route) => route.fulfill({ json: { items: [], next_cursor: null } }));
  await page.route(`**${base}`, (route) => route.fulfill({ json: application }));
  await page.route(`**${base}/notification-providers`, async (route) => {
    if (route.request().method() !== "GET") providerWrites++;
    await route.fulfill({ json: { items: [{ id: "01900000-0000-7000-8000-000000000203", provider: "smtp", name: "Shared SMTP", sender_name: "Shared Team", sender_email: "noreply@example.test", scope: "installation", inheritable: true }] } });
  });
  await page.route(`**${base}/internal-config`, async (route) => {
    updates.push({ body: route.request().postDataJSON(), version: route.request().headers()["if-match"] });
    if (failSave) {
      await route.fulfill({ status: 412, contentType: "application/problem+json", json: { code: "precondition_failed", detail: "The application changed. Reload before saving.", status: 412 } });
      return;
    }
    const body = route.request().postDataJSON() as { email_sender_name: string };
    application = { ...application, version: application.version + 1, internal_config: { ...application.internal_config, ...body } };
    await route.fulfill({ status: 204 });
  });
  await page.goto(`/?context=application&organization_id=${organizationID}&application_id=${applicationID}&section=providers`);
  const form = page.getByRole("region", { name: "Application email sender", exact: true });
  const input = form.getByLabel("App sender name");
  await expect(input).toBeEnabled();
  await expect(page.getByText("Shared SMTP", { exact: true })).toBeVisible();
  await input.fill("App Support");
  await form.getByRole("button", { name: "Save sender name", exact: true }).click();
  await expect(page.locator(".toast-success")).toContainText("Application email sender name saved");
  await expect.poll(() => updates[0]).toEqual({ body: { email_sender_name: "App Support" }, version: '"v1"' });
  await page.reload();
  await expect(input).toHaveValue("App Support");
  await expect(input).toBeEnabled();
  await page.setViewportSize({ width: 390, height: 844 });
  await input.fill("");
  await form.getByRole("button", { name: "Save sender name", exact: true }).click();
  await expect.poll(() => updates[1]).toEqual({ body: { email_sender_name: "" }, version: '"v2"' });
  await expect(page.locator(".toast-success")).toContainText("reset to the provider default");
  await expect(input).toBeEnabled();
  failSave = true;
  await input.fill("Keep my unsaved name");
  await form.getByRole("button", { name: "Save sender name", exact: true }).click();
  await expect(page.locator(".toast-error")).toContainText("The application changed");
  await expect(input).toHaveValue("Keep my unsaved name");
  await form.getByRole("button", { name: "Reload sender settings" }).click();
  await expect(input).toHaveValue("");
  expect(providerWrites).toBe(0);
  expect(application.internal_config.registration_mode).toBe("invite_only");
  const accessibility = await new AxeBuilder({ page }).include('[aria-label="Application email sender"]').analyze();
  expect(accessibility.violations.filter((item) => item.impact === "critical" || item.impact === "serious")).toEqual([]);
});
