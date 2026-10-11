import { chromium, expect, test } from "@playwright/test";

test("stock Postal OIDC accepts an existing user and rejects an unknown local user", async () => {
  test.skip(!process.env.PLATFORM93_POSTAL_URL, "Run the opt-in disposable Postal compatibility fixture.");
  test.setTimeout(120_000);
  const browser = await chromium.launch({ args: ["--host-resolver-rules=MAP host.docker.internal 127.0.0.1"] });
  try {
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();
    const postal = process.env.PLATFORM93_POSTAL_URL!;
    await expect(async () => { const result = await page.request.get(`${postal}/login`); expect(result.ok()).toBe(true); }).toPass({ timeout: 60_000 });
    await page.goto(`${postal}/login`);
    await page.getByRole("link", { name: "Login with Platform93", exact: true }).click();
    await expect(page).toHaveURL(/\/auth\/\?interaction=/);
    await page.getByRole("button", { name: "Password", exact: true }).click();
    await page.getByLabel("Email address").fill(process.env.PLATFORM93_HOSTED_EMAIL!);
    await page.getByLabel("Password", { exact: true }).fill("A disposable test password!");
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await expect(page.getByText("Signed in as")).toBeVisible();
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await expect(page).toHaveURL(`${postal}/`);
    await expect(page.getByText("No user was found matching your identity.")).toHaveCount(0);
    // Postal's stock entry point requires a CSRF-protected POST, so repeat through
    // its login page after discarding only the relying-party session cookie.
    await context.clearCookies({ domain: "localhost" });
    await page.goto(`${postal}/login`);
    await page.getByRole("link", { name: "Login with Platform93", exact: true }).click();
    await expect(page).toHaveURL(`${postal}/`);
    await context.close();

    const unknownContext = await browser.newContext({ ignoreHTTPSErrors: true });
    const unknownPage = await unknownContext.newPage();
    await unknownPage.goto(`${postal}/login`);
    await unknownPage.getByRole("link", { name: "Login with Platform93", exact: true }).click();
    await unknownPage.getByRole("button", { name: "Password", exact: true }).click();
    await unknownPage.getByLabel("Email address").fill(process.env.PLATFORM93_POSTAL_UNKNOWN_EMAIL!);
    await unknownPage.getByLabel("Password", { exact: true }).fill("A disposable test password!");
    await unknownPage.getByRole("button", { name: "Continue", exact: true }).click();
    await expect(unknownPage.getByText("Signed in as")).toBeVisible();
    await unknownPage.getByRole("button", { name: "Continue", exact: true }).click();
    await expect(unknownPage.getByText("No user was found matching your identity. Please contact your administrator.")).toBeVisible();
    await unknownContext.close();
  } finally { await browser.close(); }
});
