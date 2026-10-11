import { expect, type Locator } from "@playwright/test";

/** Exercise the visible overlay rather than manipulating the hidden form select. */
export async function chooseSelect(control: Locator, selection: string | { label: string }) {
  control = control.first();
  const root = control.locator('xpath=ancestor-or-self::div[contains(concat(" ",normalize-space(@class)," ")," ui-select ")][1]');
  const native = root.locator("select.ui-native-select");
  const value = await native.evaluate((element, wanted) => {
    const options = Array.from((element as HTMLSelectElement).options);
    return options.find((option) => typeof wanted === "string" ? option.value === wanted : option.label === wanted.label)?.value;
  }, selection);
  expect(value, "Selection must resolve to an existing option").toBeDefined();
  await root.locator(".ui-select-trigger").click();
  await control.page().locator(`.ui-popover [role="option"][data-value=${JSON.stringify(value)}]`).click();
}

export function nativeSelect(control: Locator) {
  return control.first().locator('xpath=ancestor-or-self::div[contains(concat(" ",normalize-space(@class)," ")," ui-select ")][1]').locator("select.ui-native-select");
}
