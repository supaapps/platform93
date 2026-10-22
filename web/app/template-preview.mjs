/**
 * @param {string} source
 * @param {Record<string, unknown>} values
 * @param {boolean} escapeHTML
 */
export function renderTemplatePreview(source, values, escapeHTML = false) {
  const active = [true];
  let output = "";
  let position = 0;
  for (const match of source.matchAll(/{{\s*(#if\b[^{}]*|\/if\s*)}}/g)) {
    if (active.at(-1)) output += source.slice(position, match.index);
    const tag = match[1].trim();
    if (tag === "/if") {
      if (active.length === 1) return "Invalid template: unmatched conditional.";
      active.pop();
    } else {
      const name = tag.slice(3).trim();
      if (!/^[A-Za-z][A-Za-z0-9_.-]{0,100}$/.test(name) || active.length > 16 || !(name in values)) return "Invalid template: conditional variable or nesting.";
      const value = values[name];
      const present = typeof value === "boolean" ? value : String(value ?? "").trim() !== "";
      active.push(Boolean(active.at(-1) && present));
    }
    position = match.index + match[0].length;
  }
  if (active.length !== 1) return "Invalid template: unclosed conditional.";
  output += source.slice(position);
  return output.replace(/{{\s*([A-Za-z][A-Za-z0-9_.-]{0,100})\s*}}/g, (_token, key) => {
    const raw = values[key] === undefined ? `{{${key}}}` : String(values[key]).trim();
    return escapeHTML ? raw.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#039;") : raw;
  });
}
