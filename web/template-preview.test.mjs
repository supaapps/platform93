import assert from "node:assert/strict";
import test from "node:test";
import { renderTemplatePreview } from "./app/template-preview.mjs";

const template = '{{#if code}}Code: {{code}}{{/if}}{{#if magic_link}}<a href="{{magic_link}}">Continue</a>{{/if}}';
test("email preview agrees with code, link and combined delivery", () => {
  assert.equal(renderTemplatePreview(template, { code: "AB12CD34", magic_link: "" }, true), "Code: AB12CD34");
  assert.equal(renderTemplatePreview(template, { code: "", magic_link: "https://app.example?a=1&b=2" }, true), '<a href="https://app.example?a=1&amp;b=2">Continue</a>');
  assert.equal(renderTemplatePreview(template, { code: "AB12CD34", magic_link: "https://app.example" }, true), 'Code: AB12CD34<a href="https://app.example">Continue</a>');
});
test("preview validates nesting and does not execute substituted directives", () => {
  assert.equal(renderTemplatePreview("{{#if a}}x{{#if b}}y{{/if}}{{/if}}!", { a: false, b: true }), "!");
  for (const source of ["{{/if}}", "{{#if a}}", "{{#if unknown}}x{{/if}}", "{{#if a b}}x{{/if}}", "{{#if a}}".repeat(17) + "{{/if}}".repeat(17)]) {
    assert.match(renderTemplatePreview(source, { a: true }), /^Invalid template:/);
  }
  assert.equal(renderTemplatePreview("{{code}}", { code: "{{#if unknown}}<script>{{/if}}" }, true), "{{#if unknown}}&lt;script&gt;{{/if}}");
});
