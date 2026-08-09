import { defineConfig } from "@hey-api/openapi-ts";

export default defineConfig({
  input: "../../../api/openapi/platform93.yaml",
  output: "src/generated",
});
