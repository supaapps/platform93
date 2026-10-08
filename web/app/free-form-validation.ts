import Papa from "papaparse";

export function validateFreeFormInput(format: "text" | "csv" | "json", raw: string): string {
  if (!raw.trim() || format === "text") return "";
  if (format === "json") {
    try {
      JSON.parse(raw);
      return "";
    } catch (error) {
      return error instanceof SyntaxError ? error.message : "Enter valid JSON.";
    }
  }
  const parsed = Papa.parse<string[]>(raw, { skipEmptyLines: "greedy" });
  if (parsed.errors.length > 0) {
    const issue = parsed.errors[0]!;
    return `CSV row ${issue.row === undefined ? 1 : issue.row + 1}: ${issue.message}`;
  }
  const rows = parsed.data.filter((row) => row.length > 0);
  const expectedColumns = rows[0]?.length ?? 0;
  const inconsistentRow = rows.findIndex((row) => row.length !== expectedColumns);
  return inconsistentRow === -1 ? "" : `CSV row ${inconsistentRow + 1} has ${rows[inconsistentRow]!.length} columns; expected ${expectedColumns}.`;
}
