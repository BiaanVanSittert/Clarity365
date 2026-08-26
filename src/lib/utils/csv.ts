// Shared CSV export helper used by every module's "Export CSV" button.
// Handles CSV field quoting/escaping and the Blob + temporary-<a> download
// dance so each module only needs to supply its headers and row data.

// Formula-injection guard (OWASP CSV Injection): a leading =, +, -, @, tab, or
// CR makes Excel/Sheets interpret the cell as a formula when the file is
// opened. Several exports include attacker-influenced text verbatim (e.g.
// MDO's TABL indicator values and threat-alert titles), so every export goes
// through this regardless of source.
const FORMULA_TRIGGER_RE = /^[=+\-@\t\r]/;

function escapeCsvField(value: string | number): string {
  let str = String(value);
  if (FORMULA_TRIGGER_RE.test(str)) str = `'${str}`;
  // Always quote — simplest way to safely handle commas, quotes, and
  // newlines in free-text fields (detail messages, display names, etc.).
  return `"${str.replace(/"/g, '""')}"`;
}

export function exportToCsv(filename: string, headers: string[], rows: (string | number)[][]): void {
  const csvContent = [
    headers.map(escapeCsvField).join(","),
    ...rows.map((row) => row.map(escapeCsvField).join(",")),
  ].join("\n");

  const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.setAttribute("href", url);
  link.setAttribute("download", filename);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

// Standard filename convention used across every module's export button.
export function csvFilename(moduleLabel: string, tenantDomain: string): string {
  return `Clarity365_${moduleLabel}_${tenantDomain}_${new Date().toISOString().split("T")[0]}.csv`;
}
