// Writes a plain JSON-style value as a PowerShell literal (hashtables, arrays,
// strings, numbers, booleans, $null). The fix guides build each Conditional
// Access policy once as an object; this turns that same object into the
// command the operator runs, so the command and Clarity365's impact preview
// can never describe two different policies.

const SIMPLE_KEY = /^[A-Za-z_][A-Za-z0-9_]*$/;

function quoteString(value: string): string {
  // Single-quoted PowerShell strings are literal; a quote is escaped by doubling it.
  return `'${value.replace(/'/g, "''")}'`;
}

function quoteKey(key: string): string {
  return SIMPLE_KEY.test(key) ? key : `"${key.replace(/"/g, '`"')}"`;
}

export function toPowerShell(value: unknown, indent = 0): string {
  const pad = "    ".repeat(indent);
  const inner = "    ".repeat(indent + 1);
  if (value === null || value === undefined) return "$null";
  if (typeof value === "boolean") return value ? "$true" : "$false";
  if (typeof value === "number") return Number.isFinite(value) ? String(value) : "$null";
  if (typeof value === "string") return quoteString(value);
  if (Array.isArray(value)) {
    if (value.length === 0) return "@()";
    if (value.every((v) => typeof v !== "object" || v === null)) return `@(${value.map((v) => toPowerShell(v)).join(", ")})`;
    return `@(\n${value.map((v) => inner + toPowerShell(v, indent + 1)).join("\n")}\n${pad})`;
  }
  const entries = Object.entries(value as Record<string, unknown>).filter(([, v]) => v !== undefined);
  if (entries.length === 0) return "@{}";
  return `@{\n${entries.map(([k, v]) => `${inner}${quoteKey(k)} = ${toPowerShell(v, indent + 1)}`).join("\n")}\n${pad}}`;
}
