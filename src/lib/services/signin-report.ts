import { SignInCoverage, SignInEvent, TenantSecuritySnapshot } from "../types";
import { UNKNOWN_COUNTRY, detectMostCommonCountry, getCountryDisplayName, normalizeCountryCode } from "../utils/sign-in-country";
import { describeSignInCoverage, getSignInCoverage } from "../utils/sign-in-coverage";
import { describeSignInAuthentication } from "../utils/sign-in-authentication";
import { isIpInCidr } from "../utils/ip-range";

// Sign-in report: one tenant's synced sign-ins summarised by country, IP
// address, user, MFA method, app, client and device, plus a short list of
// things worth a second look. Pure - everything comes from the snapshot, so
// it works on demo tenants and never calls Microsoft. The module renders it
// (SignInReportModal), exports each table as CSV and prints it via
// renderSignInReportHtml().
//
// The report is only as complete as the synced sign-ins: `coverage` says
// which period they cover and is printed on the report.

export interface SignInReportOptions {
  // Only sign-ins from the last N days (counted back from `now`). Omit for everything synced.
  days?: number;
  // Only users whose UPN or display name contains this text.
  user?: string;
  // The tenant's normal country (ISO-2). Defaults to the most common one.
  homeCountry?: string;
  now?: Date;
}

export interface CountryRow {
  code: string;
  name: string;
  signIns: number;
  users: number;
  succeeded: number;
  failed: number;
  blocked: number;
  isHome: boolean;
  // Country-type named locations this country belongs to.
  namedLocations: string[];
}

export interface IpRow {
  ipAddress: string;
  country: string;
  signIns: number;
  users: number;
  succeeded: number;
  failed: number;
  // IP-type named location containing this address, if any.
  namedLocation?: string;
  trusted: boolean;
  asn?: number;
}

export interface UserRow {
  userPrincipalName: string;
  displayName: string;
  userType?: "member" | "guest";
  signIns: number;
  succeeded: number;
  failed: number;
  blocked: number;
  countries: string[];
  ipAddresses: number;
  // Authentication labels seen for this user, most common first.
  authentication: string[];
  // Successful sign-ins where MFA was not required.
  withoutMfa: number;
  risky: number;
  lastSignIn: string;
}

export interface CountRow {
  label: string;
  signIns: number;
  users: number;
  succeeded: number;
  failed: number;
}

export interface ClientRow extends CountRow {
  legacy: boolean;
}

export interface DeviceRow extends CountRow {
  managed: number;
  compliant: number;
}

export interface SignInFinding {
  id: "legacy" | "outsideHome" | "withoutMfa" | "twoCountries" | "newCountry" | "failuresThenSuccess" | "risky";
  // "red": worth acting on. "orange": worth checking.
  severity: "red" | "orange";
  title: string;
  detail: string;
  total: number;
  // Up to FINDING_ROW_LIMIT examples, newest first.
  rows: { user: string; when: string; what: string }[];
}

export interface SignInReport {
  tenantName: string;
  tenantDomain: string;
  generatedAt: string;
  // The period of the sign-ins in the report (oldest to newest).
  from?: string;
  to?: string;
  requestedDays?: number;
  userFilter?: string;
  homeCountry: string | null;
  coverage: SignInCoverage;
  coverageNote: string;
  // Set when the requested period reaches further back than what was synced.
  periodWarning?: string;
  // False when the sign-ins carry no authentication details (demo data,
  // older sync, or the beta sign-in log wasn't available).
  authDetailsAvailable: boolean;
  summary: {
    total: number;
    succeeded: number;
    failed: number;
    blocked: number;
    users: number;
    guests: number;
    countries: number;
    ipAddresses: number;
    outsideHome: number;
    legacy: number;
    risky: number;
    mfaRequired: number;
    withoutMfa: number;
  };
  byCountry: CountryRow[];
  byIp: IpRow[];
  byUser: UserRow[];
  byAuthentication: CountRow[];
  byApp: CountRow[];
  byClient: ClientRow[];
  byDevice: DeviceRow[];
  findings: SignInFinding[];
}

export const FINDING_ROW_LIMIT = 15;
// Two successful sign-ins by one user from different countries this close together.
export const TWO_COUNTRIES_WINDOW_HOURS = 2;
// A country counts as new for a user when first seen this recently.
export const NEW_COUNTRY_DAYS = 7;
// This many failures inside the window, then a success, looks like a guessed password.
export const FAILURE_BURST_COUNT = 5;
export const FAILURE_BURST_WINDOW_MINUTES = 30;

const MODERN_CLIENTS = new Set(["browser", "mobile apps and desktop clients", "unknown", ""]);
export const isLegacyClient = (e: Pick<SignInEvent, "clientApp">) => !MODERN_CLIENTS.has((e.clientApp || "").toLowerCase());

// A report-only failure still let the user in.
const succeeded = (e: SignInEvent) => e.status === "success" || e.status === "report_only_failed";
const time = (e: SignInEvent) => Date.parse(e.createdDateTime) || 0;
const userKey = (e: SignInEvent) => (e.userPrincipalName || "").toLowerCase();
const countryOf = (e: SignInEvent) => normalizeCountryCode(e.location?.country);

function tally<T extends CountRow>(events: SignInEvent[], labelOf: (e: SignInEvent) => string, extend?: (row: CountRow, group: SignInEvent[]) => T): T[] {
  const groups = new Map<string, SignInEvent[]>();
  for (const e of events) {
    const label = labelOf(e);
    groups.set(label, [...(groups.get(label) || []), e]);
  }
  return [...groups.entries()]
    .map(([label, group]) => {
      const row: CountRow = {
        label,
        signIns: group.length,
        users: new Set(group.map(userKey)).size,
        succeeded: group.filter(succeeded).length,
        failed: group.filter((e) => !succeeded(e)).length,
      };
      return extend ? extend(row, group) : (row as T);
    })
    .sort((a, b) => b.signIns - a.signIns || a.label.localeCompare(b.label));
}

function finding(id: SignInFinding["id"], severity: SignInFinding["severity"], title: string, detail: string, rows: { user: string; when: string; what: string }[]): SignInFinding | null {
  if (rows.length === 0) return null;
  const sorted = [...rows].sort((a, b) => b.when.localeCompare(a.when));
  return { id, severity, title, detail, total: rows.length, rows: sorted.slice(0, FINDING_ROW_LIMIT) };
}

export function buildSignInReport(snapshot: TenantSecuritySnapshot, options: SignInReportOptions = {}): SignInReport {
  const now = options.now || new Date();
  const all = snapshot.signIns || [];
  const coverage = getSignInCoverage(snapshot);
  const homeCountry = (options.homeCountry || detectMostCommonCountry(all) || "").toUpperCase() || null;

  const cutoff = options.days ? now.getTime() - options.days * 24 * 60 * 60 * 1000 : undefined;
  const userFilter = options.user?.trim().toLowerCase();
  const events = all
    .filter((e) => cutoff === undefined || time(e) >= cutoff)
    .filter((e) => !userFilter || userKey(e).includes(userFilter) || (e.userDisplayName || "").toLowerCase().includes(userFilter))
    .sort((a, b) => time(a) - time(b));

  const isOutsideHome = (e: SignInEvent) => !!homeCountry && countryOf(e) !== UNKNOWN_COUNTRY && countryOf(e) !== homeCountry;
  const authDetailsAvailable = events.some((e) => !!e.authentication);
  const withoutMfa = (e: SignInEvent) => succeeded(e) && e.authentication?.requirement === "singleFactor";
  const namedLocations = snapshot.conditionalAccess?.namedLocations || [];

  // ---- by country
  const byCountry: CountryRow[] = tally(events, countryOf).map((row) => {
    const group = events.filter((e) => countryOf(e) === row.label);
    return {
      code: row.label,
      name: row.label === UNKNOWN_COUNTRY ? "Unknown" : getCountryDisplayName(row.label),
      signIns: row.signIns,
      users: row.users,
      succeeded: row.succeeded,
      failed: group.filter((e) => e.status === "failed").length,
      blocked: group.filter((e) => e.status === "ca_blocked").length,
      isHome: !!homeCountry && row.label === homeCountry,
      namedLocations: namedLocations.filter((l) => l.kind === "country" && (l.countries || []).includes(row.label)).map((l) => l.displayName),
    };
  });

  // ---- by IP address
  const ipLocations = namedLocations.filter((l) => l.kind === "ip");
  const byIp: IpRow[] = tally(events, (e) => e.ipAddress || "unknown").map((row) => {
    const group = events.filter((e) => (e.ipAddress || "unknown") === row.label);
    const matches = ipLocations.filter((l) => (l.ipRanges || []).some((range) => isIpInCidr(row.label, range)));
    const location = matches.find((l) => l.isTrusted) || matches[0];
    return {
      ipAddress: row.label,
      country: countryOf(group[group.length - 1]),
      signIns: row.signIns,
      users: row.users,
      succeeded: row.succeeded,
      failed: row.failed,
      namedLocation: location?.displayName,
      trusted: !!location?.isTrusted,
      asn: group.find((e) => e.asn !== undefined)?.asn,
    };
  });

  // ---- by user
  const byUser: UserRow[] = tally(events, userKey).map((row) => {
    const group = events.filter((e) => userKey(e) === row.label);
    const last = group[group.length - 1];
    return {
      userPrincipalName: last.userPrincipalName,
      displayName: last.userDisplayName,
      userType: group.find((e) => e.userType)?.userType,
      signIns: row.signIns,
      succeeded: row.succeeded,
      failed: group.filter((e) => e.status === "failed").length,
      blocked: group.filter((e) => e.status === "ca_blocked").length,
      countries: [...new Set(group.map(countryOf))].filter((c) => c !== UNKNOWN_COUNTRY),
      ipAddresses: new Set(group.map((e) => e.ipAddress)).size,
      authentication: authDetailsAvailable ? tally(group, (e) => describeSignInAuthentication(e.authentication)).map((a) => a.label) : [],
      withoutMfa: group.filter(withoutMfa).length,
      risky: group.filter((e) => e.isRisky).length,
      lastSignIn: last.createdDateTime,
    };
  });

  const byAuthentication = authDetailsAvailable ? tally(events, (e) => describeSignInAuthentication(e.authentication)) : [];
  const byApp = tally(events, (e) => e.appDisplayName || "Unknown app");
  const byClient: ClientRow[] = tally(events, (e) => e.clientApp || "Unknown", (row, group) => ({ ...row, legacy: isLegacyClient(group[0]) }));
  const byDevice: DeviceRow[] = tally(events, (e) => e.deviceDetail?.operatingSystem || "Unknown OS", (row, group) => ({
    ...row,
    managed: group.filter((e) => e.deviceDetail?.isManaged).length,
    compliant: group.filter((e) => e.deviceDetail?.isCompliant).length,
  }));

  // ---- worth a look
  const describe = (e: SignInEvent) => `${e.appDisplayName} from ${countryOf(e) === UNKNOWN_COUNTRY ? "an unknown country" : getCountryDisplayName(countryOf(e))} (${e.ipAddress})`;
  const row = (e: SignInEvent, what: string) => ({ user: e.userPrincipalName, when: e.createdDateTime, what });
  const perUser = new Map<string, SignInEvent[]>();
  for (const e of events) perUser.set(userKey(e), [...(perUser.get(userKey(e)) || []), e]);

  const twoCountries: { user: string; when: string; what: string }[] = [];
  const newCountry: { user: string; when: string; what: string }[] = [];
  const failuresThenSuccess: { user: string; when: string; what: string }[] = [];
  const periodEnd = events.length > 0 ? time(events[events.length - 1]) : now.getTime();

  perUser.forEach((list) => {
    // Two countries close together (successful sign-ins only).
    const ok = list.filter((e) => succeeded(e) && countryOf(e) !== UNKNOWN_COUNTRY);
    for (let i = 1; i < ok.length; i++) {
      const gapHours = (time(ok[i]) - time(ok[i - 1])) / 3_600_000;
      if (countryOf(ok[i]) !== countryOf(ok[i - 1]) && gapHours <= TWO_COUNTRIES_WINDOW_HOURS) {
        twoCountries.push(
          row(ok[i], `${getCountryDisplayName(countryOf(ok[i - 1]))} then ${getCountryDisplayName(countryOf(ok[i]))} within ${gapHours < 1 ? `${Math.max(1, Math.round(gapHours * 60))} minutes` : `${gapHours.toFixed(1)} hours`}`)
        );
      }
    }
    // A country first seen recently, for a user with earlier history elsewhere.
    const firstSeen = new Map<string, SignInEvent>();
    for (const e of ok) if (!firstSeen.has(countryOf(e))) firstSeen.set(countryOf(e), e);
    firstSeen.forEach((first, country) => {
      const recent = periodEnd - time(first) <= NEW_COUNTRY_DAYS * 24 * 60 * 60 * 1000;
      const hadEarlierHistory = ok.some((e) => countryOf(e) !== country && time(e) < time(first));
      if (recent && hadEarlierHistory) newCountry.push(row(first, `First sign-in from ${getCountryDisplayName(country)}`));
    });
    // A run of failures followed by a success.
    const windowMs = FAILURE_BURST_WINDOW_MINUTES * 60_000;
    for (let i = 0; i < list.length; i++) {
      if (!succeeded(list[i])) continue;
      const failures = list.slice(0, i).filter((e) => e.status === "failed" && time(list[i]) - time(e) <= windowMs);
      const previousSuccessInWindow = list.slice(0, i).some((e) => succeeded(e) && time(list[i]) - time(e) <= windowMs);
      if (failures.length >= FAILURE_BURST_COUNT && !previousSuccessInWindow) {
        failuresThenSuccess.push(row(list[i], `${failures.length} failed sign-ins in ${FAILURE_BURST_WINDOW_MINUTES} minutes, then a success: ${describe(list[i])}`));
      }
    }
  });

  const homeName = homeCountry ? getCountryDisplayName(homeCountry) : "the home country";
  const findings = [
    finding(
      "failuresThenSuccess",
      "red",
      "Repeated failures followed by a success",
      `${FAILURE_BURST_COUNT} or more failed sign-ins within ${FAILURE_BURST_WINDOW_MINUTES} minutes and then a successful one. This is what a guessed password looks like.`,
      failuresThenSuccess
    ),
    finding(
      "twoCountries",
      "red",
      "One user in two countries at almost the same time",
      `Successful sign-ins by the same user from different countries within ${TWO_COUNTRIES_WINDOW_HOURS} hours. A VPN explains some; a stolen session explains others.`,
      twoCountries
    ),
    finding(
      "legacy",
      "red",
      "Successful sign-ins over legacy protocols",
      "Legacy protocols (IMAP, POP, SMTP, older Office clients) cannot do MFA, so a password alone is enough.",
      events.filter((e) => succeeded(e) && isLegacyClient(e)).map((e) => row(e, `${e.clientApp}: ${describe(e)}`))
    ),
    finding("risky", "red", "Sign-ins Microsoft flagged as risky", "Sign-ins with medium or high risk, or a risk state of at risk.", events.filter((e) => e.isRisky).map((e) => row(e, `${e.riskLevel} risk: ${describe(e)}`))),
    finding(
      "outsideHome",
      "orange",
      `Successful sign-ins from outside ${homeName}`,
      "Check these against where your users actually are.",
      events.filter((e) => succeeded(e) && isOutsideHome(e)).map((e) => row(e, describe(e)))
    ),
    finding("newCountry", "orange", "A user signing in from a new country", `The first successful sign-in from a country in the last ${NEW_COUNTRY_DAYS} days of the period, for a user with earlier sign-ins elsewhere.`, newCountry),
    finding(
      "withoutMfa",
      "orange",
      "Successful sign-ins where MFA was not required",
      "No Conditional Access policy or security default asked for a second factor on these sign-ins.",
      events.filter(withoutMfa).map((e) => row(e, describe(e)))
    ),
  ].filter((f): f is SignInFinding => f !== null);

  const report: SignInReport = {
    tenantName: snapshot.tenant.displayName,
    tenantDomain: snapshot.tenant.defaultDomainName,
    generatedAt: now.toISOString(),
    from: events[0]?.createdDateTime,
    to: events[events.length - 1]?.createdDateTime,
    requestedDays: options.days,
    userFilter: options.user?.trim() || undefined,
    homeCountry,
    coverage,
    coverageNote: describeSignInCoverage(coverage),
    authDetailsAvailable,
    summary: {
      total: events.length,
      succeeded: events.filter(succeeded).length,
      failed: events.filter((e) => e.status === "failed").length,
      blocked: events.filter((e) => e.status === "ca_blocked").length,
      users: perUser.size,
      guests: byUser.filter((u) => u.userType === "guest").length,
      countries: byCountry.filter((c) => c.code !== UNKNOWN_COUNTRY).length,
      ipAddresses: byIp.length,
      outsideHome: events.filter(isOutsideHome).length,
      legacy: events.filter(isLegacyClient).length,
      risky: events.filter((e) => e.isRisky).length,
      mfaRequired: events.filter((e) => succeeded(e) && e.authentication?.requirement === "multiFactor").length,
      withoutMfa: events.filter(withoutMfa).length,
    },
    byCountry,
    byIp,
    byUser,
    byAuthentication,
    byApp,
    byClient,
    byDevice,
    findings,
  };

  // Asked for more history than was synced?
  if (cutoff !== undefined && !coverage.complete && coverage.from && Date.parse(coverage.from) > cutoff) {
    report.periodWarning = `You asked for the last ${options.days} days, but sign-ins were only loaded back to ${coverage.from.slice(0, 10)}. Earlier activity is not in this report.`;
  }
  return report;
}

// ------------------------------------------------------------------ CSV

export interface CsvTable {
  // Used in the file name.
  name: string;
  headers: string[];
  rows: (string | number)[][];
}

export function signInReportCsvTables(report: SignInReport): CsvTable[] {
  const yesNo = (b: boolean) => (b ? "Yes" : "No");
  const tables: CsvTable[] = [
    {
      name: "Users",
      headers: ["User", "Name", "Type", "Sign-ins", "Succeeded", "Failed", "Blocked by CA", "Countries", "IP addresses", "Authentication", "Succeeded without MFA required", "Risky", "Last sign-in (UTC)"],
      rows: report.byUser.map((u) => [u.userPrincipalName, u.displayName, u.userType || "", u.signIns, u.succeeded, u.failed, u.blocked, u.countries.join(" "), u.ipAddresses, u.authentication.join("; "), u.withoutMfa, u.risky, u.lastSignIn]),
    },
    {
      name: "Countries",
      headers: ["Country", "Code", "Sign-ins", "Users", "Succeeded", "Failed", "Blocked by CA", "Home country", "Named locations"],
      rows: report.byCountry.map((c) => [c.name, c.code, c.signIns, c.users, c.succeeded, c.failed, c.blocked, yesNo(c.isHome), c.namedLocations.join("; ")]),
    },
    {
      name: "IPAddresses",
      headers: ["IP address", "Country", "Sign-ins", "Users", "Succeeded", "Failed", "Named location", "Trusted location", "ASN"],
      rows: report.byIp.map((i) => [i.ipAddress, i.country, i.signIns, i.users, i.succeeded, i.failed, i.namedLocation || "", yesNo(i.trusted), i.asn ?? ""]),
    },
    {
      name: "Apps",
      headers: ["App", "Sign-ins", "Users", "Succeeded", "Failed"],
      rows: report.byApp.map((a) => [a.label, a.signIns, a.users, a.succeeded, a.failed]),
    },
    {
      name: "Clients",
      headers: ["Client", "Legacy protocol", "Sign-ins", "Users", "Succeeded", "Failed"],
      rows: report.byClient.map((c) => [c.label, yesNo(c.legacy), c.signIns, c.users, c.succeeded, c.failed]),
    },
    {
      name: "Devices",
      headers: ["Operating system", "Sign-ins", "Users", "Managed", "Compliant"],
      rows: report.byDevice.map((d) => [d.label, d.signIns, d.users, d.managed, d.compliant]),
    },
    {
      name: "WorthALook",
      headers: ["Finding", "User", "When (UTC)", "Detail"],
      rows: report.findings.flatMap((f) => f.rows.map((r) => [f.title, r.user, r.when, r.what])),
    },
  ];
  if (report.authDetailsAvailable) {
    tables.splice(3, 0, {
      name: "Authentication",
      headers: ["Authentication", "Sign-ins", "Users", "Succeeded", "Failed"],
      rows: report.byAuthentication.map((a) => [a.label, a.signIns, a.users, a.succeeded, a.failed]),
    });
  }
  return tables;
}

// ---------------------------------------------------------- printable HTML

const escapeHtml = (value: unknown) =>
  String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

const day = (iso?: string) => (iso ? iso.slice(0, 10) : "");
const minute = (iso: string) => iso.slice(0, 16).replace("T", " ");

function htmlTable(headers: string[], rows: (string | number)[][], total: number, limit: number): string {
  if (rows.length === 0) return `<p class="muted">Nothing to show.</p>`;
  const more = total > limit ? `<p class="muted">Showing the top ${limit} of ${total}. The CSV download has all of them.</p>` : "";
  return `<table><thead><tr>${headers.map((h) => `<th>${escapeHtml(h)}</th>`).join("")}</tr></thead><tbody>${rows
    .slice(0, limit)
    .map((r) => `<tr>${r.map((c) => `<td>${escapeHtml(c)}</td>`).join("")}</tr>`)
    .join("")}</tbody></table>${more}`;
}

// A self-contained page (inline styles, no scripts beyond the print button)
// the browser can print or save as PDF. Every value is HTML-escaped: user
// names and app names come from the tenant and can't be trusted as markup.
export function renderSignInReportHtml(report: SignInReport, limit = 10): string {
  const s = report.summary;
  const stat = (label: string, value: number | string, tone = "") => `<div class="stat ${tone}"><div class="value">${escapeHtml(value)}</div><div class="label">${escapeHtml(label)}</div></div>`;
  const period = report.from ? `${day(report.from)} to ${day(report.to)}` : "No sign-ins in this period";
  const filters = [report.requestedDays ? `Last ${report.requestedDays} days` : "All synced sign-ins", report.userFilter ? `Users matching "${report.userFilter}"` : ""].filter(Boolean).join(" · ");

  const findings =
    report.findings.length === 0
      ? `<p class="ok">Nothing stood out in this period.</p>`
      : report.findings
          .map(
            (f) =>
              `<div class="finding ${f.severity}"><h3>${escapeHtml(f.title)} <span class="count">${f.total}</span></h3><p>${escapeHtml(f.detail)}</p>${htmlTable(
                ["User", "When (UTC)", "What"],
                f.rows.map((r) => [r.user, minute(r.when), r.what]),
                f.total,
                Math.min(limit, f.rows.length)
              )}</div>`
          )
          .join("");

  const authSection = report.authDetailsAvailable
    ? htmlTable(
        ["How users signed in", "Sign-ins", "Users", "Succeeded", "Failed"],
        report.byAuthentication.map((a) => [a.label, a.signIns, a.users, a.succeeded, a.failed]),
        report.byAuthentication.length,
        limit
      )
    : `<p class="muted">The MFA method is not available for these sign-ins. Sync the tenant again to load it.</p>`;

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Sign-in report - ${escapeHtml(report.tenantName)}</title>
<style>
  body { font-family: "Segoe UI", Arial, sans-serif; color: #0f172a; margin: 24px auto; max-width: 960px; padding: 0 16px; font-size: 12px; }
  h1 { font-size: 20px; margin: 0 0 2px; } h2 { font-size: 14px; margin: 22px 0 6px; border-bottom: 1px solid #cbd5e1; padding-bottom: 3px; } h3 { font-size: 12px; margin: 0 0 2px; }
  .muted { color: #64748b; } .note { background: #f1f5f9; border: 1px solid #cbd5e1; padding: 6px 8px; margin: 8px 0; }
  .warn { background: #fff7ed; border-color: #fdba74; }
  .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin: 10px 0; }
  .stat { border: 1px solid #cbd5e1; padding: 8px; } .stat .value { font-size: 18px; font-weight: 600; } .stat .label { color: #475569; }
  .stat.red .value { color: #b91c1c; } .stat.orange .value { color: #c2410c; } .stat.green .value { color: #15803d; }
  table { border-collapse: collapse; width: 100%; margin: 4px 0; } th, td { border: 1px solid #e2e8f0; padding: 3px 6px; text-align: left; vertical-align: top; }
  th { background: #f8fafc; font-weight: 600; }
  .finding { border-left: 4px solid #c2410c; padding: 4px 0 4px 10px; margin: 10px 0; page-break-inside: avoid; } .finding.red { border-color: #b91c1c; }
  .count { background: #e2e8f0; border-radius: 8px; padding: 0 6px; font-weight: 600; } .ok { color: #15803d; font-weight: 600; }
  button { font: inherit; padding: 5px 12px; cursor: pointer; }
  @media print { button { display: none; } body { margin: 0; max-width: none; } h2 { page-break-after: avoid; } }
</style></head><body>
<button onclick="window.print()">Print or save as PDF</button>
<h1>Sign-in report</h1>
<div class="muted">${escapeHtml(report.tenantName)} (${escapeHtml(report.tenantDomain)}) · ${escapeHtml(period)} · ${escapeHtml(filters)} · generated ${escapeHtml(minute(report.generatedAt))} UTC</div>
<div class="note${report.coverage.complete ? "" : " warn"}">${escapeHtml(report.coverageNote)}</div>
${report.periodWarning ? `<div class="note warn">${escapeHtml(report.periodWarning)}</div>` : ""}
<div class="stats">
  ${stat("Sign-ins", s.total)}${stat("Succeeded", s.succeeded, "green")}${stat("Failed", s.failed, s.failed ? "orange" : "")}${stat("Blocked by Conditional Access", s.blocked)}
  ${stat("Users", s.users)}${stat("Countries", s.countries)}${stat("IP addresses", s.ipAddresses)}${stat(`Outside ${report.homeCountry || "home country"}`, s.outsideHome, s.outsideHome ? "orange" : "")}
  ${stat("Succeeded with MFA", report.authDetailsAvailable ? s.mfaRequired : "n/a", "green")}${stat("Succeeded, MFA not required", report.authDetailsAvailable ? s.withoutMfa : "n/a", s.withoutMfa ? "orange" : "")}${stat("Legacy protocol", s.legacy, s.legacy ? "red" : "")}${stat("Risky", s.risky, s.risky ? "red" : "")}
</div>
<h2>Worth a look</h2>${findings}
<h2>Countries</h2>${htmlTable(
    ["Country", "Sign-ins", "Users", "Succeeded", "Failed", "Blocked", "Named location"],
    report.byCountry.map((c) => [c.isHome ? `${c.name} (home)` : c.name, c.signIns, c.users, c.succeeded, c.failed, c.blocked, c.namedLocations.join(", ")]),
    report.byCountry.length,
    limit
  )}
<h2>IP addresses</h2>${htmlTable(
    ["IP address", "Country", "Sign-ins", "Users", "Succeeded", "Failed", "Named location"],
    report.byIp.map((i) => [i.ipAddress, i.country === UNKNOWN_COUNTRY ? "Unknown" : i.country, i.signIns, i.users, i.succeeded, i.failed, i.namedLocation ? `${i.namedLocation}${i.trusted ? " (trusted)" : ""}` : ""]),
    report.byIp.length,
    limit
  )}
<h2>Users</h2>${htmlTable(
    ["User", "Sign-ins", "Succeeded", "Failed", "Blocked", "Countries", "IPs", "Authentication", "Last sign-in (UTC)"],
    report.byUser.map((u) => [u.userType === "guest" ? `${u.userPrincipalName} (guest)` : u.userPrincipalName, u.signIns, u.succeeded, u.failed, u.blocked, u.countries.join(" "), u.ipAddresses, u.authentication.join("; "), minute(u.lastSignIn)]),
    report.byUser.length,
    limit
  )}
<h2>MFA and authentication</h2>${authSection}
<h2>Apps</h2>${htmlTable(["App", "Sign-ins", "Users", "Failed"], report.byApp.map((a) => [a.label, a.signIns, a.users, a.failed]), report.byApp.length, limit)}
<h2>Clients and devices</h2>${htmlTable(
    ["Client", "Sign-ins", "Users", "Succeeded"],
    report.byClient.map((c) => [c.legacy ? `${c.label} (legacy protocol)` : c.label, c.signIns, c.users, c.succeeded]),
    report.byClient.length,
    limit
  )}${htmlTable(["Operating system", "Sign-ins", "Users", "Managed", "Compliant"], report.byDevice.map((d) => [d.label, d.signIns, d.users, d.managed, d.compliant]), report.byDevice.length, limit)}
<p class="muted">Generated by Clarity365 from the tenant's synced sign-in log. Times are UTC.</p>
</body></html>`;
}
