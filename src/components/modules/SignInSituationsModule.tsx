import React, { useMemo, useState } from "react";
import {
  LogIn,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  HelpCircle,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
  Info,
  Wrench,
  History,
  ArrowRight,
  Crown,
  User,
  UserPlus,
} from "lucide-react";
import { TenantSecuritySnapshot } from "@/lib/types";
import { CountryFlag } from "../common/CountryFlag";
import { StatusPill } from "../common/StatusPill";
import { SituationPersona } from "@/lib/data/signin-situation-definitions";
import { buildCaEnvironment, buildSimUser, buildSyntheticSimUser, listSimAccounts, pickTypicalAccount, SimAccount } from "@/lib/services/ca-sim-context";
import { detectHomeCountry, runSituationsForPersona, summarizeVerdicts, SituationRunResult, SituationVerdict } from "@/lib/services/signin-situation-runner";
import { getCountryOptions } from "@/lib/utils/iso-country-codes";
import { getCountryDisplayName } from "@/lib/utils/sign-in-country";

interface SignInSituationsModuleProps {
  snapshot: TenantSecuritySnapshot;
  onNavigate?: (view: string) => void;
  // Persona to open on (CA Gap Analysis links straight to a persona's gaps).
  initialPersona?: SituationPersona;
}

// Colour rules from the Security Simulations review (see ai-context-vault/
// Optimization/Security Simulations Plan.md, "Decisions"): green and red
// are the main states; orange marks "allowed after MFA" and "can't confirm".
const VERDICT_STYLE: Record<SituationVerdict, { icon: React.ElementType; pill: string; bar: string; card: string; activeCard: string; text: string; title: string }> = {
  prevented: {
    icon: ShieldCheck,
    pill: "bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950/60 dark:text-emerald-300 dark:border-emerald-800",
    bar: "border-l-emerald-500",
    card: "bg-white dark:bg-slate-800 border-[#CBD5E1] dark:border-slate-700 hover:bg-emerald-50/60 dark:hover:bg-emerald-950/40",
    activeCard: "bg-emerald-100 dark:bg-emerald-950 border-emerald-400 dark:border-emerald-800",
    text: "text-emerald-800 dark:text-emerald-400",
    title: "Prevented",
  },
  partial: {
    icon: ShieldAlert,
    pill: "bg-amber-100 text-amber-900 border-amber-300 dark:bg-amber-950/60 dark:text-amber-300 dark:border-amber-800",
    bar: "border-l-amber-500",
    card: "bg-white dark:bg-slate-800 border-[#CBD5E1] dark:border-slate-700 hover:bg-amber-50/60 dark:hover:bg-amber-950/40",
    activeCard: "bg-amber-100 dark:bg-amber-950 border-amber-400 dark:border-amber-800",
    text: "text-amber-800 dark:text-amber-400",
    title: "Allowed after MFA / checks",
  },
  notPrevented: {
    icon: ShieldX,
    pill: "bg-red-100 text-red-800 border-red-300 dark:bg-red-950/60 dark:text-red-300 dark:border-red-800",
    bar: "border-l-red-500",
    card: "bg-white dark:bg-slate-800 border-[#CBD5E1] dark:border-slate-700 hover:bg-red-50/60 dark:hover:bg-red-950/40",
    activeCard: "bg-red-100 dark:bg-red-950 border-red-400 dark:border-red-800",
    text: "text-red-800 dark:text-red-400",
    title: "Not prevented",
  },
  unknown: {
    icon: HelpCircle,
    pill: "bg-orange-50 text-orange-800 border-orange-300 border-dashed dark:bg-orange-950/40 dark:text-orange-300 dark:border-orange-800",
    bar: "border-l-orange-400",
    card: "bg-white dark:bg-slate-800 border-[#CBD5E1] dark:border-slate-700 hover:bg-orange-50/60 dark:hover:bg-orange-950/40",
    activeCard: "bg-orange-100 dark:bg-orange-950 border-orange-400 dark:border-orange-800",
    text: "text-orange-800 dark:text-orange-400",
    title: "Can't confirm",
  },
};

const VERDICT_ORDER: SituationVerdict[] = ["notPrevented", "partial", "unknown", "prevented"];

const PERSONAS: { id: SituationPersona; label: string; titlePrefix: string; icon: React.ElementType }[] = [
  { id: "globalAdmin", label: "Admin account", titlePrefix: "Global Admin", icon: Crown },
  { id: "user", label: "Standard user", titlePrefix: "Standard user", icon: User },
  { id: "guest", label: "Guest account", titlePrefix: "Guest", icon: UserPlus },
];

const SYNTHETIC = "__synthetic__";

const APPLIES_LABEL: Record<string, string> = { yes: "Applies", no: "Doesn't apply", unknown: "Can't confirm" };

function accountsForPersona(lists: ReturnType<typeof listSimAccounts>, persona: SituationPersona): { group: string; accounts: SimAccount[] }[] {
  if (persona === "globalAdmin") {
    return [
      { group: "Global Administrators", accounts: lists.globalAdmins },
      { group: "Other admin roles", accounts: lists.otherAdmins },
    ].filter((g) => g.accounts.length > 0);
  }
  if (persona === "user") return lists.standardUsers.length > 0 ? [{ group: "Standard users", accounts: lists.standardUsers }] : [];
  return lists.guests.length > 0 ? [{ group: "Guests", accounts: lists.guests }] : [];
}

function defaultAccountId(groups: { accounts: SimAccount[] }[]): string {
  return pickTypicalAccount(groups.flatMap((g) => g.accounts))?.id || SYNTHETIC;
}

export const SignInSituationsModule: React.FC<SignInSituationsModuleProps> = ({ snapshot, onNavigate, initialPersona }) => {
  const env = useMemo(() => buildCaEnvironment(snapshot), [snapshot]);
  const lists = useMemo(() => listSimAccounts(snapshot), [snapshot]);
  const countryOptions = useMemo(() => getCountryOptions(), []);

  const [persona, setPersona] = useState<SituationPersona>(initialPersona || "globalAdmin");
  const [accountByPersona, setAccountByPersona] = useState<Partial<Record<SituationPersona, string>>>({});
  const [homeCountry, setHomeCountry] = useState<string>(() => detectHomeCountry(snapshot));
  const [foreignCountry, setForeignCountry] = useState<string>(() => (detectHomeCountry(snapshot) === "RU" ? "CN" : "RU"));
  const [verdictFilter, setVerdictFilter] = useState<SituationVerdict | "all">("all");
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  const accountGroups = useMemo(() => accountsForPersona(lists, persona), [lists, persona]);
  const accountId = accountByPersona[persona] ?? defaultAccountId(accountGroups);
  const selectedAccount = accountGroups.flatMap((g) => g.accounts).find((a) => a.id === accountId);
  const excludedAccountCount = accountGroups.flatMap((g) => g.accounts).filter((a) => a.excludedFrom && !a.breakGlassReasons && a.id !== accountId).length;

  const simUser = useMemo(() => {
    if (accountId !== SYNTHETIC) {
      const u = buildSimUser(snapshot, accountId);
      if (u) return u;
    }
    return buildSyntheticSimUser(persona);
  }, [snapshot, accountId, persona]);

  const results = useMemo(
    () => runSituationsForPersona(snapshot, persona, simUser, { homeCountry, foreignCountry }),
    [snapshot, persona, simUser, homeCountry, foreignCountry]
  );
  const counts = useMemo(() => summarizeVerdicts(results), [results]);
  const visible = useMemo(
    () =>
      results
        .filter((r) => verdictFilter === "all" || r.verdict === verdictFilter)
        .sort((a, b) => VERDICT_ORDER.indexOf(a.verdict) - VERDICT_ORDER.indexOf(b.verdict)),
    [results, verdictFilter]
  );

  const personaMeta = PERSONAS.find((p) => p.id === persona)!;
  const incompleteCount = env.incompletePolicyIds?.length || 0;
  const lastSync = snapshot.tenant.lastSyncTimestamp ? new Date(snapshot.tenant.lastSyncTimestamp).toLocaleString() : "never";

  const toggle = (id: string) => setExpanded((prev) => ({ ...prev, [id]: !prev[id] }));

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 p-4 rounded-sm">
        <div className="flex items-center gap-2">
          <LogIn size={18} className="text-slate-800 dark:text-slate-200" />
          <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">Sign-in Situations</h2>
        </div>
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
          Sign in as a real account and see what Conditional Access would do in each situation: which policy blocks it, or why it gets through and
          what would stop it. Simulated from this tenant&apos;s policies as of the last sync ({lastSync}); nothing is sent to Microsoft.
        </p>
      </div>

      {/* Data-quality banners */}
      {incompleteCount > 0 && (
        <Banner tone="warn" icon={History}>
          {incompleteCount} of {env.policies.length} policies were synced before simulation support, so some of their conditions weren&apos;t stored.
          Situations they could affect show &quot;Can&apos;t confirm&quot;. Re-sync this tenant for exact results.
        </Banner>
      )}
      {!env.namedLocations && incompleteCount === 0 && (
        <Banner tone="warn" icon={History}>
          Named locations haven&apos;t been synced yet, so location-based policies can&apos;t be evaluated. Re-sync this tenant.
        </Banner>
      )}
      {env.securityDefaultsEnabled && (
        <Banner tone="info" icon={Info}>
          Security defaults are on, so Microsoft&apos;s fixed baseline applies instead of Conditional Access. Results reflect security defaults.
        </Banner>
      )}

      {/* Sign in as */}
      <div className="bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm p-4 space-y-3">
        <div className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Sign in as</div>
        <div className="flex flex-wrap gap-2" role="tablist" aria-label="Persona">
          {PERSONAS.map((p) => {
            const active = p.id === persona;
            const Icon = p.icon;
            const count = p.id === "globalAdmin" ? lists.globalAdmins.length : p.id === "user" ? lists.standardUsers.length : lists.guests.length;
            return (
              <button
                key={p.id}
                role="tab"
                aria-selected={active}
                onClick={() => {
                  setPersona(p.id);
                  setVerdictFilter("all");
                }}
                className={`px-3 py-1.5 text-xs font-semibold rounded-sm border flex items-center gap-1.5 transition-colors ${
                  active
                    ? "bg-slate-900 text-white border-slate-900 dark:bg-slate-100 dark:text-slate-900 dark:border-slate-100"
                    : "bg-white text-slate-700 border-[#CBD5E1] hover:bg-slate-50 dark:bg-slate-800 dark:text-slate-200 dark:border-slate-600 dark:hover:bg-slate-700"
                }`}
              >
                <Icon size={13} />
                <span>{p.label}</span>
                <span className={`font-mono text-[10px] ${active ? "opacity-80" : "text-slate-400"}`}>{count}</span>
              </button>
            );
          })}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <label className="block">
            <span className="text-[11px] text-slate-500 dark:text-slate-400">Account</span>
            <select
              value={accountId}
              onChange={(e) => setAccountByPersona((prev) => ({ ...prev, [persona]: e.target.value }))}
              className="mt-1 w-full text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm px-2 py-1.5 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100"
            >
              {accountGroups.map((g) => (
                <optgroup key={g.group} label={g.group}>
                  {g.accounts.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.displayName} ({a.userPrincipalName})
                      {a.breakGlassReasons ? " - possible break-glass" : a.excludedFrom ? ` - excluded from ${a.excludedFrom.length} polic${a.excludedFrom.length === 1 ? "y" : "ies"}` : ""}
                    </option>
                  ))}
                </optgroup>
              ))}
              <option value={SYNTHETIC}>A hypothetical {personaMeta.titlePrefix.toLowerCase()} (no real account)</option>
            </select>
          </label>
          <CountrySelect label="Home country" value={homeCountry} onChange={setHomeCountry} options={countryOptions} />
          <CountrySelect label="Foreign country (for foreign-country situations)" value={foreignCountry} onChange={setForeignCountry} options={countryOptions} />
        </div>

        {accountGroups.length === 0 && (
          <p className="text-[11px] text-slate-500 dark:text-slate-400">
            No {personaMeta.label.toLowerCase()}s were found in the last sync, so a hypothetical account is used. It only matches policies that target all
            users, guests or roles - not specific people or groups.
          </p>
        )}
        {selectedAccount?.breakGlassReasons && (
          <Banner tone="warn" icon={AlertTriangle}>
            This looks like an emergency-access (break-glass) account ({selectedAccount.breakGlassReasons.join("; ")}). Those are excluded from most
            policies by design, so its results don&apos;t represent a normal {personaMeta.titlePrefix.toLowerCase()}. Confirm it really is a break-glass
            account and that its sign-ins are monitored.
          </Banner>
        )}
        {selectedAccount?.excludedFrom && !selectedAccount.breakGlassReasons && (
          <Banner tone="warn" icon={AlertTriangle}>
            This account is individually excluded from {selectedAccount.excludedFrom.map((n) => `"${n}"`).join(", ")}, so its results are worse than a
            typical {personaMeta.titlePrefix.toLowerCase()}&apos;s. Check the exclusion is still needed (service and scanner accounts often are).
          </Banner>
        )}
        {!selectedAccount?.excludedFrom && excludedAccountCount > 0 && (
          <p className="text-[11px] text-slate-500 dark:text-slate-400">
            {excludedAccountCount} other account(s) in this list are individually excluded from policies (marked in the list). Select one to see how
            much the exclusion exposes it.
          </p>
        )}
        {selectedAccount?.roleSource === "inferred" && (
          <p className="text-[11px] text-amber-700 dark:text-amber-400">
            This account&apos;s roles come from an older sync and may be inferred rather than confirmed. Re-sync for exact role data.
          </p>
        )}
      </div>

      {/* Summary strip */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-2.5">
        {(["prevented", "partial", "notPrevented", "unknown"] as SituationVerdict[]).map((v) => {
          const style = VERDICT_STYLE[v];
          const Icon = style.icon;
          const active = verdictFilter === v;
          const select = () => setVerdictFilter(active ? "all" : v);
          return (
            <div
              key={v}
              role="button"
              tabIndex={0}
              onClick={select}
              onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), select())}
              title={`Click to show only "${style.title}" situations`}
              className={`p-3 border rounded-sm cursor-pointer transition-colors ${active ? style.activeCard : style.card}`}
            >
              <div className={`text-[11px] font-semibold uppercase tracking-wider flex items-center gap-1 ${style.text}`}>
                <Icon size={12} />
                <span>{style.title}</span>
              </div>
              <div className={`text-xl font-bold font-mono mt-1 ${style.text}`}>
                {counts[v]} <span className="text-xs font-normal">of {results.length}</span>
              </div>
              <div className={`text-[10px] mt-0.5 ${style.text}`}>(Click to filter)</div>
            </div>
          );
        })}
      </div>

      {/* Situations */}
      <div className="space-y-2">
        {visible.map((r) => (
          <SituationCard
            key={r.situation.id}
            result={r}
            titlePrefix={personaMeta.titlePrefix}
            foreignCountry={foreignCountry}
            expanded={!!expanded[r.situation.id]}
            onToggle={() => toggle(r.situation.id)}
            onNavigate={onNavigate}
            isSynthetic={accountId === SYNTHETIC}
          />
        ))}
        {visible.length === 0 && (
          <div className="text-xs text-slate-500 dark:text-slate-400 p-4 border border-dashed border-[#CBD5E1] dark:border-slate-700 rounded-sm">
            No situations match this filter.
          </div>
        )}
      </div>
    </div>
  );
};

// ----------------------------------------------------------------- pieces

const Banner: React.FC<{ tone: "warn" | "info"; icon: React.ElementType; children: React.ReactNode }> = ({ tone, icon: Icon, children }) => (
  <div
    className={`flex items-start gap-2 p-3 rounded-sm border text-xs ${
      tone === "warn"
        ? "bg-amber-50 border-amber-300 text-amber-900 dark:bg-amber-950/40 dark:border-amber-800 dark:text-amber-200"
        : "bg-sky-50 border-sky-300 text-sky-900 dark:bg-sky-950/40 dark:border-sky-800 dark:text-sky-200"
    }`}
  >
    <Icon size={14} className="mt-0.5 shrink-0" />
    <div>{children}</div>
  </div>
);

const CountrySelect: React.FC<{ label: string; value: string; onChange: (code: string) => void; options: { code: string; name: string }[] }> = ({
  label,
  value,
  onChange,
  options,
}) => (
  <label className="block">
    <span className="text-[11px] text-slate-500 dark:text-slate-400">{label}</span>
    <div className="mt-1 flex items-center gap-2 border border-[#CBD5E1] dark:border-slate-600 rounded-sm px-2 bg-white dark:bg-slate-900">
      <CountryFlag code={value} />
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full text-xs py-1.5 bg-transparent text-slate-900 dark:text-slate-100 outline-none"
      >
        {options.map((o) => (
          <option key={o.code} value={o.code}>
            {o.name}
          </option>
        ))}
      </select>
    </div>
  </label>
);

export const SituationCard: React.FC<{
  result: SituationRunResult;
  titlePrefix: string;
  foreignCountry: string;
  expanded: boolean;
  onToggle: () => void;
  onNavigate?: (view: string) => void;
  isSynthetic: boolean;
}> = ({ result, titlePrefix, foreignCountry, expanded, onToggle, onNavigate, isSynthetic }) => {
  const style = VERDICT_STYLE[result.verdict];
  const Icon = style.icon;
  const s = result.situation;
  const usesForeign = s.context.location === "foreign";
  const [showAllPolicies, setShowAllPolicies] = useState(false);
  const trace = result.result?.trace || [];
  const relevantTrace = showAllPolicies ? trace : trace.filter((t) => t.applies !== "no" || (t.excludedBy && t.excludedBy.length > 0) || t.state !== "disabled");

  return (
    <div className={`border border-[#CBD5E1] dark:border-slate-700 border-l-4 ${style.bar} rounded-sm bg-white dark:bg-slate-800`}>
      <button onClick={onToggle} aria-expanded={expanded} className="w-full text-left p-3 flex items-start gap-3 hover:bg-slate-50 dark:hover:bg-slate-700/40">
        {expanded ? <ChevronDown size={14} className="mt-0.5 text-slate-400 shrink-0" /> : <ChevronRight size={14} className="mt-0.5 text-slate-400 shrink-0" />}
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-semibold text-slate-900 dark:text-slate-100">
              {titlePrefix} · {s.label}
            </span>
            {usesForeign && (
              <span className="inline-flex items-center gap-1 text-[10px] text-slate-500 dark:text-slate-400">
                <CountryFlag code={foreignCountry} size={11} />
                {getCountryDisplayName(foreignCountry)}
              </span>
            )}
            <span className={`inline-flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded-sm border ${style.pill}`}>
              <Icon size={11} />
              {result.verdictLabel}
            </span>
          </div>
          <div className="text-[11px] text-slate-600 dark:text-slate-300 mt-1">{result.outcomeText}</div>
        </div>
      </button>

      {expanded && (
        <div className="px-4 pb-4 pt-1 space-y-3 border-t border-slate-100 dark:border-slate-700">
          <p className="text-[11px] text-slate-500 dark:text-slate-400">{s.description}</p>

          {result.whyNotBlocked.length > 0 && (
            <Section title="Why it isn't blocked">
              <ul className="list-disc pl-4 space-y-0.5">
                {result.whyNotBlocked.map((w, i) => (
                  <li key={i}>{w}</li>
                ))}
              </ul>
            </Section>
          )}

          {result.fixes.length > 0 && (
            <Section title="What would prevent it" icon={Wrench}>
              <ol className="space-y-2">
                {result.fixes.map((f, i) => (
                  <li key={i} className="border border-slate-200 dark:border-slate-700 rounded-sm p-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-[10px] text-slate-400">{i + 1}.</span>
                      <span className="font-semibold text-slate-900 dark:text-slate-100">{f.title}</span>
                      {f.sideEffect && <span className="text-[10px] px-1.5 py-0.5 rounded-sm bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300">Broad fix</span>}
                      {f.kind === "deployBaseline" && onNavigate && (
                        <button
                          onClick={() => onNavigate("ca_baseline")}
                          className="ml-auto inline-flex items-center gap-1 text-[10px] font-semibold text-slate-700 dark:text-slate-200 hover:underline"
                        >
                          Open CA Policy Baseline <ArrowRight size={11} />
                        </button>
                      )}
                    </div>
                    <div className="mt-1 text-slate-600 dark:text-slate-300">{f.detail}</div>
                    {f.sideEffect && <div className="mt-1 text-slate-500 dark:text-slate-400">{f.sideEffect}</div>}
                    {f.warning && (
                      <div className="mt-1.5 flex items-start gap-1.5 text-amber-800 dark:text-amber-300">
                        <AlertTriangle size={12} className="mt-0.5 shrink-0" />
                        <span>{f.warning}</span>
                      </div>
                    )}
                  </li>
                ))}
              </ol>
            </Section>
          )}

          {result.evidence && !isSynthetic && (
            <Section title="In this account's sign-in log">
              {result.evidence.matched === 0
                ? "No synced sign-ins by this account look like this situation."
                : `${result.evidence.matched} synced sign-in(s) by this account look like this situation; ${result.evidence.succeeded} succeeded.`}
            </Section>
          )}

          {result.notes.length > 0 && (
            <Section title="Notes" icon={Info}>
              <ul className="list-disc pl-4 space-y-0.5">
                {result.notes.map((n, i) => (
                  <li key={i}>{n}</li>
                ))}
              </ul>
            </Section>
          )}

          {trace.length > 0 && (
            <Section title="How each policy evaluated">
              <div className="overflow-x-auto">
                <table className="w-full text-[11px]">
                  <thead>
                    <tr className="text-left text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-700">
                      <th className="py-1 pr-3 font-semibold">Policy</th>
                      <th className="py-1 pr-3 font-semibold">State</th>
                      <th className="py-1 pr-3 font-semibold">Result</th>
                      <th className="py-1 font-semibold">Why</th>
                    </tr>
                  </thead>
                  <tbody>
                    {relevantTrace.map((t) => (
                      <tr key={t.policyId} className="border-b border-slate-100 dark:border-slate-700/60 align-top">
                        <td className="py-1 pr-3 text-slate-900 dark:text-slate-100">{t.policyName}</td>
                        <td className="py-1 pr-3">
                          <StatusPill status={t.state} />
                        </td>
                        <td className="py-1 pr-3 whitespace-nowrap text-slate-700 dark:text-slate-300">
                          {APPLIES_LABEL[t.applies]}
                          {t.applies !== "no" && t.grant
                            ? t.grant.kind === "block"
                              ? " · blocks"
                              : t.grant.kind === "unsatisfiable"
                              ? " · blocks"
                              : t.grant.kind === "requires"
                              ? ` · requires ${t.grant.paths.map((p) => p.map((r) => r.label).join(" + ")).join(" or ")}`
                              : " · satisfied"
                            : ""}
                        </td>
                        <td className="py-1 text-slate-600 dark:text-slate-400">
                          {t.reason}
                          {t.sessionControls.length > 0 && <div className="text-slate-500">Session: {t.sessionControls.join(", ")}</div>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {trace.length !== relevantTrace.length || showAllPolicies ? (
                <button onClick={() => setShowAllPolicies((v) => !v)} className="mt-1 text-[10px] font-semibold text-slate-600 dark:text-slate-300 hover:underline">
                  {showAllPolicies ? "Hide disabled policies" : `Show all ${trace.length} policies`}
                </button>
              ) : null}
            </Section>
          )}
        </div>
      )}
    </div>
  );
};

const Section: React.FC<{ title: string; icon?: React.ElementType; children: React.ReactNode }> = ({ title, icon: Icon, children }) => (
  <div>
    <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 flex items-center gap-1 mb-1">
      {Icon && <Icon size={11} />}
      <span>{title}</span>
    </div>
    <div className="text-[11px] text-slate-700 dark:text-slate-300">{children}</div>
  </div>
);
