import { ExoAppAccess, TenantCredentials } from "@/lib/types";

// The ONE answer to "can Clarity365 use Exchange Online for this tenant, and
// can it write?" - used by the sync, the write actions in tenant-store.ts,
// every Exchange module and the Permissions check. Replaces ~20 separate
// `!!credentials.exoRefreshToken` checks (the duplicated-logic bug class in
// ai-context-vault/Optimization/Optimization Plan.md item 7).
//
// Two ways in, preferred first:
//   appOnly   - the app registration has Exchange.ManageAsApp and an Entra
//               role (no sign-in). What the role allows decides canWrite.
//   delegated - the older device-code admin sign-in (a stored refresh token).
//               It acts as the signed-in admin, so it can write.

export type ExchangeAccessMode = "appOnly" | "delegated" | "none";

export interface ExchangeAccess {
  available: boolean;
  mode: ExchangeAccessMode;
  canWrite: boolean;
  role?: ExoAppAccess["role"];
}

export function getExchangeAccess(credentials: Pick<TenantCredentials, "exoAppAccess" | "exoRefreshToken"> | undefined): ExchangeAccess {
  const app = credentials?.exoAppAccess;
  if (app?.status === "ok") return { available: true, mode: "appOnly", canWrite: app.canWrite, role: app.role };
  if (credentials?.exoRefreshToken) return { available: true, mode: "delegated", canWrite: true };
  return { available: false, mode: "none", canWrite: false };
}

// Writes need Exchange access that can write AND the tenant's explicit
// "allow Clarity365 to write to Exchange" switch.
export function canWriteToExchange(
  credentials: Pick<TenantCredentials, "exoAppAccess" | "exoRefreshToken" | "exoWriteEnabled"> | undefined
): boolean {
  return !!credentials?.exoWriteEnabled && getExchangeAccess(credentials).canWrite;
}

// Role template ids Microsoft puts in an app-only token's `wids` claim.
// Other ids in `wids` (Microsoft adds one that isn't a directory role -
// verified in the Phase 0 spike) are ignored.
const EXCHANGE_ADMINISTRATOR = "29232cdf-9323-42fd-ade2-1d097af3e4de";
const GLOBAL_ADMINISTRATOR = "62e90394-69f5-4237-9190-012177145e10";
const GLOBAL_READER = "f2ef992c-3afb-46b9-b7cf-a126ee74c451";
// Other roles Microsoft lists as usable for app-only Exchange access.
const OTHER_EXCHANGE_ROLES = new Set([
  "17315797-102d-40b4-93e0-432062caca18", // Compliance Administrator
  "31392ffb-586c-42d1-9346-e59415a2cc4e", // Exchange Recipient Administrator
  "729827e3-9c14-49f7-bb1b-9608f156bbb8", // Helpdesk Administrator
  "194ae4cb-b126-40b2-bd5b-6091b380977d", // Security Administrator
  "5d6b6bb7-de71-4623-b4af-96380a352509", // Security Reader
]);

// Pure: turns an app-only Exchange token's claims into an access status.
export function classifyExoAppToken(
  claims: { roles?: string[]; wids?: string[] },
  method: ExoAppAccess["method"],
  checkedAt: string
): ExoAppAccess {
  const hasPermission = (claims.roles || []).includes("Exchange.ManageAsApp");
  const wids = (claims.wids || []).map((w) => w.toLowerCase());
  const role: ExoAppAccess["role"] = wids.includes(EXCHANGE_ADMINISTRATOR)
    ? "exchangeAdministrator"
    : wids.includes(GLOBAL_ADMINISTRATOR)
    ? "globalAdministrator"
    : wids.includes(GLOBAL_READER)
    ? "globalReader"
    : wids.some((w) => OTHER_EXCHANGE_ROLES.has(w))
    ? "otherRole"
    : undefined;

  if (!hasPermission || !role) {
    return {
      status: "notSetUp",
      hasPermission,
      role,
      canWrite: false,
      method,
      checkedAt,
      detail: !hasPermission
        ? "The app doesn't have the Office 365 Exchange Online permission Exchange.ManageAsApp (with admin consent)."
        : "The app has the Exchange permission but no role. Assign Exchange Administrator (or Global Reader for reports only) to the app.",
    };
  }
  return { status: "ok", hasPermission, role, canWrite: role === "exchangeAdministrator" || role === "globalAdministrator", method, checkedAt };
}

export const EXCHANGE_ROLE_LABEL: Record<NonNullable<ExoAppAccess["role"]>, string> = {
  exchangeAdministrator: "Exchange Administrator",
  globalAdministrator: "Global Administrator",
  globalReader: "Global Reader",
  otherRole: "a limited Exchange role",
};
