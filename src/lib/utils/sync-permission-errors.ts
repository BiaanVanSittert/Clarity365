import { GRAPH_PERMISSIONS, findPermissionForSyncError, isPermissionGrantedByRoles } from "../data/graph-permissions";

// Turns the sync's raw error list into what the tenant's health should be
// based on, using the permissions the access token actually carries (its
// roles claim) rather than guessing from Microsoft's error text alone:
//  - a step refused because a REQUIRED permission isn't granted becomes one
//    plain line naming the permission to grant (instead of a raw JSON blob);
//  - a step refused because an OPTIONAL permission isn't granted is dropped -
//    declining an optional feature isn't a sync failure;
//  - everything else (timeouts, caps, licence refusals on a granted
//    permission) passes through untouched.
// grantedRoles is null when the token couldn't be decoded; nothing is
// rewritten then.
const ACCESS_REFUSED_PATTERN = /insufficient privileges|authorization_requestdenied|forbidden|missing application roles|not authorized|access ?denied|\b40[13]\b/i;

export interface ResolvedSyncErrors {
  errors: string[];
  // Required permissions the app registration doesn't have, by the name to grant.
  missingPermissions: string[];
}

export function resolveSyncErrors(rawErrors: string[], grantedRoles: string[] | null): ResolvedSyncErrors {
  if (grantedRoles === null) return { errors: rawErrors, missingPermissions: [] };

  const missingPermissions = GRAPH_PERMISSIONS.filter((p) => !p.optional && !isPermissionGrantedByRoles(p.permission, grantedRoles)).map((p) => p.grant[0]);

  const errors: string[] = [];
  for (const raw of rawErrors) {
    const permission = findPermissionForSyncError(raw);
    if (!permission || isPermissionGrantedByRoles(permission.permission, grantedRoles) || !ACCESS_REFUSED_PATTERN.test(raw)) {
      errors.push(raw);
      continue;
    }
    if (permission.optional) continue;
    const step = raw.slice(0, raw.indexOf(":"));
    const line = `${step}: not synced - the ${permission.grant[0]} permission isn't granted. Add it under API permissions in Entra and grant admin consent.`;
    if (!errors.includes(line)) errors.push(line);
  }
  return { errors, missingPermissions };
}
