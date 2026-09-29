import { CAPolicyRule } from "../types";

// Demo tenants never re-sync (fetchLiveTenantSnapshot short-circuits for
// authMode "mock"), so a demo tenant's persisted CA policies would otherwise
// keep whatever shape mock-tenants.ts had when the tenant was first seeded -
// the same staleness class tenant-store.ts's backfillSnapshot() already
// handles for users/mailboxes/signIns/devices. Policies can't simply be
// replaced wholesale like those, though: tenantStore.deployBaselinePolicy()
// mutates a demo tenant's stored policies locally (flips an existing
// policy's state to report-only, or appends a new policy), and replacing
// would silently undo that demo deploy.
//
// Rule, per policy id:
//   - in mock and stored: mock's shape wins; stored state/modifiedDateTime
//     are kept only if the stored copy was modified AFTER the mock copy
//     (i.e. a local demo deploy touched it)
//   - only in mock: included as-is
//   - only in stored: kept (a locally deployed policy), appended after mock's
export function mergeDemoCaPolicies(stored: CAPolicyRule[], mock: CAPolicyRule[]): CAPolicyRule[] {
  const storedById = new Map(stored.map((p) => [p.id, p]));
  const mockIds = new Set(mock.map((p) => p.id));

  const merged = mock.map((mockPolicy) => {
    const storedPolicy = storedById.get(mockPolicy.id);
    if (!storedPolicy) return mockPolicy;
    const storedTime = Date.parse(storedPolicy.modifiedDateTime);
    const mockTime = Date.parse(mockPolicy.modifiedDateTime);
    const locallyModified = Number.isFinite(storedTime) && Number.isFinite(mockTime) && storedTime > mockTime;
    return locallyModified
      ? { ...mockPolicy, state: storedPolicy.state, modifiedDateTime: storedPolicy.modifiedDateTime }
      : mockPolicy;
  });

  return [...merged, ...stored.filter((p) => !mockIds.has(p.id))];
}
