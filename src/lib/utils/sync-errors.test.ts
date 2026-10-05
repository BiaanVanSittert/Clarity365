import { describe, expect, it } from "vitest";
import { getSyncErrorsForPrefixes, getSyncNoticesForPrefixes, isSyncLimitNotice, splitSyncLimitNotices } from "./sync-errors";
import { TenantSecuritySnapshot } from "../types";

// The exact messages the sync writes (graph-client.ts, exo-client.ts).
const GROUPS_CAP = "Groups: Owner/member scan capped at the first 250 groups for sync performance - this tenant may have more.";
const SITES_CAP = "SharePoint Sites: Storage scan capped at the first 250 sites for sync performance - this tenant may have more.";
const MAILBOX_CAP = "Mailflow: Mailbox scan capped at the first 250 mailboxes for sync performance - this tenant may have more.";
const REAL = "Groups: Insufficient privileges to complete the operation.";

const snap = (syncHealth: object) => ({ syncHealth: { isPartial: true, lastAttemptAt: "", errors: [], ...syncHealth } }) as unknown as TenantSecuritySnapshot;

describe("sync limit notices", () => {
  it("recognises the three caps and nothing else", () => {
    for (const m of [GROUPS_CAP, SITES_CAP, MAILBOX_CAP]) expect(isSyncLimitNotice(m)).toBe(true);
    expect(isSyncLimitNotice(REAL)).toBe(false);
    expect(isSyncLimitNotice("Sign-in logs: Request timed out")).toBe(false);
  });

  it("splits caps out of the errors, so they don't make a tenant degraded", () => {
    expect(splitSyncLimitNotices([GROUPS_CAP, REAL, SITES_CAP])).toEqual({ errors: [REAL], notices: [GROUPS_CAP, SITES_CAP] });
  });

  it("shows a cap as a notice, not an error, in the module", () => {
    const s = snap({ errors: [REAL], notices: [GROUPS_CAP] });
    expect(getSyncErrorsForPrefixes(s, ["Groups:"])).toEqual([REAL]);
    expect(getSyncNoticesForPrefixes(s, ["Groups:"])).toEqual([GROUPS_CAP]);
    expect(getSyncNoticesForPrefixes(s, ["Mailflow:"])).toEqual([]);
  });

  it("reads caps stored as errors by older syncs as notices too", () => {
    const old = snap({ errors: [MAILBOX_CAP, REAL] });
    expect(getSyncErrorsForPrefixes(old, ["Mailflow:"])).toEqual([]);
    expect(getSyncNoticesForPrefixes(old, ["Mailflow:"])).toEqual([MAILBOX_CAP]);
  });
});
