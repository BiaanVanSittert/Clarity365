import { describe, it, expect } from "vitest";
import { flagMassDeletionBursts, flagPossibleBec, DEFAULT_MASS_DELETION_THRESHOLD, DEFAULT_BEC_MAIL_ACCESS_THRESHOLD } from "./audit-log-heuristics";

describe("flagMassDeletionBursts", () => {
  it("does not flag a bucket just under the threshold", () => {
    const flags = flagMassDeletionBursts([{ userId: "a@x.com", hourBucket: "2026-01-01T09", deleteCount: DEFAULT_MASS_DELETION_THRESHOLD - 1 }]);
    expect(flags).toHaveLength(0);
  });

  it("flags a bucket exactly at the threshold", () => {
    const flags = flagMassDeletionBursts([{ userId: "a@x.com", hourBucket: "2026-01-01T09", deleteCount: DEFAULT_MASS_DELETION_THRESHOLD }]);
    expect(flags).toHaveLength(1);
    expect(flags[0].userId).toBe("a@x.com");
  });

  it("flags a bucket over the threshold", () => {
    const flags = flagMassDeletionBursts([{ userId: "a@x.com", hourBucket: "2026-01-01T09", deleteCount: 500 }]);
    expect(flags).toHaveLength(1);
  });

  it("respects a custom threshold", () => {
    const flags = flagMassDeletionBursts([{ userId: "a@x.com", hourBucket: "2026-01-01T09", deleteCount: 3 }], 3);
    expect(flags).toHaveLength(1);
  });

  it("returns nothing for empty input", () => {
    expect(flagMassDeletionBursts([])).toHaveLength(0);
  });

  it("flags multiple independent buckets", () => {
    const flags = flagMassDeletionBursts([
      { userId: "a@x.com", hourBucket: "2026-01-01T09", deleteCount: 50 },
      { userId: "b@x.com", hourBucket: "2026-01-01T10", deleteCount: 2 },
      { userId: "c@x.com", hourBucket: "2026-01-01T11", deleteCount: 12 },
    ]);
    expect(flags.map((f) => f.userId).sort()).toEqual(["a@x.com", "c@x.com"]);
  });
});

describe("flagPossibleBec", () => {
  it("does not flag an inbox rule change with no mail access in the same bucket", () => {
    const flags = flagPossibleBec([{ userId: "a@x.com", hourBucket: "2026-01-01T09", inboxRuleChangeCount: 1 }], []);
    expect(flags).toHaveLength(0);
  });

  it("does not flag high mail access volume with no inbox rule change", () => {
    // No entry in inboxRuleChanges at all for this user - flagPossibleBec
    // only ever iterates inbox-rule changes, so mail access alone never
    // produces a flag regardless of volume.
    const flags = flagPossibleBec([], [{ userId: "a@x.com", hourBucket: "2026-01-01T09", mailItemsAccessedCount: 500 }]);
    expect(flags).toHaveLength(0);
  });

  it("does not flag when mail access is under the threshold", () => {
    const flags = flagPossibleBec(
      [{ userId: "a@x.com", hourBucket: "2026-01-01T09", inboxRuleChangeCount: 1 }],
      [{ userId: "a@x.com", hourBucket: "2026-01-01T09", mailItemsAccessedCount: DEFAULT_BEC_MAIL_ACCESS_THRESHOLD - 1 }]
    );
    expect(flags).toHaveLength(0);
  });

  it("flags when both an inbox rule change and elevated mail access occur in the same bucket", () => {
    const flags = flagPossibleBec(
      [{ userId: "a@x.com", hourBucket: "2026-01-01T09", inboxRuleChangeCount: 1 }],
      [{ userId: "a@x.com", hourBucket: "2026-01-01T09", mailItemsAccessedCount: DEFAULT_BEC_MAIL_ACCESS_THRESHOLD }]
    );
    expect(flags).toHaveLength(1);
    expect(flags[0]).toMatchObject({ userId: "a@x.com", hourBucket: "2026-01-01T09", inboxRuleChangeCount: 1, mailItemsAccessedCount: DEFAULT_BEC_MAIL_ACCESS_THRESHOLD });
  });

  it("does not flag when the inbox rule change and mail access spike are in different hour buckets", () => {
    const flags = flagPossibleBec(
      [{ userId: "a@x.com", hourBucket: "2026-01-01T09", inboxRuleChangeCount: 1 }],
      [{ userId: "a@x.com", hourBucket: "2026-01-01T14", mailItemsAccessedCount: 500 }]
    );
    expect(flags).toHaveLength(0);
  });

  it("respects a custom threshold", () => {
    const flags = flagPossibleBec(
      [{ userId: "a@x.com", hourBucket: "2026-01-01T09", inboxRuleChangeCount: 1 }],
      [{ userId: "a@x.com", hourBucket: "2026-01-01T09", mailItemsAccessedCount: 5 }],
      5
    );
    expect(flags).toHaveLength(1);
  });
});
