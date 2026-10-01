import { describe, expect, it } from "vitest";
import { canWriteToExchange, classifyExoAppToken, getExchangeAccess } from "./exchange-access";

const NOW = "2026-09-30T12:00:00Z";
const GLOBAL_READER = "f2ef992c-3afb-46b9-b7cf-a126ee74c451";
const EXCHANGE_ADMIN = "29232cdf-9323-42fd-ade2-1d097af3e4de";
// Seen in the real Phase 0 token alongside Global Reader; not a directory role.
const NON_ROLE_ID = "0997a1d0-0d1d-4acb-b408-d5ca73121e90";

describe("classifyExoAppToken", () => {
  it("reads the real Phase 0 token shape (Global Reader, read-only)", () => {
    expect(classifyExoAppToken({ roles: ["Exchange.ManageAsApp"], wids: [GLOBAL_READER, NON_ROLE_ID] }, "clientSecret", NOW)).toMatchObject({
      status: "ok",
      role: "globalReader",
      canWrite: false,
      hasPermission: true,
    });
  });

  it("allows writes with Exchange Administrator", () => {
    expect(classifyExoAppToken({ roles: ["Exchange.ManageAsApp"], wids: [EXCHANGE_ADMIN] }, "clientSecret", NOW)).toMatchObject({ status: "ok", role: "exchangeAdministrator", canWrite: true });
  });

  it("is not set up without the permission, or without a role", () => {
    const noPermission = classifyExoAppToken({ roles: [], wids: [GLOBAL_READER] }, "clientSecret", NOW);
    expect(noPermission).toMatchObject({ status: "notSetUp", hasPermission: false });
    expect(noPermission.detail).toMatch(/Exchange\.ManageAsApp/);
    const noRole = classifyExoAppToken({ roles: ["Exchange.ManageAsApp"], wids: [NON_ROLE_ID] }, "clientSecret", NOW);
    expect(noRole).toMatchObject({ status: "notSetUp", hasPermission: true });
    expect(noRole.detail).toMatch(/Assign Exchange Administrator/);
  });
});

describe("getExchangeAccess / canWriteToExchange", () => {
  const ok = (canWrite: boolean) => ({ status: "ok" as const, canWrite, hasPermission: true, method: "clientSecret" as const, checkedAt: NOW, role: canWrite ? ("exchangeAdministrator" as const) : ("globalReader" as const) });

  it("prefers app-only access over the older sign-in", () => {
    expect(getExchangeAccess({ exoAppAccess: ok(false), exoRefreshToken: "rt" })).toEqual({ available: true, mode: "appOnly", canWrite: false, role: "globalReader" });
  });

  it("falls back to the older sign-in, then to none", () => {
    const notSetUp = { ...ok(false), status: "notSetUp" as const };
    expect(getExchangeAccess({ exoAppAccess: notSetUp, exoRefreshToken: "rt" }).mode).toBe("delegated");
    expect(getExchangeAccess({ exoAppAccess: notSetUp }).mode).toBe("none");
    expect(getExchangeAccess(undefined).available).toBe(false);
  });

  it("writes need both a write-capable role and the tenant's write switch", () => {
    expect(canWriteToExchange({ exoAppAccess: ok(true), exoWriteEnabled: true })).toBe(true);
    expect(canWriteToExchange({ exoAppAccess: ok(true), exoWriteEnabled: false })).toBe(false);
    // Global Reader can't write even with the switch on.
    expect(canWriteToExchange({ exoAppAccess: ok(false), exoWriteEnabled: true })).toBe(false);
    expect(canWriteToExchange({ exoRefreshToken: "rt", exoWriteEnabled: true })).toBe(true);
  });
});
