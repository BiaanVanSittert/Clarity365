import { describe, it, expect } from "vitest";
import { mapCsvRowToRecord, getExportCapWarning, RawCsvRow } from "./audit-log-parser";

const ctx = { tenantId: "tenant-1", importId: "import-1" };

describe("mapCsvRowToRecord", () => {
  it("hoists SessionId/ClientIPAddress/ClientInfoString from a MailItemsAccessed record", () => {
    const row: RawCsvRow = {
      CreationDate: "2026-01-01T10:00:00",
      UserIds: "user@contoso.com",
      Operations: "MailItemsAccessed",
      AuditData: JSON.stringify({
        CreationTime: "2026-01-01T10:00:00",
        Operation: "MailItemsAccessed",
        UserId: "user@contoso.com",
        RecordType: 2,
        SessionId: "abc-123",
        ClientIPAddress: "203.0.113.5",
        ClientInfoString: "Client=OWA;Action=ViaProxy",
        Workload: "Exchange",
      }),
    };

    const { record, parseError } = mapCsvRowToRecord(row, ctx);

    expect(parseError).toBe(false);
    expect(record.sessionId).toBe("abc-123");
    expect(record.clientIp).toBe("203.0.113.5");
    expect(record.clientInfo).toBe("Client=OWA;Action=ViaProxy");
    expect(record.operation).toBe("MailItemsAccessed");
    expect(record.userId).toBe("user@contoso.com");
    expect(record.recordType).toBe("ExchangeItem");
    expect(record.workload).toBe("Exchange");
  });

  it("hoists ClientIP (not ClientIPAddress) from an Entra ID sign-in-flavored record", () => {
    const row: RawCsvRow = {
      CreationDate: "2026-01-02T08:00:00",
      UserIds: "admin@contoso.com",
      Operations: "UserLoggedIn",
      AuditData: JSON.stringify({
        CreationTime: "2026-01-02T08:00:00",
        Operation: "UserLoggedIn",
        UserId: "admin@contoso.com",
        RecordType: 15,
        ClientIP: "198.51.100.9",
        ResultStatus: "Success",
      }),
    };

    const { record } = mapCsvRowToRecord(row, ctx);

    expect(record.clientIp).toBe("198.51.100.9");
    expect(record.sessionId).toBeUndefined();
    expect(record.resultStatus).toBe("Success");
    expect(record.recordType).toBe("AzureActiveDirectoryStsLogon");
  });

  it("parses UserIds as a JSON array and takes the first entry", () => {
    const row: RawCsvRow = {
      CreationDate: "2026-01-03T00:00:00",
      UserIds: JSON.stringify(["first@contoso.com", "second@contoso.com"]),
      Operations: "FileDeleted",
      AuditData: JSON.stringify({ CreationTime: "2026-01-03T00:00:00", Operation: "FileDeleted", RecordType: 6 }),
    };

    const { record } = mapCsvRowToRecord(row, ctx);
    expect(record.userId).toBe("first@contoso.com");
  });

  it("degrades gracefully instead of throwing on malformed AuditData JSON", () => {
    const row: RawCsvRow = {
      CreationDate: "2026-01-04T00:00:00",
      UserIds: "user@contoso.com",
      Operations: "New-InboxRule",
      AuditData: "{not valid json",
    };

    const { record, parseError } = mapCsvRowToRecord(row, ctx);

    expect(parseError).toBe(true);
    expect(record.parseError).toBe(true);
    // Still falls back to the plain CSV columns for the hoisted fields that
    // don't require AuditData to have parsed successfully.
    expect(record.creationDate).toBe("2026-01-04T00:00:00");
    expect(record.operation).toBe("New-InboxRule");
    expect(record.userId).toBe("user@contoso.com");
    expect(record.rawData).toContain("{not valid json");
  });

  it("falls back to a numeric RecordType label when no name mapping exists", () => {
    const row: RawCsvRow = {
      CreationDate: "2026-01-05T00:00:00",
      Operations: "SomeFutureOperation",
      AuditData: JSON.stringify({ CreationTime: "2026-01-05T00:00:00", RecordType: 999 }),
    };

    const { record } = mapCsvRowToRecord(row, ctx);
    expect(record.recordType).toBe("RecordType 999");
  });

  it("prefers a PowerShell-exported RecordType column when present", () => {
    const row: RawCsvRow = {
      CreationDate: "2026-01-06T00:00:00",
      RecordType: "SharePointFileOperation",
      Operations: "FileDownloaded",
      AuditData: JSON.stringify({ CreationTime: "2026-01-06T00:00:00", RecordType: 6, Operation: "FileDownloaded" }),
    };

    const { record } = mapCsvRowToRecord(row, ctx);
    expect(record.recordType).toBe("SharePointFileOperation");
  });

  it("extracts device/client text from a DeviceProperties array when no flat client field exists", () => {
    const row: RawCsvRow = {
      CreationDate: "2026-01-07T00:00:00",
      Operations: "UserLoggedIn",
      AuditData: JSON.stringify({
        CreationTime: "2026-01-07T00:00:00",
        RecordType: 15,
        DeviceProperties: [
          { Name: "OS", Value: "Windows 11" },
          { Name: "DisplayName", Value: "DESKTOP-ABC123" },
        ],
      }),
    };

    const { record } = mapCsvRowToRecord(row, ctx);
    expect(record.clientInfo).toBeTruthy();
  });
});

describe("getExportCapWarning", () => {
  it("returns undefined well below any cap", () => {
    expect(getExportCapWarning(1200)).toBeUndefined();
  });

  it("warns at/above the Audit Standard 50,000-row cap", () => {
    expect(getExportCapWarning(50_000)).toMatch(/Audit \(Standard\)/);
  });

  it("warns at/above the Audit Premium 1,000,000-row cap with different text", () => {
    expect(getExportCapWarning(1_000_000)).toMatch(/Audit \(Premium\)/);
  });
});
