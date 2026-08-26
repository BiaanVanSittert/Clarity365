import { promises as dns } from "dns";
import { DomainAuthCheck } from "../types";

// SPF/DMARC live in public DNS, not Exchange Online config — this is the one
// data source in the whole app that isn't a Graph or Exchange Online call.
// The actual DNS resolution (checkSpfRecord/checkDmarcRecord) is a thin I/O
// wrapper around the pure, independently-testable evaluate* functions below,
// which take already-fetched TXT record strings and decide pass/warn/fail —
// same separation of concerns as mailflow-mapper.ts's raw-to-typed mappers.

export function evaluateSpfTxtRecords(records: string[]): DomainAuthCheck {
  const spfRecord = records.find((r) => r.toLowerCase().startsWith("v=spf1"));
  if (!spfRecord) {
    return {
      status: "fail",
      detail: "No SPF record found for this domain.",
      recommendation: "Add a TXT record at the domain root: v=spf1 include:spf.protection.outlook.com -all",
    };
  }

  const includesOutlook = /include:spf\.protection\.outlook\.com/i.test(spfRecord);
  if (!includesOutlook) {
    return {
      status: "warn",
      detail: `SPF record found but doesn't authorize Microsoft 365's sending servers: "${spfRecord}"`,
      recommendation: "Add 'include:spf.protection.outlook.com' to the existing SPF record so mail sent through Microsoft 365 passes SPF.",
    };
  }

  const trimmed = spfRecord.trim();
  if (/-all\s*$/i.test(trimmed)) {
    return { status: "pass", detail: `SPF record found and enforced: "${spfRecord}"` };
  }
  if (/~all\s*$/i.test(trimmed)) {
    return {
      status: "warn",
      detail: `SPF record found but ends in a soft-fail (~all), not enforced: "${spfRecord}"`,
      recommendation: "Once you've confirmed every legitimate sender is included, change the ending from '~all' to '-all' so spoofed mail is rejected outright instead of only flagged.",
    };
  }
  return {
    status: "warn",
    detail: `SPF record found but doesn't end in an enforcement qualifier (-all or ~all): "${spfRecord}"`,
    recommendation: "End the record with '-all' to reject mail from senders not explicitly authorized.",
  };
}

export function evaluateDmarcTxtRecords(records: string[]): DomainAuthCheck {
  const dmarcRecord = records.find((r) => r.toLowerCase().startsWith("v=dmarc1"));
  if (!dmarcRecord) {
    return {
      status: "fail",
      detail: "No DMARC record found for this domain.",
      recommendation: "Add a TXT record at _dmarc.<domain>: v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@<domain>",
    };
  }

  const policyMatch = dmarcRecord.match(/p=(\w+)/i);
  const policy = policyMatch ? policyMatch[1].toLowerCase() : undefined;
  const hasReporting = /rua=/i.test(dmarcRecord);

  if (policy === "reject") {
    return { status: "pass", detail: `DMARC record found and enforced (p=reject): "${dmarcRecord}"` };
  }
  if (policy === "quarantine") {
    return {
      status: hasReporting ? "pass" : "warn",
      detail: `DMARC record found with p=quarantine: "${dmarcRecord}"`,
      recommendation: hasReporting
        ? undefined
        : "Add 'rua=mailto:<address>' to receive aggregate reports on spoofing attempts against this domain.",
    };
  }
  if (policy === "none") {
    return {
      status: "warn",
      detail: `DMARC record found but set to monitoring-only (p=none) — spoofed mail is reported on, not blocked or quarantined: "${dmarcRecord}"`,
      recommendation: "Move to 'p=quarantine' once reporting shows no legitimate mail would be affected, then to 'p=reject'.",
    };
  }
  return {
    status: "warn",
    detail: `DMARC record found but its policy tag couldn't be determined: "${dmarcRecord}"`,
  };
}

async function resolveTxtStrings(hostname: string): Promise<string[]> {
  const chunks = await dns.resolveTxt(hostname);
  return chunks.map((c) => c.join(""));
}

export async function checkSpfRecord(domain: string): Promise<DomainAuthCheck> {
  try {
    return evaluateSpfTxtRecords(await resolveTxtStrings(domain));
  } catch (err: any) {
    if (err?.code === "ENODATA" || err?.code === "ENOTFOUND") return evaluateSpfTxtRecords([]);
    return { status: "unknown", detail: `DNS lookup failed: ${err.message || "unknown error"}` };
  }
}

export async function checkDmarcRecord(domain: string): Promise<DomainAuthCheck> {
  try {
    return evaluateDmarcTxtRecords(await resolveTxtStrings(`_dmarc.${domain}`));
  } catch (err: any) {
    if (err?.code === "ENODATA" || err?.code === "ENOTFOUND") return evaluateDmarcTxtRecords([]);
    return { status: "unknown", detail: `DNS lookup failed: ${err.message || "unknown error"}` };
  }
}
