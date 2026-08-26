import { TenantSecuritySnapshot } from "../types";
import { evaluateMdoBaseline } from "./mdo-baseline-matcher";
import { evaluateMailflowBaseline } from "./mailflow-baseline-matcher";

// Single "Exchange & Mailflow Security Score" combining every check in the
// consolidated Exchange & Mailflow nav group into one percentage - MDO's
// baseline, the Mail Flow Rules baseline (transport rules, connectors, org
// settings), Domain Authentication (SPF/DKIM/DMARC), and the mailbox-auditing
// gate. Unweighted: every individual check counts equally toward the total,
// the same way each MDO0x/MF0x check already does within its own baseline -
// this is meant to be tracked over time, not treated as a precise risk score.
export function computeExchangeMailflowScore(snapshot: TenantSecuritySnapshot): {
  percent: number;
  metCount: number;
  totalCount: number;
} {
  const mdo = evaluateMdoBaseline(snapshot.mdoThreat.policies);
  const mailflow = evaluateMailflowBaseline({
    transportRules: snapshot.mailflowTransportRules,
    policies: snapshot.mdoThreat.policies,
    connectors: snapshot.mailflowConnectors,
    remoteDomainAutoForwardBlocked: snapshot.remoteDomainAutoForwardBlocked,
    externalSenderTagEnabled: snapshot.externalSenderTagEnabled,
  });

  const domainCheckStatuses = snapshot.domainAuth.flatMap((d) => [d.dkim.status, d.spf.status, d.dmarc.status]);
  const domainMetCount = domainCheckStatuses.filter((s) => s === "pass").length;

  // The audit-logging gate only counts toward the total once it's actually
  // been synced - undefined (never synced) contributes to neither side
  // rather than silently counting as a miss.
  const auditTotal = snapshot.mailboxAuditingEnabled === undefined ? 0 : 1;
  const auditMet = snapshot.mailboxAuditingEnabled === true ? 1 : 0;

  const metCount = mdo.results.filter((r) => r.met).length + mailflow.results.filter((r) => r.met).length + domainMetCount + auditMet;
  const totalCount = mdo.results.length + mailflow.results.length + domainCheckStatuses.length + auditTotal;

  return { percent: totalCount > 0 ? Math.round((metCount / totalCount) * 100) : 0, metCount, totalCount };
}
