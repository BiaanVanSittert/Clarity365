// Fallback "why this matters" text for the rare control where Microsoft's
// own Secure Score data genuinely has no description at all.
//
// Live-audited before assuming this needed 70+ authored entries: the
// "No description available" text most security engineers were actually
// seeing turned out to be a STALE-SNAPSHOT problem, not a real Graph gap -
// TenantSecuritySnapshot has no migration step (see [[Optimization Plan]]'s
// tenth variant), and a tenant that hadn't been re-synced recently was
// showing an old secureScores entry from before Microsoft started populating
// controlScores[].description. A fresh sync against a real tenant
// (Coetzee Architects) recovered real Microsoft-authored descriptions for
// 69 of 70 controls immediately. Only one control's description is genuinely
// blank straight from Microsoft, confirmed live: `mdo_autoforwardingmode`.
//
// Keyed by the real Graph controlName. Extend this map only for a control
// confirmed live (via a fresh sync) to have no description of its own -
// don't add speculative entries for controls that just haven't been
// re-synced recently.
export const SECURE_SCORE_DESCRIPTION_FALLBACKS: Record<string, string> = {
  mdo_autoforwardingmode:
    "Automatic forwarding rules are a common way attackers exfiltrate mail from a compromised mailbox without the user noticing - a rule silently copies incoming mail to an external address. Setting the outbound anti-spam policy's forwarding option to system-controlled (or disabling it outright) removes that path instead of leaving it to each mailbox's own configuration.",
};

export function getSecureScoreDescriptionFallback(controlId: string): string | undefined {
  return SECURE_SCORE_DESCRIPTION_FALLBACKS[controlId];
}
