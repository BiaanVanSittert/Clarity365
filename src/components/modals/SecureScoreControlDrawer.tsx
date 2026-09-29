import React, { useState } from "react";
import { Drawer } from "../common/Drawer";
import { StatusPill } from "../common/StatusPill";
import { SecureScoreControl } from "@/lib/types";
import { CA_BASELINE_STANDARDS } from "@/lib/data/baseline-definitions";
import { getSecureScoreRemediationGuide } from "@/lib/data/secure-score-remediation-guides";
import { getDeviceControlGuide } from "@/lib/data/device-secure-score-guides";
import { htmlToPlainText } from "@/lib/utils/html-to-text";
import { ExternalLink, Terminal, Copy, Check, ShieldAlert, Zap, Compass, Info, AlertTriangle, MapPin, Users } from "lucide-react";

interface SecureScoreControlDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  control: SecureScoreControl | null;
  onRequestCaDeploy: (baselineCode: string) => void;
  onNavigateToEndpointSecurity?: () => void;
}

const CA_CODE_PATTERN = /^CA\d{2}$/;

const IMPACT_STYLES: Record<string, string> = {
  Low: "text-emerald-700 dark:text-emerald-400",
  Moderate: "text-amber-700 dark:text-amber-400",
  High: "text-rose-700 dark:text-red-400",
  Unknown: "text-slate-500 dark:text-slate-400",
};

export const SecureScoreControlDrawer: React.FC<SecureScoreControlDrawerProps> = ({
  isOpen,
  onClose,
  control,
  onRequestCaDeploy,
  onNavigateToEndpointSecurity,
}) => {
  const [copied, setCopied] = useState(false);

  if (!control) return null;

  const handleCopy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard write failed (e.g. permission denied) - don't show a
      // false "Copied" success state.
    }
  };

  const matchedBaseline =
    control.deployment.type === "auto" && control.deployment.clarity365Action && CA_CODE_PATTERN.test(control.deployment.clarity365Action)
      ? CA_BASELINE_STANDARDS.find((b) => b.code === control.deployment.clarity365Action)
      : undefined;

  const remediationText = htmlToPlainText(control.remediationSummary);
  const remediationImpactText = htmlToPlainText(control.remediationImpact);
  const guide = getSecureScoreRemediationGuide(control.id);
  // Device-category controls: Graph's own userImpact/remediationImpact come
  // back as the literal string "Unknown" for every one of them (confirmed
  // live - see device-secure-score-guides.ts), so this authored map fills
  // real user-impact/mechanism/PowerShell content Graph never provides for
  // this category. Kept as a separate lookup from `guide` above (the
  // MDO/EXO/MIP "where to go" map) since its shape and purpose differ.
  const deviceGuide = getDeviceControlGuide(control.id);
  const wherePortal = guide || deviceGuide?.portal;
  const powershellCommand = control.powershellCommand || deviceGuide?.powershellCommand;
  const usingAuthoredPowershell = !control.powershellCommand && !!deviceGuide?.powershellCommand;

  return (
    <Drawer
      isOpen={isOpen}
      onClose={onClose}
      title={control.title}
      subtitle={`${control.id} · ${control.category}`}
      width="lg"
    >
      <div className="space-y-5">
        {/* Summary grid */}
        <div className="grid grid-cols-2 gap-3">
          <div className="p-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#E2E8F0] dark:border-slate-700 rounded-sm">
            <div className="text-[11px] text-slate-500 dark:text-slate-400 font-medium">Points Attained</div>
            <div className="text-sm font-mono font-bold text-slate-900 dark:text-slate-100 tabular-nums">
              {control.scoreCurrent} / {control.scoreMax}
            </div>
          </div>
          <div className="p-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#E2E8F0] dark:border-slate-700 rounded-sm">
            <div className="text-[11px] text-slate-500 dark:text-slate-400 font-medium">Status</div>
            <StatusPill
              status={control.status === "Completed" ? "pass" : control.status === "Partial" ? "warn" : "fail"}
              label={control.status}
              size="sm"
            />
          </div>
          <div className="p-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#E2E8F0] dark:border-slate-700 rounded-sm">
            <div className="text-[11px] text-slate-500 dark:text-slate-400 font-medium">User Impact</div>
            <div className={`text-xs font-semibold ${IMPACT_STYLES[control.userImpact]}`}>{control.userImpact}</div>
          </div>
          <div className="p-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#E2E8F0] dark:border-slate-700 rounded-sm">
            <div className="text-[11px] text-slate-500 dark:text-slate-400 font-medium">Implementation Cost</div>
            <div className={`text-xs font-semibold ${IMPACT_STYLES[control.implementationCost]}`}>{control.implementationCost}</div>
          </div>
        </div>

        {control.implementationStatus && (
          <div className="text-[11px] text-slate-500 dark:text-slate-400 font-mono">{control.implementationStatus}</div>
        )}

        {/* Why this matters */}
        <div className="space-y-1.5">
          <div className="text-[11px] font-semibold text-slate-900 dark:text-slate-100 uppercase tracking-wide flex items-center gap-1.5">
            <Info size={12} className="text-slate-600 dark:text-slate-400" />
            <span>Why This Matters</span>
          </div>
          <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">{control.description}</p>
          {control.threats && control.threats.length > 0 && (
            <div className="flex items-center gap-1.5 flex-wrap pt-1">
              {control.threats.map((t) => (
                <span
                  key={t}
                  className="px-1.5 py-0.5 text-[10px] font-medium bg-rose-50 dark:bg-red-950 text-rose-700 dark:text-red-400 border border-rose-200 dark:border-red-800 rounded-sm flex items-center gap-1"
                >
                  <ShieldAlert size={10} />
                  {t}
                </span>
              ))}
            </div>
          )}
        </div>

        {/* User impact (authored) - only shown when Graph's own userImpact
            field is the literal "Unknown" it returns for every Device
            control, and Clarity365 has authored a real assessment. */}
        {control.userImpact === "Unknown" && deviceGuide?.userImpact && (
          <div className="space-y-1.5">
            <div className="text-[11px] font-semibold text-slate-900 dark:text-slate-100 uppercase tracking-wide flex items-center gap-1.5">
              <Users size={12} className="text-slate-600 dark:text-slate-400" />
              <span>User Impact</span>
            </div>
            <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">{deviceGuide.userImpact}</p>
          </div>
        )}

        {/* How to fix */}
        <div className="space-y-1.5">
          <div className="text-[11px] font-semibold text-slate-900 dark:text-slate-100 uppercase tracking-wide flex items-center gap-1.5">
            <Compass size={12} className="text-slate-600 dark:text-slate-400" />
            <span>How To Fix</span>
          </div>
          {wherePortal && (
            <div className="p-2 bg-blue-50 dark:bg-blue-950 border border-blue-200 dark:border-blue-800 rounded-sm text-[11px] text-blue-900 dark:text-blue-300 flex items-start gap-1.5">
              <MapPin size={12} className="mt-0.5 shrink-0" />
              <div>
                <span className="font-semibold">Where to go: </span>
                {guide ? `${guide.portalName} → ${guide.navPath.join(" → ")}` : `${deviceGuide!.portal!.name} → ${deviceGuide!.portal!.navPath.join(" → ")}`}
              </div>
            </div>
          )}
          {deviceGuide?.clarity365Action && (
            <div className="p-2 bg-amber-50 dark:bg-amber-950 border border-amber-200 dark:border-amber-800 rounded-sm text-[11px] text-amber-900 dark:text-amber-300 flex items-start gap-1.5">
              <Zap size={12} className="mt-0.5 shrink-0" />
              <div>
                <span className="font-semibold">Clarity365 already has this: </span>
                {deviceGuide.clarity365Action}
              </div>
            </div>
          )}
          <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed whitespace-pre-line">
            {remediationText || "No remediation guidance available for this control."}
          </p>
          {remediationImpactText && remediationImpactText !== "Unknown" && (
            <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-relaxed">
              <span className="font-semibold text-slate-700 dark:text-slate-300">Impact of applying this fix: </span>
              {remediationImpactText}
            </p>
          )}
          {deviceGuide?.caveats && deviceGuide.caveats.length > 0 && (
            <ul className="space-y-1 pt-0.5">
              {deviceGuide.caveats.map((c, i) => (
                <li key={i} className="text-[11px] text-amber-800 dark:text-amber-400 leading-relaxed flex items-start gap-1.5">
                  <AlertTriangle size={11} className="mt-0.5 shrink-0" />
                  <span>{c}</span>
                </li>
              ))}
            </ul>
          )}
          {control.actionUrl ? (
            <a
              href={control.actionUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-xs font-medium text-blue-700 dark:text-blue-400 hover:underline pt-1"
            >
              <ExternalLink size={12} />
              Open in Microsoft Admin Center
            </a>
          ) : guide ? (
            <a
              href={guide.url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-xs font-medium text-blue-700 dark:text-blue-400 hover:underline pt-1"
            >
              <ExternalLink size={12} />
              Open {guide.portalName}
            </a>
          ) : deviceGuide?.portal ? (
            <a
              href={deviceGuide.portal.url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-xs font-medium text-blue-700 dark:text-blue-400 hover:underline pt-1"
            >
              <ExternalLink size={12} />
              Open {deviceGuide.portal.name}
            </a>
          ) : null}
        </div>

        {/* PowerShell - Graph's own powershellCommand first, falling back to
            Clarity365's authored command (verified live source, not Graph)
            for controls Graph never provides one for - all 44 Device
            controls in this group are the latter. */}
        {powershellCommand && (
          <div>
            <div className="flex items-center justify-between bg-slate-900 px-3 py-1.5 rounded-t-sm border border-slate-800">
              <div className="flex items-center gap-2 text-[11px] font-mono text-slate-300">
                <Terminal size={13} className="text-emerald-400" />
                <span>PowerShell</span>
              </div>
              <button
                onClick={() => handleCopy(powershellCommand!)}
                className="flex items-center gap-1 text-[11px] text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 px-2 py-0.5 rounded-sm transition-colors"
              >
                {copied ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                <span>{copied ? "Copied" : "Copy"}</span>
              </button>
            </div>
            <pre className="p-3 bg-slate-950 text-slate-200 font-mono text-[11px] overflow-x-auto rounded-b-sm border-x border-b border-slate-800 leading-relaxed max-h-40">
              <code>{powershellCommand}</code>
            </pre>
            {usingAuthoredPowershell && deviceGuide?.powershellCaveat && (
              <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-relaxed pt-1.5 flex items-start gap-1.5">
                <AlertTriangle size={11} className="mt-0.5 shrink-0 text-amber-500" />
                <span>{deviceGuide.powershellCaveat}</span>
              </p>
            )}
          </div>
        )}

        {/* Deployment action */}
        <div className="p-3 border rounded-sm space-y-2 bg-[#F8FAFC] dark:bg-slate-900/50 border-[#CBD5E1] dark:border-slate-700">
          {matchedBaseline ? (
            <>
              <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-900 dark:text-slate-100">
                <Zap size={13} className="text-amber-500" />
                <span>Clarity365 can deploy this directly</span>
              </div>
              <p className="text-[11px] text-slate-600 dark:text-slate-400 leading-relaxed">
                This control is satisfied by <strong>{matchedBaseline.code}: {matchedBaseline.name}</strong>, which Clarity365 can create via Microsoft Graph in Report-Only mode.
              </p>
              <button
                onClick={() => onRequestCaDeploy(matchedBaseline.code)}
                className="px-3 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-sm flex items-center gap-1.5 transition-colors shadow-sm"
              >
                <Zap size={13} className="text-amber-400" />
                <span>Deploy {matchedBaseline.code} to Tenant</span>
              </button>
            </>
          ) : control.deployment.type === "auto" && control.deployment.clarity365Action ? (
            <>
              <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-900 dark:text-slate-100">
                <Zap size={13} className="text-amber-500" />
                <span>Managed in another Clarity365 module</span>
              </div>
              <p className="text-[11px] text-slate-600 dark:text-slate-400 leading-relaxed">
                This control improves as devices come into compliance with a policy Clarity365 already deploys in Endpoint Security. Deploying/redeploying it there should move this score over time.
              </p>
              {onNavigateToEndpointSecurity && (
                <button
                  onClick={onNavigateToEndpointSecurity}
                  className="px-3 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-sm flex items-center gap-1.5 transition-colors shadow-sm"
                >
                  <Compass size={13} />
                  <span>Open Endpoint Security</span>
                </button>
              )}
            </>
          ) : control.deployment.type === "guided" ? (
            <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-700 dark:text-slate-300">
              <Compass size={13} className="text-slate-500 dark:text-slate-400" />
              <span>Guided fix - no one-click deploy for this control yet. Follow the steps above or use the admin center link.</span>
            </div>
          ) : (
            <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-700 dark:text-slate-300">
              <AlertTriangle size={13} className="text-slate-500 dark:text-slate-400" />
              <span>Manual action required - not scriptable (e.g. a purchasing decision or org-wide behavior change).</span>
            </div>
          )}
        </div>
      </div>
    </Drawer>
  );
};
