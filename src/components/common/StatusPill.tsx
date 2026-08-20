import React from "react";
import { CheckCircle2, AlertTriangle, AlertCircle, Info, ShieldCheck, ShieldAlert, ShieldX } from "lucide-react";
import { TrafficStatus } from "@/lib/types";

interface StatusPillProps {
  status:
    | TrafficStatus
    | "enabled"
    | "disabled"
    | "reportOnly"
    | "enabledForReportingButNotEnforced"
    | "compliant"
    | "noncompliant"
    | "critical"
    | "warning"
    | "substandard"
    | "high"
    | "moderate"
    | "medium"
    | "low"
    | "none"
    | string;
  label?: string;
  size?: "sm" | "md";
  showIcon?: boolean;
  className?: string;
}

export const StatusPill: React.FC<StatusPillProps> = ({
  status,
  label,
  size = "sm",
  showIcon = true,
  className = "",
}) => {
  let normalizedStatus: TrafficStatus = "info";
  let defaultLabel = label;
  let IconComponent = Info;

  switch (status) {
    case "pass":
    case "compliant":
    case "enabled":
      normalizedStatus = "pass";
      defaultLabel = label || (status === "enabled" ? "Enabled" : "Compliant");
      IconComponent = CheckCircle2;
      break;

    case "warn":
    case "warning":
    case "substandard":
    case "reportOnly":
    case "enabledForReportingButNotEnforced":
    case "moderate":
    case "medium":
      normalizedStatus = "warn";
      defaultLabel =
        label ||
        (status === "reportOnly" || status === "enabledForReportingButNotEnforced"
          ? "Report-Only"
          : status === "moderate"
          ? "Moderate"
          : "Warning");
      IconComponent = AlertTriangle;
      break;

    case "fail":
    case "critical":
    case "noncompliant":
    case "high":
      normalizedStatus = "fail";
      defaultLabel = label || (status === "noncompliant" ? "Non-Compliant" : "Critical");
      IconComponent = AlertCircle;
      break;

    case "disabled":
    case "low":
    case "none":
    case "info":
    default:
      normalizedStatus = "info";
      defaultLabel = label || (status === "disabled" ? "Disabled" : String(status));
      IconComponent = Info;
      break;
  }

  const styles = {
    pass: "bg-[#ECFDF5] border-[#10B981] text-[#065F46]",
    warn: "bg-[#FFFBEB] border-[#F59E0B] text-[#92400E]",
    fail: "bg-[#FEF2F2] border-[#EF4444] text-[#991B1B]",
    info: "bg-[#F1F5F9] border-[#CBD5E1] text-[#334155]",
  };

  const sizeClasses = size === "sm" ? "px-2 py-0.5 text-[11px]" : "px-2.5 py-1 text-xs";
  const iconSize = size === "sm" ? 12 : 14;

  return (
    <span
      className={`inline-flex items-center gap-1.5 font-medium border rounded-sm tracking-tight select-none ${styles[normalizedStatus]} ${sizeClasses} ${className}`}
    >
      {showIcon && <IconComponent size={iconSize} className="shrink-0" />}
      <span className="truncate">{defaultLabel}</span>
    </span>
  );
};
