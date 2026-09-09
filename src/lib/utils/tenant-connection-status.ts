import { Tenant } from "@/lib/types";

export interface ConnectionStatusDisplay {
  pillStatus: "pass" | "warn" | "fail";
  label: string;
}

// Single source of truth for connectionStatus -> display. Both the Fleet
// Posture Matrix and the per-tenant header badge must call this instead of
// re-deriving their own label logic - two independent copies of this switch
// previously drifted apart (one treated any non-healthy/non-degraded status
// as "Error", the other as "Degraded"), showing conflicting statuses for the
// same tenant.
export function getConnectionStatusDisplay(
  status: Tenant["connectionStatus"],
  context: "fleet" | "header" = "fleet"
): ConnectionStatusDisplay {
  switch (status) {
    case "healthy":
      return { pillStatus: "pass", label: context === "header" ? "Sync Healthy" : "Healthy" };
    case "degraded":
      return { pillStatus: "warn", label: "Degraded" };
    case "error":
      return { pillStatus: "fail", label: "Error" };
    case "disconnected":
      return { pillStatus: "fail", label: "Not Connected" };
  }
}
