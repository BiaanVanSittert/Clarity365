import { NextRequest, NextResponse } from "next/server";
import { tenantStore } from "@/lib/services/tenant-store";
import {
  evaluateTenantCompliance,
  evaluateFleetCompliance,
} from "@/lib/services/compliance-evaluator";
import { ComplianceFramework } from "@/lib/types";

export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const tenantId = searchParams.get("tenantId");
    const framework = (searchParams.get("framework") as ComplianceFramework) || "cis_m365_v3";

    if (tenantId && tenantId !== "fleet") {
      const snapshot = tenantStore.getSnapshot(tenantId);
      if (!snapshot) {
        return NextResponse.json(
          { success: false, error: `Tenant snapshot for '${tenantId}' not found.` },
          { status: 404 }
        );
      }
      const assessment = evaluateTenantCompliance(snapshot, framework);
      return NextResponse.json({ success: true, assessment });
    }

    // Fleet-wide summary
    const tenants = tenantStore.getAllTenants();
    const snapshots = tenants
      .map((t) => tenantStore.getSnapshot(t.id))
      .filter(Boolean) as any[];

    const fleetSummary = evaluateFleetCompliance(snapshots, framework);
    return NextResponse.json({ success: true, fleetSummary });
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}
