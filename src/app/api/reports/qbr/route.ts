import { NextRequest, NextResponse } from "next/server";
import { tenantStore } from "@/lib/services/tenant-store";
import { generateTenantQbrReport } from "@/lib/services/report-generator";

export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const tenantId = searchParams.get("tenantId");
    const period = searchParams.get("period") || "Q3 2026";
    const mspName = searchParams.get("mspName");
    const preparedBy = searchParams.get("preparedBy");

    if (!tenantId) {
      return NextResponse.json(
        { success: false, error: "Query parameter 'tenantId' is required." },
        { status: 400 }
      );
    }

    const snapshot = tenantStore.getSnapshot(tenantId);
    if (!snapshot) {
      return NextResponse.json(
        { success: false, error: `Tenant snapshot for '${tenantId}' not found.` },
        { status: 404 }
      );
    }

    const report = generateTenantQbrReport(snapshot, period, {
      ...(mspName ? { mspName } : {}),
      ...(preparedBy ? { preparedBy } : {}),
    });

    return NextResponse.json({ success: true, report });
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}
