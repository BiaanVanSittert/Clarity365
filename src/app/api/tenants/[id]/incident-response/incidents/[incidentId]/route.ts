import { NextRequest, NextResponse } from "next/server";
import { tenantStore } from "@/lib/services/tenant-store";

export const dynamic = "force-dynamic";

export async function PATCH(
  request: NextRequest,
  { params }: { params: { id: string; incidentId: string } }
) {
  try {
    const { id, incidentId } = params;
    const body = await request.json();

    const tenant = tenantStore.getTenant(id);
    if (!tenant) {
      return NextResponse.json({ success: false, error: "Tenant not found" }, { status: 404 });
    }

    const result = tenantStore.updateSecurityIncident(id, incidentId, body);
    if (!result.success) {
      return NextResponse.json({ success: false, error: "Incident not found" }, { status: 404 });
    }

    return NextResponse.json({
      success: true,
      snapshot: result.snapshot,
    });
  } catch (error: any) {
    console.error("[Incident Response] Update Incident Error:", error);
    return NextResponse.json({ success: false, error: error.message || "Failed to update incident" }, { status: 500 });
  }
}
