import { NextRequest, NextResponse } from "next/server";
import { tenantStore } from "@/lib/services/tenant-store";

export const dynamic = "force-dynamic";

export async function PATCH(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const { id } = params;
    const body = await request.json();
    const { connectorId, patch } = body;

    if (!connectorId || !patch) {
      return NextResponse.json({ success: false, error: "Missing connectorId or patch parameter" }, { status: 400 });
    }

    const tenant = tenantStore.getTenant(id);
    if (!tenant) {
      return NextResponse.json({ success: false, error: "Tenant not found" }, { status: 404 });
    }
    if (tenant.endpointSecurityWriteMode !== "write_enabled") {
      return NextResponse.json(
        { success: false, error: "Endpoint Security write mode is not enabled for this tenant - turn it on in the Defender Config module first." },
        { status: 400 }
      );
    }

    const result = await tenantStore.updateMdeConnectorSettings(id, connectorId, patch);
    if (!result.success) {
      return NextResponse.json({ success: false, error: result.error || "Failed to update MDE connector settings" }, { status: 500 });
    }

    return NextResponse.json({
      success: true,
      message: `Updated MDE connector settings on '${tenant.displayName}'.`,
      snapshot: result.snapshot,
    });
  } catch (error: any) {
    return NextResponse.json({ success: false, error: error.message || "Failed to update MDE connector settings" }, { status: 500 });
  }
}
