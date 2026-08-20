import { NextRequest, NextResponse } from "next/server";
import { tenantStore } from "@/lib/services/tenant-store";

export const dynamic = "force-dynamic";

export async function POST(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const { id } = params;
    const tenant = tenantStore.getTenant(id);
    if (!tenant) {
      return NextResponse.json({ success: false, error: "Tenant not found" }, { status: 404 });
    }

    const updatedSnapshot = await tenantStore.syncTenant(id);
    if (!updatedSnapshot) {
      return NextResponse.json({ success: false, error: "Sync failed to generate snapshot" }, { status: 500 });
    }

    return NextResponse.json({
      success: true,
      message: `Successfully synchronized live telemetry for '${tenant.displayName}'`,
      snapshot: updatedSnapshot,
    });
  } catch (error: any) {
    return NextResponse.json({ success: false, error: error.message || "Failed to sync tenant" }, { status: 500 });
  }
}
