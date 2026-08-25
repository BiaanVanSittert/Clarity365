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

    const result = await tenantStore.syncTenant(id, "manual");
    if (!result || !result.snapshot) {
      return NextResponse.json(
        { success: false, error: result?.error || "Sync failed to generate snapshot" },
        { status: 502 }
      );
    }

    return NextResponse.json({
      success: result.outcome === "synced",
      stale: result.outcome === "stale_fallback",
      error: result.outcome === "stale_fallback" ? result.error : undefined,
      message: `Successfully synchronized live telemetry for '${tenant.displayName}'`,
      snapshot: result.snapshot,
    });
  } catch (error: any) {
    return NextResponse.json({ success: false, error: error.message || "Failed to sync tenant" }, { status: 500 });
  }
}
