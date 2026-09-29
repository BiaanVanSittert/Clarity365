import { NextRequest, NextResponse } from "next/server";
import { tenantStore } from "@/lib/services/tenant-store";

export const dynamic = "force-dynamic";

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string; sessionId: string } }
) {
  const tenant = tenantStore.getTenant(params.id);
  if (!tenant) {
    return NextResponse.json({ success: false, error: "Tenant not found" }, { status: 404 });
  }
  const records = tenantStore.getAuditLogSessionTimeline(tenant.id, decodeURIComponent(params.sessionId));
  return NextResponse.json({ success: true, records });
}
