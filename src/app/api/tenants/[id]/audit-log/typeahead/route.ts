import { NextRequest, NextResponse } from "next/server";
import { tenantStore } from "@/lib/services/tenant-store";

export const dynamic = "force-dynamic";

const VALID_FIELDS = ["sessionId", "userId", "clientInfo"] as const;

export async function GET(request: NextRequest, { params }: { params: { id: string } }) {
  const tenant = tenantStore.getTenant(params.id);
  if (!tenant) {
    return NextResponse.json({ success: false, error: "Tenant not found" }, { status: 404 });
  }
  const sp = request.nextUrl.searchParams;
  const field = sp.get("field") as (typeof VALID_FIELDS)[number] | null;
  const query = sp.get("q") || "";
  if (!field || !VALID_FIELDS.includes(field)) {
    return NextResponse.json({ success: false, error: "field must be one of sessionId, userId, clientInfo" }, { status: 400 });
  }
  const suggestions = tenantStore.getAuditLogTypeahead(tenant.id, field, query);
  return NextResponse.json({ success: true, suggestions });
}
