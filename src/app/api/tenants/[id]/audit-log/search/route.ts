import { NextRequest, NextResponse } from "next/server";
import { tenantStore } from "@/lib/services/tenant-store";
import { UnifiedAuditLogSearchFilters } from "@/lib/types";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest, { params }: { params: { id: string } }) {
  const tenant = tenantStore.getTenant(params.id);
  if (!tenant) {
    return NextResponse.json({ success: false, error: "Tenant not found" }, { status: 404 });
  }

  const sp = request.nextUrl.searchParams;
  const filters: UnifiedAuditLogSearchFilters = {
    search: sp.get("search") || undefined,
    operation: sp.get("operation") || undefined,
    operations: sp.get("operations") ? sp.get("operations")!.split(",").filter(Boolean) : undefined,
    recordType: sp.get("recordType") || undefined,
    workload: sp.get("workload") || undefined,
    userId: sp.get("userId") || undefined,
    sessionId: sp.get("sessionId") || undefined,
    clientInfo: sp.get("clientInfo") || undefined,
    startDate: sp.get("startDate") || undefined,
    endDate: sp.get("endDate") || undefined,
    importId: sp.get("importId") || undefined,
    page: sp.get("page") ? Number(sp.get("page")) : undefined,
    pageSize: sp.get("pageSize") ? Number(sp.get("pageSize")) : undefined,
    sortDirection: sp.get("sortDirection") === "asc" ? "asc" : "desc",
  };

  const result = tenantStore.searchAuditLogRecords(tenant.id, filters);
  return NextResponse.json({ success: true, ...result });
}
