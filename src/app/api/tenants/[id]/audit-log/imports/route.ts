import { NextRequest, NextResponse } from "next/server";
import { tenantStore } from "@/lib/services/tenant-store";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest, { params }: { params: { id: string } }) {
  const tenant = tenantStore.getTenant(params.id);
  if (!tenant) {
    return NextResponse.json({ success: false, error: "Tenant not found" }, { status: 404 });
  }
  const imports = tenantStore.getAuditLogImports(tenant.id);
  return NextResponse.json({ success: true, imports });
}

export async function DELETE(request: NextRequest, { params }: { params: { id: string } }) {
  const tenant = tenantStore.getTenant(params.id);
  if (!tenant) {
    return NextResponse.json({ success: false, error: "Tenant not found" }, { status: 404 });
  }
  const importId = request.nextUrl.searchParams.get("importId");
  if (!importId) {
    return NextResponse.json({ success: false, error: "importId query parameter is required" }, { status: 400 });
  }
  const deleted = tenantStore.deleteAuditLogImport(tenant.id, importId);
  if (!deleted) {
    return NextResponse.json({ success: false, error: "Import not found" }, { status: 404 });
  }
  return NextResponse.json({ success: true });
}
