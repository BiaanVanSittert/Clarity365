import { NextRequest, NextResponse } from "next/server";
import crypto from "crypto";
import { tenantStore } from "@/lib/services/tenant-store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Purview CSV exports can be large (up to 1,000,000 rows on Audit Premium) -
// Route Handlers reading multipart form data aren't subject to Next's
// Server-Action body-size limit, so no explicit size cap is imposed here
// beyond available memory/time.
export async function POST(request: NextRequest, { params }: { params: { id: string } }) {
  const tenant = tenantStore.getTenant(params.id);
  if (!tenant) {
    return NextResponse.json({ success: false, error: "Tenant not found" }, { status: 404 });
  }

  let formData: FormData;
  try {
    formData = await request.formData();
  } catch {
    return NextResponse.json({ success: false, error: "Expected multipart/form-data with a 'file' field" }, { status: 400 });
  }

  const file = formData.get("file");
  if (!(file instanceof File)) {
    return NextResponse.json({ success: false, error: "No file uploaded" }, { status: 400 });
  }
  if (!file.name.toLowerCase().endsWith(".csv")) {
    return NextResponse.json({ success: false, error: "Only .csv files are supported" }, { status: 400 });
  }

  const importId = crypto.randomUUID();
  tenantStore.startAuditImportProgress(tenant.id, importId, file.name);

  try {
    const importRecord = await tenantStore.ingestAuditLogCsv(tenant.id, importId, file.name, file.stream());
    return NextResponse.json({ success: true, import: importRecord });
  } catch (error: any) {
    return NextResponse.json({ success: false, error: error.message || "Failed to import CSV" }, { status: 500 });
  } finally {
    tenantStore.clearAuditImportProgress(tenant.id);
  }
}
