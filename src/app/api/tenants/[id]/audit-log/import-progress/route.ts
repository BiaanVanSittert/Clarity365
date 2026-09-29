import { NextRequest, NextResponse } from "next/server";
import { getAuditImportProgress } from "@/lib/services/tenant-store";

export const dynamic = "force-dynamic";

// Polled while a CSV import is in flight - same convention as
// /api/tenants/[id]/sync-progress, but reports a live rows-processed counter
// instead of a step index/percentage, since a streaming CSV parse doesn't
// know the total row count until it reaches the end of the file.
export async function GET(request: NextRequest, { params }: { params: { id: string } }) {
  const progress = getAuditImportProgress(params.id);
  if (!progress) {
    return NextResponse.json({ inProgress: false });
  }
  return NextResponse.json({ inProgress: true, ...progress });
}
