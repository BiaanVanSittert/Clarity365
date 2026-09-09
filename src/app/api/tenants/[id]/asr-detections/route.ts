import { NextRequest, NextResponse } from "next/server";
import { tenantStore } from "@/lib/services/tenant-store";

export const dynamic = "force-dynamic";

// On-demand Advanced Hunting data for the Attack Surface Reduction module -
// deliberately not part of the tenant sync (see graph-client.fetchAsrDetectionSummaries).
// A missing-permission/license response is a graceful { success: false, error }
// at HTTP 200, not a 500 - it's an expected outcome on many tenants, not a bug.
export async function POST(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const { id } = params;
    const body = await request.json().catch(() => ({}));
    const { ruleId } = body;

    const tenant = tenantStore.getTenant(id);
    if (!tenant) {
      return NextResponse.json({ success: false, error: "Tenant not found" }, { status: 404 });
    }

    if (ruleId) {
      const result = await tenantStore.getAsrDetectionEvents(id, ruleId);
      if (!result) {
        return NextResponse.json({ success: false, error: "Tenant not found" }, { status: 404 });
      }
      if (result.error) {
        return NextResponse.json({ success: false, error: result.error });
      }
      return NextResponse.json({ success: true, events: result.events || [] });
    }

    const result = await tenantStore.getAsrDetectionSummaries(id);
    if (!result) {
      return NextResponse.json({ success: false, error: "Tenant not found" }, { status: 404 });
    }
    if (result.error) {
      return NextResponse.json({ success: false, error: result.error });
    }
    return NextResponse.json({ success: true, summaries: result.summaries || [] });
  } catch (error: any) {
    return NextResponse.json(
      { success: false, error: error.message || "Failed to fetch ASR detection activity" },
      { status: 500 }
    );
  }
}
