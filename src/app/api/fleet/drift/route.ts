import { NextRequest, NextResponse } from "next/server";
import { tenantStore } from "@/lib/services/tenant-store";
import { evaluateFleetDrift } from "@/lib/services/drift-analyzer";
import { realignTenantDrift } from "@/lib/services/fleet-operations";

export async function GET() {
  try {
    const tenants = tenantStore.getAllTenants();
    const snapshots = tenants
      .map((t) => tenantStore.getSnapshot(t.id))
      .filter((s): s is NonNullable<typeof s> => s !== null);

    const driftSummary = evaluateFleetDrift(snapshots);
    return NextResponse.json({ success: true, drift: driftSummary });
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { tenantId, findingIds } = body;

    if (!tenantId || !Array.isArray(findingIds) || findingIds.length === 0) {
      return NextResponse.json(
        { success: false, error: "Missing tenantId or findingIds array in request payload." },
        { status: 400 }
      );
    }

    const result = await realignTenantDrift(tenantId, findingIds);
    return NextResponse.json(result);
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}
