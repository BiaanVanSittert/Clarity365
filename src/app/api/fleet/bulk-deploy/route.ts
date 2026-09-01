import { NextRequest, NextResponse } from "next/server";
import { executeBulkCaDeployment } from "@/lib/services/fleet-operations";
import { FleetBulkDeployRequest } from "@/lib/types";

export async function POST(req: NextRequest) {
  try {
    const body = (await req.json()) as FleetBulkDeployRequest;

    if (!Array.isArray(body.baselineCodes) || body.baselineCodes.length === 0) {
      return NextResponse.json(
        { success: false, error: "Must specify at least one baseline code in baselineCodes array." },
        { status: 400 }
      );
    }

    if (!Array.isArray(body.targetTenantIds) || body.targetTenantIds.length === 0) {
      return NextResponse.json(
        { success: false, error: "Must specify at least one target tenant in targetTenantIds array." },
        { status: 400 }
      );
    }

    const result = await executeBulkCaDeployment(body);
    return NextResponse.json({ success: true, result });
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}
