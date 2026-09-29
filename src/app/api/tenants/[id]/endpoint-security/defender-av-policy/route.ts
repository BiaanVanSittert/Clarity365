import { NextRequest, NextResponse } from "next/server";
import { tenantStore } from "@/lib/services/tenant-store";

export const dynamic = "force-dynamic";

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const { id } = params;
    const tenant = tenantStore.getTenant(id);
    if (!tenant) {
      return NextResponse.json({ success: false, error: "Tenant not found" }, { status: 404 });
    }

    const result = await tenantStore.getDefenderAvPolicy(id);
    if (result.error) {
      return NextResponse.json({ success: false, error: result.error }, { status: 500 });
    }
    return NextResponse.json({ success: true, deployedPolicyId: result.deployedPolicyId, settings: result.settings });
  } catch (error: any) {
    return NextResponse.json({ success: false, error: error.message || "Failed to fetch Defender Antivirus policy" }, { status: 500 });
  }
}

export async function POST(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const { id } = params;
    const body = await request.json();
    const { settings, assignment } = body;

    if (!settings || !assignment) {
      return NextResponse.json({ success: false, error: "Missing settings or assignment parameter" }, { status: 400 });
    }

    const tenant = tenantStore.getTenant(id);
    if (!tenant) {
      return NextResponse.json({ success: false, error: "Tenant not found" }, { status: 404 });
    }
    if (tenant.endpointSecurityWriteMode !== "write_enabled") {
      return NextResponse.json(
        { success: false, error: "Endpoint Security write mode is not enabled for this tenant - turn it on in the Defender Config module first." },
        { status: 400 }
      );
    }

    const wasAlreadyDeployed = !!tenantStore.getSnapshot(id)?.intune?.defenderAvPolicy?.deployedPolicyId;

    const result = await tenantStore.deployDefenderAvPolicy(id, settings, assignment);
    if (!result.success) {
      return NextResponse.json({ success: false, error: result.error || "Failed to deploy Defender Antivirus policy" }, { status: 500 });
    }

    return NextResponse.json({
      success: true,
      message: `${wasAlreadyDeployed ? "Updated" : "Deployed"} Defender Antivirus policy on '${tenant.displayName}' (assignment: ${assignment.mode}).`,
      policyId: result.policyId,
      snapshot: result.snapshot,
    });
  } catch (error: any) {
    return NextResponse.json({ success: false, error: error.message || "Failed to deploy Defender Antivirus policy" }, { status: 500 });
  }
}
