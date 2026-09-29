import { NextRequest, NextResponse } from "next/server";
import { tenantStore } from "@/lib/services/tenant-store";

export const dynamic = "force-dynamic";

export async function POST(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const { id } = params;
    const body = await request.json();
    const { modes, assignment } = body;

    if (!modes || !assignment) {
      return NextResponse.json({ success: false, error: "Missing modes or assignment parameter" }, { status: 400 });
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

    const wasAlreadyDeployed = !!tenantStore.getSnapshot(id)?.intune?.clarity365AsrPolicyId;

    const result = await tenantStore.deployAsrRules(id, modes, assignment);
    if (!result.success) {
      return NextResponse.json({ success: false, error: result.error || "Failed to deploy ASR rules" }, { status: 500 });
    }

    return NextResponse.json({
      success: true,
      message: `${wasAlreadyDeployed ? "Updated" : "Deployed"} ASR rules policy on '${tenant.displayName}' (assignment: ${assignment.mode}).`,
      policyId: result.policyId,
      snapshot: result.snapshot,
    });
  } catch (error: any) {
    return NextResponse.json({ success: false, error: error.message || "Failed to deploy ASR rules" }, { status: 500 });
  }
}
