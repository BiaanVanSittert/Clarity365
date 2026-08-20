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
    const { baselineCode } = body;

    if (!baselineCode) {
      return NextResponse.json({ success: false, error: "Missing baselineCode parameter" }, { status: 400 });
    }

    const tenant = tenantStore.getTenant(id);
    if (!tenant) {
      return NextResponse.json({ success: false, error: "Tenant not found" }, { status: 404 });
    }

    const result = await tenantStore.deployBaselinePolicy(id, baselineCode);
    if (!result.success) {
      return NextResponse.json({ success: false, error: result.error || "Failed to deploy policy" }, { status: 500 });
    }

    return NextResponse.json({
      success: true,
      message: `Successfully created ${baselineCode} in Report-Only mode on '${tenant.displayName}'`,
      policy: result.policy,
      snapshot: result.snapshot,
    });
  } catch (error: any) {
    return NextResponse.json({ success: false, error: error.message || "Failed to deploy policy" }, { status: 500 });
  }
}
