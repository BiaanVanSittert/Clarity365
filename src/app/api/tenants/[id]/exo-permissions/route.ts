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

    const result = await tenantStore.testExoConnectivity(id);
    if (!result) {
      return NextResponse.json({ success: false, error: "Failed to test Exchange Online connectivity" }, { status: 500 });
    }

    return NextResponse.json({
      success: true,
      result,
    });
  } catch (error: any) {
    return NextResponse.json({ success: false, error: error.message || "Failed to test Exchange Online connectivity" }, { status: 500 });
  }
}
