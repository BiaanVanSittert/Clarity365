import { NextRequest, NextResponse } from "next/server";
import { tenantStore } from "@/lib/services/tenant-store";

export const dynamic = "force-dynamic";

export async function POST(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const { id } = params;
    const tenant = tenantStore.getTenant(id);
    if (!tenant) {
      return NextResponse.json({ success: false, error: "Tenant not found" }, { status: 404 });
    }

    const outcome = await tenantStore.startExoConnect(id);
    if (!outcome || outcome.error || !outcome.result) {
      return NextResponse.json(
        { success: false, error: outcome?.error || "Failed to start Exchange Online sign-in" },
        { status: 500 }
      );
    }

    return NextResponse.json({
      success: true,
      result: outcome.result,
    });
  } catch (error: any) {
    return NextResponse.json({ success: false, error: error.message || "Failed to start Exchange Online sign-in" }, { status: 500 });
  }
}
