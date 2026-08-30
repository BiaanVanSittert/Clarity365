import { NextResponse } from "next/server";
import { tenantStore } from "@/lib/services/tenant-store";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const wasteSummary = tenantStore.getFleetLicenseWaste();
    return NextResponse.json({ success: true, waste: wasteSummary });
  } catch (error: any) {
    return NextResponse.json({ success: false, error: error.message }, { status: 500 });
  }
}
