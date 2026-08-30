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
    const { deviceId, deviceName, scanType = "quickScan" } = body;

    if (!deviceId) {
      return NextResponse.json({ success: false, error: "Missing required parameter: deviceId" }, { status: 400 });
    }

    const tenant = tenantStore.getTenant(id);
    if (!tenant) {
      return NextResponse.json({ success: false, error: "Tenant not found" }, { status: 404 });
    }

    const result = await tenantStore.scanEndpointDevice(id, deviceId, deviceName || deviceId, scanType);

    return NextResponse.json({
      success: result.success,
      error: result.error,
    });
  } catch (error: any) {
    console.error("[Incident Response] Scan Device Error:", error);
    return NextResponse.json({ success: false, error: error.message || "Device scan trigger failed" }, { status: 500 });
  }
}
