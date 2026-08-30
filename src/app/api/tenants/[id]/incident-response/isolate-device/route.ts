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
    const { deviceId, deviceName, comment } = body;

    if (!deviceId) {
      return NextResponse.json({ success: false, error: "Missing required parameter: deviceId" }, { status: 400 });
    }

    const tenant = tenantStore.getTenant(id);
    if (!tenant) {
      return NextResponse.json({ success: false, error: "Tenant not found" }, { status: 404 });
    }

    const result = await tenantStore.isolateEndpointDevice(id, deviceId, deviceName || deviceId, comment);

    return NextResponse.json({
      success: result.success,
      error: result.error,
      snapshot: result.snapshot,
    });
  } catch (error: any) {
    console.error("[Incident Response] Isolate Device Error:", error);
    return NextResponse.json({ success: false, error: error.message || "Device isolation failed" }, { status: 500 });
  }
}
