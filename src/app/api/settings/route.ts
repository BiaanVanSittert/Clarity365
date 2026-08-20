import { NextResponse } from "next/server";
import { tenantStore } from "@/lib/services/tenant-store";

export async function GET() {
  const settings = tenantStore.getSettings();
  return NextResponse.json({ success: true, settings });
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const updated = tenantStore.updateSettings(body);
    return NextResponse.json({ success: true, settings: updated });
  } catch (error: any) {
    return NextResponse.json({ success: false, error: error.message }, { status: 500 });
  }
}
