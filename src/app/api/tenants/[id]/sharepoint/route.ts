import { NextResponse } from "next/server";
import { tenantStore } from "@/lib/services/tenant-store";

export async function PUT(request: Request, { params }: { params: { id: string } }) {
  try {
    const { id } = params;
    const body = await request.json();
    const updated = tenantStore.updateSharePointPolicy(id, body);
    if (!updated) {
      return NextResponse.json({ success: false, error: "Tenant not found." }, { status: 404 });
    }
    return NextResponse.json({ success: true, sharePoint: updated });
  } catch (error: any) {
    return NextResponse.json({ success: false, error: error.message }, { status: 500 });
  }
}
