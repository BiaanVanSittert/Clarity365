import { NextResponse } from "next/server";
import { tenantStore } from "@/lib/services/tenant-store";

export async function GET(request: Request, { params }: { params: { id: string } }) {
  try {
    const { id } = params;
    const snapshot = tenantStore.getSnapshot(id);
    if (!snapshot) {
      return NextResponse.json({ success: false, error: `Tenant snapshot for '${id}' not found.` }, { status: 404 });
    }
    return NextResponse.json({ success: true, snapshot });
  } catch (error: any) {
    return NextResponse.json({ success: false, error: error.message }, { status: 500 });
  }
}

export async function PUT(request: Request, { params }: { params: { id: string } }) {
  try {
    const { id } = params;
    const body = await request.json();
    const updated = tenantStore.updateTenant(id, body);
    if (!updated) {
      return NextResponse.json({ success: false, error: `Tenant '${id}' not found.` }, { status: 404 });
    }
    return NextResponse.json({ success: true, tenant: updated });
  } catch (error: any) {
    return NextResponse.json({ success: false, error: error.message }, { status: 500 });
  }
}
