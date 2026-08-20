import { NextResponse } from "next/server";
import { tenantStore } from "@/lib/services/tenant-store";

export async function POST(request: Request, { params }: { params: { id: string } }) {
  try {
    const { id } = params;
    const body = await request.json();
    const created = tenantStore.addGroup(id, body);
    if (!created) {
      return NextResponse.json({ success: false, error: "Tenant not found." }, { status: 404 });
    }
    return NextResponse.json({ success: true, group: created });
  } catch (error: any) {
    return NextResponse.json({ success: false, error: error.message }, { status: 500 });
  }
}
