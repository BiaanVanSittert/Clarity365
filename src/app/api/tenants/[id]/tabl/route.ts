import { NextResponse } from "next/server";
import { tenantStore } from "@/lib/services/tenant-store";

export async function POST(request: Request, { params }: { params: { id: string } }) {
  try {
    const { id } = params;
    const body = await request.json();
    const created = tenantStore.addTablEntry(id, body);
    if (!created) {
      return NextResponse.json({ success: false, error: "Tenant not found." }, { status: 404 });
    }
    return NextResponse.json({ success: true, entry: created });
  } catch (error: any) {
    return NextResponse.json({ success: false, error: error.message }, { status: 500 });
  }
}

export async function DELETE(request: Request, { params }: { params: { id: string } }) {
  try {
    const { id } = params;
    const { searchParams } = new URL(request.url);
    const entryId = searchParams.get("entryId");
    if (!entryId) {
      return NextResponse.json({ success: false, error: "Missing entryId." }, { status: 400 });
    }
    const removed = tenantStore.removeTablEntry(id, entryId);
    return NextResponse.json({ success: removed });
  } catch (error: any) {
    return NextResponse.json({ success: false, error: error.message }, { status: 500 });
  }
}
