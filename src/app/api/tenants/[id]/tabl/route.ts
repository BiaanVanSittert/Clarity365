import { NextResponse } from "next/server";
import { tenantStore } from "@/lib/services/tenant-store";

export async function POST(request: Request, { params }: { params: { id: string } }) {
  try {
    const { id } = params;
    const body = await request.json();
    const result = await tenantStore.addTablEntry(id, body);
    if (!result.success) {
      return NextResponse.json(
        { success: false, error: result.error || "Failed to add entry." },
        { status: result.error === "Tenant not found" ? 404 : 500 }
      );
    }
    return NextResponse.json({ success: true, entry: result.entry });
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
    const result = await tenantStore.removeTablEntry(id, entryId);
    return NextResponse.json({ success: result.success, error: result.error });
  } catch (error: any) {
    return NextResponse.json({ success: false, error: error.message }, { status: 500 });
  }
}
