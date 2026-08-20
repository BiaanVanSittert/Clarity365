import { NextResponse } from "next/server";
import { tenantStore } from "@/lib/services/tenant-store";

export async function GET() {
  try {
    const tenants = tenantStore.getAllTenants();
    return NextResponse.json({ success: true, tenants });
  } catch (error: any) {
    return NextResponse.json({ success: false, error: error.message }, { status: 500 });
  }
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    if (!body.displayName || !body.defaultDomainName) {
      return NextResponse.json(
        { success: false, error: "Display Name and Default Domain are required." },
        { status: 400 }
      );
    }
    const created = tenantStore.addTenant(body);
    return NextResponse.json({ success: true, tenant: created });
  } catch (error: any) {
    return NextResponse.json({ success: false, error: error.message }, { status: 500 });
  }
}

export async function DELETE(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const id = searchParams.get("id");
    if (!id) {
      return NextResponse.json({ success: false, error: "Missing tenant id parameter." }, { status: 400 });
    }
    const removed = tenantStore.removeTenant(id);
    if (!removed) {
      return NextResponse.json({ success: false, error: "Tenant not found." }, { status: 404 });
    }
    return NextResponse.json({ success: true, message: `Tenant '${id}' deleted.` });
  } catch (error: any) {
    return NextResponse.json({ success: false, error: error.message }, { status: 500 });
  }
}
