import { NextRequest, NextResponse } from "next/server";
import { getFleetTablEntries, addFleetTablEntry } from "@/lib/services/fleet-operations";

export async function GET() {
  try {
    const entries = getFleetTablEntries();
    return NextResponse.json({ success: true, entries });
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { type, value, action, reason, addedBy } = body;

    if (!type || !value || !action || !reason) {
      return NextResponse.json(
        { success: false, error: "Missing required fields (type, value, action, reason)." },
        { status: 400 }
      );
    }

    const created = addFleetTablEntry({
      type,
      value,
      action: action === "allow" ? "allow" : "block",
      reason,
      addedBy: addedBy || "SecOps Analyst",
    });

    return NextResponse.json({ success: true, entry: created });
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}
