import { NextRequest, NextResponse } from "next/server";
import { tenantStore } from "@/lib/services/tenant-store";
import { isScenarioConfirmationKey } from "@/lib/utils/scenario-confirmations";

export const dynamic = "force-dynamic";

// Records (or clears) a "confirmed once" answer for one Security Scenarios
// check on ONE tenant. Stored in Clarity365 only - nothing is sent to
// Microsoft 365. See src/lib/utils/scenario-confirmations.ts.
export async function POST(request: NextRequest, { params }: { params: { id: string } }) {
  try {
    const body = await request.json().catch(() => ({}));
    const { key, status, note } = body || {};
    if (!isScenarioConfirmationKey(key)) {
      return NextResponse.json({ success: false, error: "Unknown check." }, { status: 400 });
    }
    if (status !== "inPlace" && status !== "notInPlace" && status !== "clear") {
      return NextResponse.json({ success: false, error: "status must be inPlace, notInPlace or clear." }, { status: 400 });
    }
    const tenant = tenantStore.setScenarioConfirmation(params.id, key, status === "clear" ? null : { status, note: typeof note === "string" ? note.trim().slice(0, 300) || undefined : undefined });
    if (!tenant) return NextResponse.json({ success: false, error: "Tenant not found" }, { status: 404 });
    return NextResponse.json({ success: true, scenarioConfirmations: tenant.scenarioConfirmations || {} });
  } catch (error: any) {
    return NextResponse.json({ success: false, error: error.message || "Could not save the confirmation." }, { status: 500 });
  }
}
