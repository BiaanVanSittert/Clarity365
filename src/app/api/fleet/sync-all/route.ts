import { NextResponse } from "next/server";
import { getSyncAllStatus, requestStopSyncAll, SyncAllStatus } from "@/lib/services/sync-all";
import { startManualSyncAll } from "@/lib/services/scheduler";
import { getSyncProgress } from "@/lib/services/tenant-store";

export const dynamic = "force-dynamic";

// "Sync all tenants": every live tenant, one at a time (see sync-all.ts).
// Read-only towards the tenants. GET = status (polled by the fleet overview),
// POST = start a pass, DELETE = stop after the tenant in progress.

function withStep(status: SyncAllStatus) {
  const progress = status.current ? getSyncProgress(status.current.tenantId) : undefined;
  return {
    ...status,
    currentStep: progress ? { step: progress.step, percent: Math.round((progress.stepIndex / progress.totalSteps) * 100) } : undefined,
  };
}

export async function GET() {
  return NextResponse.json({ success: true, status: withStep(getSyncAllStatus()) });
}

export async function POST() {
  try {
    const { started, status } = startManualSyncAll();
    return NextResponse.json({ success: true, started, status: withStep(status) });
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message || "Could not start the sync." }, { status: 500 });
  }
}

export async function DELETE() {
  return NextResponse.json({ success: true, status: withStep(requestStopSyncAll()) });
}
