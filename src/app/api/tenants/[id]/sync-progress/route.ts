import { NextRequest, NextResponse } from "next/server";
import { getSyncProgress } from "@/lib/services/tenant-store";

export const dynamic = "force-dynamic";

// Polled from the client while a sync is in flight (same setInterval pattern
// PermissionsModal.tsx already uses for the EXO device-code flow) - reads an
// in-memory, never-persisted progress marker, not a snapshot field. Absence
// of an entry means "not currently syncing" (either never started, or
// already finished), not an error.
export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  const progress = getSyncProgress(params.id);
  if (!progress) {
    return NextResponse.json({ inProgress: false });
  }

  return NextResponse.json({
    inProgress: true,
    step: progress.step,
    stepIndex: progress.stepIndex,
    totalSteps: progress.totalSteps,
    percent: Math.round((progress.stepIndex / progress.totalSteps) * 100),
  });
}
