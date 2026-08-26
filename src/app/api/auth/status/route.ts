import { NextResponse } from "next/server";
import { tenantStore } from "@/lib/services/tenant-store";

// Public - the login page needs this before it knows whether to show
// "create a password" (first run) or the normal login form.
export async function GET() {
  return NextResponse.json({ success: true, configured: tenantStore.isPasswordConfigured() });
}
