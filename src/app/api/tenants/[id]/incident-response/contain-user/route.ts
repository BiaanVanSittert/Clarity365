import { NextRequest, NextResponse } from "next/server";
import { tenantStore } from "@/lib/services/tenant-store";

export const dynamic = "force-dynamic";

export async function POST(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const { id } = params;
    const body = await request.json();
    const {
      userId,
      userPrincipalName,
      revokeTokens = true,
      disableAccount = true,
      resetPassword = true,
      purgeForwardingRules = true,
      reason,
    } = body;

    if (!userPrincipalName && !userId) {
      return NextResponse.json(
        { success: false, error: "Missing required parameter: userPrincipalName or userId" },
        { status: 400 }
      );
    }

    const tenant = tenantStore.getTenant(id);
    if (!tenant) {
      return NextResponse.json({ success: false, error: "Tenant not found" }, { status: 404 });
    }

    const result = await tenantStore.containUserAccount(id, {
      userId,
      userPrincipalName,
      revokeTokens,
      disableAccount,
      resetPassword,
      purgeForwardingRules,
      reason,
    });

    return NextResponse.json({
      success: result.success,
      actionsExecuted: result.actionsExecuted,
      errors: result.errors,
      snapshot: result.snapshot,
    });
  } catch (error: any) {
    console.error("[Incident Response] Contain User Error:", error);
    return NextResponse.json({ success: false, error: error.message || "Containment action failed" }, { status: 500 });
  }
}
