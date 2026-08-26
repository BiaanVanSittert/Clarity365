import { NextRequest, NextResponse } from "next/server";
import { tenantStore } from "@/lib/services/tenant-store";

export const dynamic = "force-dynamic";

// Single route for the three Module 6/7 write actions (disable a forwarding
// rule, revoke a mailbox delegation, enable tenant-wide mailbox auditing) -
// same shape as mdo-fix/route.ts, dispatched on an `action` discriminator
// rather than three separate route files.
export async function POST(request: NextRequest, { params }: { params: { id: string } }) {
  try {
    const { id } = params;
    const body = await request.json();
    const { action } = body;

    if (!action) {
      return NextResponse.json({ success: false, error: "Missing action parameter" }, { status: 400 });
    }

    const tenant = tenantStore.getTenant(id);
    if (!tenant) {
      return NextResponse.json({ success: false, error: "Tenant not found" }, { status: 404 });
    }

    let result: { success: boolean; error?: string };

    if (action === "disable_forwarding_rule") {
      const { ruleId } = body;
      if (!ruleId) {
        return NextResponse.json({ success: false, error: "Missing ruleId parameter" }, { status: 400 });
      }
      result = await tenantStore.disableForwardingRule(id, ruleId);
    } else if (action === "revoke_delegation") {
      const { mailboxId, principalUserPrincipalName, accessRight } = body;
      if (!mailboxId || !principalUserPrincipalName || !accessRight) {
        return NextResponse.json(
          { success: false, error: "Missing mailboxId, principalUserPrincipalName, or accessRight parameter" },
          { status: 400 }
        );
      }
      result = await tenantStore.revokeMailboxDelegation(id, mailboxId, principalUserPrincipalName, accessRight);
    } else if (action === "enable_mailbox_auditing") {
      result = await tenantStore.setMailboxAuditingEnabled(id);
    } else {
      return NextResponse.json({ success: false, error: `Unknown action '${action}'` }, { status: 400 });
    }

    if (!result.success) {
      return NextResponse.json({ success: false, error: result.error || "Failed to apply fix" }, { status: 500 });
    }

    return NextResponse.json({ success: true });
  } catch (error: any) {
    return NextResponse.json({ success: false, error: error.message || "Failed to apply fix" }, { status: 500 });
  }
}
