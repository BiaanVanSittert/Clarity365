import { NextResponse } from "next/server";
import { tenantStore } from "@/lib/services/tenant-store";
import { hashPassword, verifyPasswordHash } from "@/lib/services/crypto";
import { isRateLimited } from "@/lib/services/rate-limit";

const MIN_PASSWORD_LENGTH = 8;

// Reaching this route at all requires a valid session - see the middleware matcher,
// which only exempts /api/auth/login, /api/auth/setup, and /api/auth/status.
export async function POST(request: Request) {
  try {
    if (isRateLimited("auth-change-password", 10, 15 * 60 * 1000)) {
      return NextResponse.json(
        { success: false, error: "Too many attempts. Try again in a few minutes." },
        { status: 429 }
      );
    }

    const passwordHash = tenantStore.getPasswordHash();
    if (!passwordHash) {
      return NextResponse.json({ success: false, error: "No password is configured yet." }, { status: 409 });
    }

    const body = await request.json().catch(() => ({}));
    const { currentPassword, newPassword, confirmPassword } = body;

    if (!currentPassword || typeof currentPassword !== "string") {
      return NextResponse.json({ success: false, error: "Current password is required." }, { status: 400 });
    }
    if (!verifyPasswordHash(currentPassword, passwordHash)) {
      return NextResponse.json({ success: false, error: "Current password is incorrect." }, { status: 401 });
    }

    if (!newPassword || typeof newPassword !== "string" || newPassword.length < MIN_PASSWORD_LENGTH) {
      return NextResponse.json(
        { success: false, error: `New password must be at least ${MIN_PASSWORD_LENGTH} characters.` },
        { status: 400 }
      );
    }
    if (newPassword !== confirmPassword) {
      return NextResponse.json({ success: false, error: "New passwords do not match." }, { status: 400 });
    }
    if (newPassword === currentPassword) {
      return NextResponse.json(
        { success: false, error: "New password must be different from the current password." },
        { status: 400 }
      );
    }

    tenantStore.setPasswordHash(hashPassword(newPassword));
    return NextResponse.json({ success: true });
  } catch (error: any) {
    return NextResponse.json({ success: false, error: error.message || "Failed to change password." }, { status: 500 });
  }
}
