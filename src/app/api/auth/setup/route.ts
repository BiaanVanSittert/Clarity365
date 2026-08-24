import { NextResponse } from "next/server";
import { tenantStore } from "@/lib/services/tenant-store";
import { hashPassword } from "@/lib/services/crypto";
import { createSessionToken, SESSION_COOKIE_NAME, SESSION_TTL_SECONDS } from "@/lib/services/auth";
import { isRateLimited } from "@/lib/services/rate-limit";

const MIN_PASSWORD_LENGTH = 8;

export async function POST(request: Request) {
  try {
    if (isRateLimited("auth-setup", 20, 15 * 60 * 1000)) {
      return NextResponse.json(
        { success: false, error: "Too many attempts. Try again in a few minutes." },
        { status: 429 }
      );
    }

    // First-run setup only. Once a password exists, this route refuses to overwrite it —
    // rotating the password is done through /api/auth/change-password (requires a session).
    if (tenantStore.isPasswordConfigured()) {
      return NextResponse.json(
        { success: false, error: "A password is already configured. Use the login form instead." },
        { status: 409 }
      );
    }

    const body = await request.json().catch(() => ({}));
    const { password, confirmPassword } = body;

    if (!password || typeof password !== "string" || password.length < MIN_PASSWORD_LENGTH) {
      return NextResponse.json(
        { success: false, error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters.` },
        { status: 400 }
      );
    }
    if (password !== confirmPassword) {
      return NextResponse.json({ success: false, error: "Passwords do not match." }, { status: 400 });
    }

    tenantStore.setPasswordHash(hashPassword(password));

    const token = await createSessionToken();
    const response = NextResponse.json({ success: true });
    response.cookies.set(SESSION_COOKIE_NAME, token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      maxAge: SESSION_TTL_SECONDS,
    });
    return response;
  } catch (error: any) {
    return NextResponse.json({ success: false, error: error.message || "Setup failed." }, { status: 500 });
  }
}
