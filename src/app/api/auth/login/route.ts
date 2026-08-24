import { NextResponse } from "next/server";
import { tenantStore } from "@/lib/services/tenant-store";
import { verifyPasswordHash } from "@/lib/services/crypto";
import { createSessionToken, SESSION_COOKIE_NAME, SESSION_TTL_SECONDS } from "@/lib/services/auth";
import { isRateLimited } from "@/lib/services/rate-limit";

const MAX_ATTEMPTS = 10;
const WINDOW_MS = 15 * 60 * 1000;

export async function POST(request: Request) {
  try {
    if (isRateLimited("auth-login", MAX_ATTEMPTS, WINDOW_MS)) {
      return NextResponse.json(
        { success: false, error: "Too many login attempts. Try again in a few minutes." },
        { status: 429 }
      );
    }

    const passwordHash = tenantStore.getPasswordHash();
    if (!passwordHash) {
      return NextResponse.json(
        { success: false, error: "No password has been set up yet.", needsSetup: true },
        { status: 409 }
      );
    }

    const body = await request.json().catch(() => ({}));
    const { password } = body;
    if (!password || typeof password !== "string") {
      return NextResponse.json({ success: false, error: "Password is required." }, { status: 400 });
    }

    if (!verifyPasswordHash(password, passwordHash)) {
      return NextResponse.json({ success: false, error: "Incorrect password." }, { status: 401 });
    }

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
    return NextResponse.json({ success: false, error: error.message || "Login failed." }, { status: 500 });
  }
}
