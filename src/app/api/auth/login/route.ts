import { NextResponse } from "next/server";
import { createSessionToken, verifyAdminPassword, SESSION_COOKIE_NAME, SESSION_TTL_SECONDS } from "@/lib/services/auth";

// Best-effort, process-memory login throttle. Single-operator tool, single instance —
// this is not a substitute for a real rate limiter behind a multi-instance deployment.
const attempts = new Map<string, { count: number; resetAt: number }>();
const MAX_ATTEMPTS = 10;
const WINDOW_MS = 15 * 60 * 1000;

function isRateLimited(key: string): boolean {
  const now = Date.now();
  const entry = attempts.get(key);
  if (!entry || now > entry.resetAt) {
    attempts.set(key, { count: 1, resetAt: now + WINDOW_MS });
    return false;
  }
  entry.count += 1;
  return entry.count > MAX_ATTEMPTS;
}

export async function POST(request: Request) {
  try {
    if (isRateLimited("global")) {
      return NextResponse.json(
        { success: false, error: "Too many login attempts. Try again in a few minutes." },
        { status: 429 }
      );
    }

    const body = await request.json().catch(() => ({}));
    const { password } = body;
    if (!password || typeof password !== "string") {
      return NextResponse.json({ success: false, error: "Password is required." }, { status: 400 });
    }

    const valid = await verifyAdminPassword(password);
    if (!valid) {
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
