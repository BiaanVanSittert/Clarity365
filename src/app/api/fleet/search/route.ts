import { NextResponse } from "next/server";
import { tenantStore } from "@/lib/services/tenant-store";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const query = searchParams.get("query") || searchParams.get("q") || "";
    const category = searchParams.get("category") || searchParams.get("type") || undefined;

    if (!query.trim()) {
      return NextResponse.json({ success: true, results: [] });
    }

    const results = tenantStore.searchFleet(query, category);
    return NextResponse.json({ success: true, results, count: results.length });
  } catch (error: any) {
    return NextResponse.json({ success: false, error: error.message }, { status: 500 });
  }
}
