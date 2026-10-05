import { NextRequest, NextResponse } from "next/server";
import { tenantStore } from "@/lib/services/tenant-store";
import { parseAllowedCountries } from "@/lib/utils/allowed-countries";

export const dynamic = "force-dynamic";

export async function POST(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const { id } = params;
    const body = await request.json();
    const { baselineCode, allowedCountries } = body;

    if (!baselineCode) {
      return NextResponse.json({ success: false, error: "Missing baselineCode parameter" }, { status: 400 });
    }

    const tenant = tenantStore.getTenant(id);
    if (!tenant) {
      return NextResponse.json({ success: false, error: "Tenant not found" }, { status: 404 });
    }

    // CA08 needs the allowed countries; validated before anything is written.
    let countries: string[] | undefined;
    if (String(baselineCode).toUpperCase() === "CA08") {
      const parsed = parseAllowedCountries(allowedCountries);
      if (!parsed.countries) return NextResponse.json({ success: false, error: `CA08: ${parsed.error}` }, { status: 400 });
      countries = parsed.countries;
    }

    const result = await tenantStore.deployBaselinePolicy(id, baselineCode, { allowedCountries: countries });
    if (!result.success) {
      return NextResponse.json({ success: false, error: result.error || "Failed to deploy policy" }, { status: 500 });
    }

    return NextResponse.json({
      success: true,
      message: `Successfully created ${baselineCode} in Report-Only mode on '${tenant.displayName}'`,
      policy: result.policy,
      snapshot: result.snapshot,
    });
  } catch (error: any) {
    return NextResponse.json({ success: false, error: error.message || "Failed to deploy policy" }, { status: 500 });
  }
}
