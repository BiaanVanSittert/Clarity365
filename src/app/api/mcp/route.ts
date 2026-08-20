import { NextResponse } from "next/server";
import { MCP_TOOL_DEFINITIONS, executeMcpTool } from "@/lib/mcp/engine";
import { tenantStore } from "@/lib/services/tenant-store";

export async function GET() {
  const settings = tenantStore.getSettings();
  return NextResponse.json({
    status: settings.enableMcpServer ? "active" : "disabled",
    serverName: "clarity365-mcp-server",
    version: "1.0.0",
    tools: MCP_TOOL_DEFINITIONS,
  });
}

export async function POST(request: Request) {
  try {
    const settings = tenantStore.getSettings();
    if (!settings.enableMcpServer) {
      return NextResponse.json({ success: false, error: "MCP Server is currently disabled in Settings." }, { status: 403 });
    }

    const body = await request.json();
    const { tool, arguments: toolArgs } = body;

    if (!tool) {
      return NextResponse.json({ success: false, error: "Missing 'tool' name in request." }, { status: 400 });
    }

    const result = await executeMcpTool(tool, toolArgs || {});
    return NextResponse.json(result);
  } catch (error: any) {
    return NextResponse.json({ success: false, error: error.message }, { status: 500 });
  }
}
