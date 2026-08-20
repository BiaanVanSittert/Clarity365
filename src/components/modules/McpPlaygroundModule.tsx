import React, { useState } from "react";
import { TenantSecuritySnapshot } from "@/lib/types";
import { StatusPill } from "../common/StatusPill";
import { MCP_TOOL_DEFINITIONS } from "@/lib/mcp/definitions";
import { Cpu, Play, Terminal, Check, Copy, Code, Layers } from "lucide-react";

interface McpPlaygroundModuleProps {
  snapshot: TenantSecuritySnapshot;
}

export const McpPlaygroundModule: React.FC<McpPlaygroundModuleProps> = ({ snapshot }) => {
  const { tenant } = snapshot;
  const [selectedTool, setSelectedTool] = useState(MCP_TOOL_DEFINITIONS[0].name);
  const [toolArgsJson, setToolArgsJson] = useState<string>(
    JSON.stringify({ tenantId: tenant.id }, null, 2)
  );
  const [isExecuting, setIsExecuting] = useState(false);
  const [executionResult, setExecutionResult] = useState<any | null>(null);
  const [copied, setCopied] = useState(false);

  const activeDef = MCP_TOOL_DEFINITIONS.find((t) => t.name === selectedTool);

  const handleToolChange = (toolName: string) => {
    setSelectedTool(toolName);
    if (toolName === "list_tenants") {
      setToolArgsJson(JSON.stringify({}, null, 2));
    } else if (toolName === "manage_tabl") {
      setToolArgsJson(
        JSON.stringify(
          {
            tenantId: tenant.id,
            action: "list",
          },
          null,
          2
        )
      );
    } else if (toolName === "query_signin_logs") {
      setToolArgsJson(
        JSON.stringify(
          {
            tenantId: tenant.id,
            status: "all",
            onlyRisky: false,
          },
          null,
          2
        )
      );
    } else {
      setToolArgsJson(JSON.stringify({ tenantId: tenant.id }, null, 2));
    }
  };

  const handleExecute = async () => {
    setIsExecuting(true);
    setExecutionResult(null);

    try {
      let parsedArgs = {};
      try {
        parsedArgs = JSON.parse(toolArgsJson);
      } catch (e: any) {
        setExecutionResult({ error: `Invalid JSON Arguments: ${e.message}` });
        setIsExecuting(false);
        return;
      }

      const res = await fetch("/api/mcp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tool: selectedTool,
          arguments: parsedArgs,
        }),
      });

      const data = await res.json();
      setExecutionResult(data);
    } catch (err: any) {
      setExecutionResult({ error: err.message });
    } finally {
      setIsExecuting(false);
    }
  };

  const copyResult = () => {
    navigator.clipboard.writeText(JSON.stringify(executionResult, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="bg-[#F8FAFC] border border-[#CBD5E1] p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Cpu size={18} className="text-slate-800" />
            <h2 className="text-sm font-bold text-slate-900 tracking-tight">
              Model Context Protocol (MCP) In-House Tool Inspector & Playground
            </h2>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Test and inspect internal Clarity365 MCP tool definitions, input schemas, and execution responses.
          </p>
        </div>

        <StatusPill status="pass" label="MCP Engine Active (Localhost)" />
      </div>

      {/* Tool Selector & Execution Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left: Tool List */}
        <div className="lg:col-span-4 border border-[#CBD5E1] bg-white rounded-sm p-3 space-y-2 shadow-xs">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 border-b border-[#E2E8F0] pb-1.5">
            Available MCP Tools ({MCP_TOOL_DEFINITIONS.length})
          </h3>

          <div className="space-y-1">
            {MCP_TOOL_DEFINITIONS.map((def) => {
              const isSelected = def.name === selectedTool;
              return (
                <button
                  key={def.name}
                  onClick={() => handleToolChange(def.name)}
                  className={`w-full text-left p-2 rounded-sm text-xs transition-colors ${
                    isSelected
                      ? "bg-slate-900 text-white font-semibold"
                      : "text-slate-700 hover:bg-slate-100"
                  }`}
                >
                  <div className="font-mono text-xs">{def.name}</div>
                  <div className={`text-[11px] truncate mt-0.5 ${isSelected ? "text-slate-300" : "text-slate-500"}`}>
                    {def.description}
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Right: Arguments Editor & Execution Output */}
        <div className="lg:col-span-8 space-y-3">
          {/* Tool Definition & Arguments */}
          <div className="border border-[#CBD5E1] bg-white rounded-sm p-3.5 space-y-2 shadow-xs">
            <div className="flex items-center justify-between border-b border-[#E2E8F0] pb-2">
              <div>
                <h4 className="text-xs font-bold font-mono text-slate-900">{activeDef?.name}</h4>
                <p className="text-xs text-slate-600 mt-0.5">{activeDef?.description}</p>
              </div>
              <button
                onClick={handleExecute}
                disabled={isExecuting}
                className="px-3.5 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-sm flex items-center gap-1.5 transition-colors disabled:opacity-50"
              >
                <Play size={13} className="fill-current text-emerald-400" />
                <span>{isExecuting ? "Executing..." : "Execute Tool"}</span>
              </button>
            </div>

            <div>
              <label className="block text-[11px] font-mono font-semibold text-slate-700 mb-1">
                Tool Input Parameters (JSON Schema)
              </label>
              <textarea
                rows={5}
                value={toolArgsJson}
                onChange={(e) => setToolArgsJson(e.target.value)}
                className="w-full p-2.5 bg-slate-950 text-slate-200 font-mono text-xs border border-slate-800 rounded-sm focus:outline-none focus:border-slate-600"
              />
            </div>
          </div>

          {/* Execution Output */}
          <div className="border border-[#CBD5E1] bg-white rounded-sm overflow-hidden shadow-xs">
            <div className="px-3.5 py-2 bg-[#F8FAFC] border-b border-[#E2E8F0] flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Code size={14} className="text-slate-600" />
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800">
                  Tool Execution Result (JSON)
                </h4>
              </div>

              {executionResult && (
                <button
                  onClick={copyResult}
                  className="flex items-center gap-1 text-[11px] text-slate-600 hover:text-slate-900 bg-white border border-[#CBD5E1] px-2 py-0.5 rounded-sm"
                >
                  {copied ? <Check size={12} className="text-emerald-600" /> : <Copy size={12} />}
                  <span>{copied ? "Copied" : "Copy Output"}</span>
                </button>
              )}
            </div>

            <pre className="p-4 bg-slate-950 text-emerald-400 font-mono text-xs overflow-x-auto min-h-[160px] max-h-[360px] leading-relaxed">
              {executionResult ? (
                <code>{JSON.stringify(executionResult, null, 2)}</code>
              ) : (
                <span className="text-slate-500 italic">Click "Execute Tool" to test MCP response.</span>
              )}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
