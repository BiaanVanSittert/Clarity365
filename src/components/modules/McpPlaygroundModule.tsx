import React, { useState, useEffect } from "react";
import { Tenant, TenantSecuritySnapshot } from "@/lib/types";
import { StatusPill } from "../common/StatusPill";
import { MCP_TOOL_DEFINITIONS } from "@/lib/mcp/definitions";
import { Cpu, Play, Terminal, Check, Copy, Code, Layers, Building2 } from "lucide-react";

interface McpPlaygroundModuleProps {
  snapshot?: TenantSecuritySnapshot | null;
  tenants?: Tenant[];
  isFleetMode?: boolean;
}

export const McpPlaygroundModule: React.FC<McpPlaygroundModuleProps> = ({
  snapshot,
  tenants = [],
  isFleetMode = false,
}) => {
  const [selectedTenantId, setSelectedTenantId] = useState<string>(
    snapshot?.tenant?.id || (tenants.length > 0 ? tenants[0].id : "")
  );

  useEffect(() => {
    if (snapshot?.tenant?.id) {
      setSelectedTenantId(snapshot.tenant.id);
    } else if (tenants.length > 0 && !selectedTenantId) {
      setSelectedTenantId(tenants[0].id);
    }
  }, [snapshot, tenants]);

  const [selectedTool, setSelectedTool] = useState(MCP_TOOL_DEFINITIONS[0].name);
  const [toolArgsJson, setToolArgsJson] = useState<string>(() => {
    const tid = snapshot?.tenant?.id || (tenants[0]?.id || "");
    return JSON.stringify({ tenantId: tid }, null, 2);
  });
  const [isExecuting, setIsExecuting] = useState(false);
  const [executionResult, setExecutionResult] = useState<any | null>(null);
  const [copied, setCopied] = useState(false);

  const activeDef = MCP_TOOL_DEFINITIONS.find((t) => t.name === selectedTool);

  const handleToolChange = (toolName: string, targetTenantId = selectedTenantId) => {
    setSelectedTool(toolName);
    if (toolName === "list_tenants") {
      setToolArgsJson(JSON.stringify({}, null, 2));
    } else if (toolName === "manage_tabl") {
      setToolArgsJson(
        JSON.stringify(
          {
            tenantId: targetTenantId,
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
            tenantId: targetTenantId,
            status: "all",
            onlyRisky: false,
          },
          null,
          2
        )
      );
    } else {
      setToolArgsJson(JSON.stringify({ tenantId: targetTenantId }, null, 2));
    }
  };

  const handleTenantChange = (newTenantId: string) => {
    setSelectedTenantId(newTenantId);
    handleToolChange(selectedTool, newTenantId);
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

  const activeTenantName =
    snapshot?.tenant?.displayName ||
    tenants.find((t) => t.id === selectedTenantId)?.displayName ||
    "Selected Organization";

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto select-none">
      {/* Header */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Cpu size={18} className="text-slate-800 dark:text-slate-200" />
            <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">
              Model Context Protocol (MCP) In-House Tool Inspector & Playground
            </h2>
            {isFleetMode && (
              <span className="text-[10px] font-mono font-bold uppercase px-1.5 py-0.5 bg-indigo-100 dark:bg-indigo-950 text-indigo-800 dark:text-indigo-300 border border-indigo-300 dark:border-indigo-800 rounded-sm">
                Fleet Mode
              </span>
            )}
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Test and inspect internal Clarity365 MCP tool definitions, input schemas, and execution responses across customer tenants.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {(isFleetMode || !snapshot) && tenants.length > 0 && (
            <div className="flex items-center gap-1.5 bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 px-2 py-1 rounded-sm">
              <Building2 size={13} className="text-slate-400" />
              <select
                value={selectedTenantId}
                onChange={(e) => handleTenantChange(e.target.value)}
                className="text-xs font-semibold bg-transparent text-slate-900 dark:text-slate-100 focus:outline-none"
              >
                {tenants.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.displayName} ({t.defaultDomainName})
                  </option>
                ))}
              </select>
            </div>
          )}
          <StatusPill status="pass" label="MCP Engine Active (Localhost)" />
        </div>
      </div>

      {/* Tool Selector & Execution Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left: Tool List */}
        <div className="lg:col-span-4 border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm p-3 space-y-2 shadow-xs">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200 border-b border-[#E2E8F0] dark:border-slate-700 pb-1.5">
            Available MCP Tools ({MCP_TOOL_DEFINITIONS.length})
          </h3>

          <div className="space-y-1">
            {MCP_TOOL_DEFINITIONS.map((def) => {
              const isSelected = def.name === selectedTool;
              return (
                <button
                  key={def.name}
                  onClick={() => handleToolChange(def.name)}
                  className={`w-full text-left p-2 rounded-sm border transition-colors ${
                    isSelected
                      ? "bg-slate-100 dark:bg-slate-700/80 border-slate-400 dark:border-slate-500 font-semibold text-slate-950 dark:text-slate-50"
                      : "bg-white dark:bg-slate-800 border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700/50"
                  }`}
                >
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono">{def.name}</span>
                    <span className="text-[10px] text-slate-400 font-normal">v1.0</span>
                  </div>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400 font-normal line-clamp-2 mt-0.5 leading-snug">
                    {def.description}
                  </p>
                </button>
              );
            })}
          </div>
        </div>

        {/* Right: Schema & Execution Area */}
        <div className="lg:col-span-8 space-y-4">
          {/* Tool Definition Details */}
          {activeDef && (
            <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm p-3.5 space-y-3 shadow-xs">
              <div className="flex items-center justify-between border-b border-[#E2E8F0] dark:border-slate-700 pb-2">
                <div>
                  <h3 className="text-xs font-bold font-mono text-slate-900 dark:text-slate-100 flex items-center gap-1.5">
                    <Code size={14} className="text-indigo-600 dark:text-indigo-400" />
                    <span>{activeDef.name}</span>
                  </h3>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                    {activeDef.description}
                  </p>
                </div>

                <button
                  onClick={handleExecute}
                  disabled={isExecuting}
                  className="px-3 py-1.5 text-xs font-bold text-white bg-slate-900 dark:bg-slate-100 dark:text-slate-900 hover:bg-slate-800 dark:hover:bg-white rounded-sm flex items-center gap-1.5 transition-colors disabled:opacity-50 shadow-xs"
                >
                  <Play size={12} className={isExecuting ? "animate-spin" : "fill-current"} />
                  <span>{isExecuting ? "Executing..." : "Execute Tool"}</span>
                </button>
              </div>

              {/* JSON Args Editor */}
              <div className="space-y-1">
                <div className="flex items-center justify-between text-[11px] font-mono text-slate-600 dark:text-slate-400">
                  <span>Input Arguments (JSON): Target: {activeTenantName}</span>
                </div>
                <textarea
                  value={toolArgsJson}
                  onChange={(e) => setToolArgsJson(e.target.value)}
                  rows={6}
                  className="w-full p-2.5 text-xs font-mono bg-[#F8FAFC] dark:bg-slate-900 border border-[#CBD5E1] dark:border-slate-700 rounded-sm text-slate-900 dark:text-slate-100 focus:outline-none focus:border-slate-500"
                />
              </div>

              {/* Input Schema Details */}
              <div className="space-y-1 bg-slate-50 dark:bg-slate-900/60 p-2.5 rounded-sm border border-slate-200 dark:border-slate-700/80">
                <div className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                  Accepted Parameters (Schema)
                </div>
                <div className="text-[11px] font-mono text-slate-700 dark:text-slate-300 space-y-1">
                  {Object.entries(activeDef.inputSchema.properties || {}).map(([key, val]: [string, any]) => (
                    <div key={key} className="flex items-start gap-2">
                      <span className="font-bold text-indigo-700 dark:text-indigo-400">{key}:</span>
                      <span className="text-slate-500 dark:text-slate-400">
                        ({val.type || "string"}) - {val.description || ""}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Execution Response Inspector */}
          <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm p-3.5 space-y-2 shadow-xs">
            <div className="flex items-center justify-between border-b border-[#E2E8F0] dark:border-slate-700 pb-2">
              <h3 className="text-xs font-bold font-mono text-slate-900 dark:text-slate-100 flex items-center gap-1.5">
                <Terminal size={14} className="text-emerald-600 dark:text-emerald-400" />
                <span>Execution Output / Tool Response</span>
              </h3>

              {executionResult && (
                <button
                  onClick={copyResult}
                  className="px-2 py-0.5 text-[10px] font-medium text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-slate-100 bg-slate-100 dark:bg-slate-700 rounded-sm border border-slate-300 dark:border-slate-600 flex items-center gap-1 transition-colors"
                >
                  {copied ? <Check size={11} className="text-emerald-600" /> : <Copy size={11} />}
                  <span>{copied ? "Copied" : "Copy JSON"}</span>
                </button>
              )}
            </div>

            <pre className="w-full p-3 text-xs font-mono bg-[#0F172A] text-[#F8FAFC] rounded-sm overflow-x-auto max-h-96 leading-relaxed">
              {executionResult ? (
                JSON.stringify(executionResult, null, 2)
              ) : (
                <span className="text-slate-500">
                  Ready. Click &quot;Execute Tool&quot; above to trigger this MCP handler.
                </span>
              )}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
