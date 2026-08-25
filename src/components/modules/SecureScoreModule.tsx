import React, { useState } from "react";
import { TenantSecuritySnapshot, SecureScoreControl } from "@/lib/types";
import { StatusPill } from "../common/StatusPill";
import { EmptyStateRow } from "../common/EmptyStateRow";
import {
  ShieldAlert,
  ShieldCheck,
  TrendingUp,
  ArrowUpRight,
  Filter,
  CheckCircle2,
  Terminal,
  Layers,
  Search,
  Download,
} from "lucide-react";
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";
import { exportToCsv, csvFilename } from "@/lib/utils/csv";

interface SecureScoreModuleProps {
  snapshot: TenantSecuritySnapshot;
  onOpenRemediation: (findingType?: string) => void;
}

export const SecureScoreModule: React.FC<SecureScoreModuleProps> = ({
  snapshot,
  onOpenRemediation,
}) => {
  const { secureScore, tenant } = snapshot;
  const [selectedCategory, setSelectedCategory] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");

  const categories = ["all", "Identity", "Device", "Apps", "Data"];

  const filteredControls = secureScore.controls.filter((ctrl) => {
    const matchesCategory = selectedCategory === "all" || ctrl.category === selectedCategory;
    const matchesSearch =
      ctrl.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      ctrl.remediationSummary.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesCategory && matchesSearch;
  });

  const handleExportCSV = () => {
    const headers = ["ControlId", "Title", "Category", "ScoreCurrent", "ScoreMax", "UserImpact", "Status"];
    const rows = filteredControls.map((ctrl) => [
      ctrl.id,
      ctrl.title,
      ctrl.category,
      ctrl.scoreCurrent,
      ctrl.scoreMax,
      ctrl.userImpact,
      ctrl.status,
    ]);
    exportToCsv(csvFilename("SecureScore", tenant.defaultDomainName), headers, rows);
  };

  const chartData = secureScore.history.map((h) => ({
    date: h.date,
    percentage: h.percentage,
    score: h.score,
    maxScore: h.maxScore,
  }));

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="bg-[#F8FAFC] border border-[#CBD5E1] p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <ShieldAlert size={18} className="text-slate-800" />
            <h2 className="text-sm font-bold text-slate-900 tracking-tight">
              Module 3: Defender Secure Score & Historical Timeline
            </h2>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Continuous posture evaluation, 90-day progress metrics, and actionable improvement recommendations.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="text-right">
            <div className="text-xs font-semibold text-slate-700">Current Attainment</div>
            <div className="text-xl font-bold font-mono text-slate-900 tabular-nums">
              {secureScore.percentage.toFixed(1)}% ({secureScore.currentScore} / {secureScore.maxScore} pts)
            </div>
          </div>
          <button
            onClick={() => onOpenRemediation("all")}
            className="px-3.5 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-sm flex items-center gap-1.5 transition-colors shadow-sm"
          >
            <Terminal size={14} className="text-emerald-400" />
            <span>Generate Remediation Script</span>
          </button>
        </div>
      </div>

      {/* Metric Cards & Historical Timeline Graph */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Metric Summary Card */}
        <div className="border border-[#CBD5E1] bg-white p-4 rounded-sm space-y-3 shadow-xs">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 border-b border-[#E2E8F0] pb-2">
            Score Progression Benchmarks
          </h3>

          <div className="space-y-3">
            <div className="flex justify-between items-center p-2.5 bg-[#F8FAFC] border border-[#E2E8F0] rounded-sm">
              <span className="text-xs text-slate-600 font-medium">30-Day Delta</span>
              <span className={`text-xs font-mono font-bold ${secureScore.delta30Days >= 0 ? "text-emerald-700" : "text-red-700"}`}>
                {secureScore.delta30Days >= 0 ? `+${secureScore.delta30Days.toFixed(1)}%` : `${secureScore.delta30Days.toFixed(1)}%`}
              </span>
            </div>

            <div className="flex justify-between items-center p-2.5 bg-[#F8FAFC] border border-[#E2E8F0] rounded-sm">
              <span className="text-xs text-slate-600 font-medium">90-Day Delta</span>
              <span className={`text-xs font-mono font-bold ${secureScore.delta90Days >= 0 ? "text-emerald-700" : "text-red-700"}`}>
                {secureScore.delta90Days >= 0 ? `+${secureScore.delta90Days.toFixed(1)}%` : `${secureScore.delta90Days.toFixed(1)}%`}
              </span>
            </div>

            <div className="flex justify-between items-center p-2.5 bg-[#F8FAFC] border border-[#E2E8F0] rounded-sm">
              <span className="text-xs text-slate-600 font-medium">Industry Peer Benchmark</span>
              <span className="text-xs font-mono font-bold text-slate-900">
                {secureScore.industryBenchmark.toFixed(1)}%
              </span>
            </div>
          </div>
        </div>

        {/* Historical Timeline Graph */}
        <div className="border border-[#CBD5E1] bg-white p-4 rounded-sm shadow-xs lg:col-span-2 flex flex-col justify-between">
          <div className="flex items-center justify-between border-b border-[#E2E8F0] pb-2 mb-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
              90-Day Secure Score History & Trajectory
            </h3>
            <span className="text-[11px] font-mono text-slate-500">Historical Trend</span>
          </div>

          <div className="h-44 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={chartData} margin={{ top: 10, right: 20, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#E2E8F0" />
                <XAxis dataKey="date" stroke="#64748B" fontSize={11} tickLine={false} />
                <YAxis domain={[0, 100]} stroke="#64748B" fontSize={11} tickLine={false} unit="%" />
                <Tooltip
                  contentStyle={{ backgroundColor: "#0F172A", borderColor: "#334155", color: "#F8FAFC", borderRadius: "2px", fontSize: "11px" }}
                  formatter={(val: any) => [`${val}%`, "Attainment"]}
                />
                <Line
                  type="monotone"
                  dataKey="percentage"
                  stroke="#0F172A"
                  strokeWidth={2}
                  dot={{ r: 4, fill: "#0F172A" }}
                  activeDot={{ r: 6 }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recommendations & Controls Table */}
      <div className="border border-[#CBD5E1] bg-white rounded-sm overflow-hidden shadow-xs">
        <div className="p-3 bg-[#F8FAFC] border-b border-[#CBD5E1] flex flex-col sm:flex-row items-center justify-between gap-3">
          {/* Category Tabs */}
          <div className="flex items-center gap-1 border border-[#CBD5E1] bg-white p-0.5 rounded-sm">
            {categories.map((cat) => (
              <button
                key={cat}
                onClick={() => setSelectedCategory(cat)}
                className={`px-2.5 py-1 text-xs rounded-sm transition-colors ${
                  selectedCategory === cat
                    ? "bg-slate-900 text-white font-medium shadow-xs"
                    : "text-slate-600 hover:text-slate-900"
                }`}
              >
                {cat === "all" ? "All Domains" : cat}
              </button>
            ))}
          </div>

          {/* Search */}
          <div className="relative w-full sm:w-72">
            <Search size={14} className="absolute left-2.5 top-2.5 text-slate-400" />
            <input
              type="text"
              placeholder="Search security controls..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white"
            />
          </div>

          <button
            onClick={handleExportCSV}
            title="Export filtered controls to CSV"
            className="px-2.5 py-1.5 text-xs font-medium text-slate-700 bg-white hover:bg-slate-50 border border-[#CBD5E1] rounded-sm flex items-center gap-1.5 transition-colors shadow-2xs shrink-0"
          >
            <Download size={13} className="text-slate-500" />
            <span>Export CSV</span>
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse table-dense">
            <thead>
              <tr>
                <th className="w-24">Control ID</th>
                <th>Security Improvement Action</th>
                <th className="w-24">Category</th>
                <th className="w-24">Points Attained</th>
                <th className="w-28">User Impact</th>
                <th className="w-28">Status</th>
              </tr>
            </thead>
            <tbody>
              {filteredControls.length === 0 ? (
                <EmptyStateRow colSpan={6} entityLabel="controls" isFiltered={searchQuery.trim().length > 0} />
              ) : (
              filteredControls.map((ctrl) => (
                <tr key={ctrl.id}>
                  <td className="font-mono font-bold text-xs text-slate-900">{ctrl.id}</td>
                  <td>
                    <div className="font-semibold text-xs text-slate-900">{ctrl.title}</div>
                    <div className="text-[11px] text-slate-500 mt-0.5">{ctrl.remediationSummary}</div>
                  </td>
                  <td>
                    <span className="font-mono text-xs text-slate-700">{ctrl.category}</span>
                  </td>
                  <td className="font-mono text-xs font-bold text-slate-900 tabular-nums">
                    {ctrl.scoreCurrent} / {ctrl.scoreMax}
                  </td>
                  <td className="text-xs text-slate-600">{ctrl.userImpact}</td>
                  <td>
                    <StatusPill
                      status={
                        ctrl.status === "Completed"
                          ? "pass"
                          : ctrl.status === "Partial"
                          ? "warn"
                          : "fail"
                      }
                      label={ctrl.status}
                      size="sm"
                    />
                  </td>
                </tr>
              ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
