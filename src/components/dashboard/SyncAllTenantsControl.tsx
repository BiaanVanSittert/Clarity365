"use client";

import React, { useCallback, useEffect, useRef, useState } from "react";
import { AlertTriangle, CheckCircle2, RefreshCw, Square } from "lucide-react";
import type { SyncAllStatus } from "@/lib/services/sync-all";

type Status = SyncAllStatus & { currentStep?: { step: string; percent: number } };

interface SyncAllTenantsControlProps {
  // Called each time a tenant finishes and once at the end, so the fleet table refreshes.
  onTenantSynced?: () => void;
  // Test hook: render a given status without fetching.
  initialStatus?: Status;
}

const POLL_MS = 2500;

type Seen = { startedAt?: string; completed: number; running: boolean };

// Should the fleet table reload? Only when something changed while this
// control was watching: a tenant finished, or the pass ended. The first
// status seen (before === null) is just a baseline.
export function shouldReloadFleet(before: Seen | null, next: Seen): boolean {
  if (!before || before.startedAt !== next.startedAt) return false;
  return next.completed > before.completed || (before.running && !next.running);
}

// Fleet overview's "Sync all tenants": starts one pass over every live
// tenant, one at a time, on the server (so it keeps going if this screen is
// closed) and shows which tenant it is on. Only reads from Microsoft 365.
export const SyncAllTenantsControl: React.FC<SyncAllTenantsControlProps> = ({ onTenantSynced, initialStatus }) => {
  const [status, setStatus] = useState<Status | null>(initialStatus || null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // What the previous status looked like. Null until the first status
  // arrives: that first one is only a baseline and must never trigger a
  // reload. (It did once: every reload remounted this control, the fresh
  // mount saw "completed" differ from zero, asked for another reload, and
  // the fleet view refreshed forever.)
  const previous = useRef<Seen | null>(null);

  const apply = useCallback(
    (next: Status) => {
      setStatus(next);
      const before = previous.current;
      previous.current = { startedAt: next.startedAt, completed: next.completed, running: next.running };
      if (shouldReloadFleet(before, next)) onTenantSynced?.();
    },
    [onTenantSynced]
  );

  const call = useCallback(
    async (method: "GET" | "POST" | "DELETE") => {
      try {
        const res = await fetch("/api/fleet/sync-all", { method });
        const data = await res.json();
        if (!data.success) throw new Error(data.error || "Request failed");
        setError(null);
        apply(data.status);
      } catch (err: any) {
        setError(err.message || "Could not reach the server.");
      }
    },
    [apply]
  );

  // Pick up a pass that is already running (started earlier, or by the auto-sync).
  useEffect(() => {
    if (!initialStatus) call("GET");
  }, [call, initialStatus]);

  const running = !!status?.running;
  useEffect(() => {
    if (!running) return;
    const timer = setInterval(() => call("GET"), POLL_MS);
    return () => clearInterval(timer);
  }, [running, call]);

  const act = async (method: "POST" | "DELETE") => {
    setBusy(true);
    await call(method);
    setBusy(false);
  };

  const failed = (status?.results || []).filter((r) => r.outcome === "failed");
  const finished = !!status && !status.running && !!status.finishedAt;
  const button =
    "px-2.5 py-1.5 text-xs font-medium rounded-sm flex items-center gap-1.5 border transition-colors disabled:opacity-50 bg-white dark:bg-slate-800 border-[#CBD5E1] dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700";

  return (
    <div className="bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm px-3 py-2 text-xs text-slate-700 dark:text-slate-300 space-y-1.5">
      <div className="flex flex-wrap items-center gap-3">
        {!running ? (
          <button onClick={() => act("POST")} disabled={busy} title="Refreshes the data for every live tenant, one tenant at a time. Only reads from Microsoft 365; changes nothing in any tenant." className={button}>
            <RefreshCw size={13} className="text-slate-500 dark:text-slate-400" />
            <span>Sync all tenants</span>
          </button>
        ) : (
          <button onClick={() => act("DELETE")} disabled={busy || status!.stopRequested} title="The tenant being synced finishes first; the rest are skipped." className={button}>
            <Square size={12} className="text-rose-600 dark:text-red-400" />
            <span>{status!.stopRequested ? "Stopping after this tenant..." : "Stop"}</span>
          </button>
        )}

        {running && (
          <div className="flex-1 min-w-[240px]">
            <div className="flex items-center gap-2">
              <RefreshCw size={12} className="animate-spin text-indigo-600 dark:text-indigo-400 shrink-0" />
              <span className="font-medium text-slate-900 dark:text-slate-100">
                Syncing {Math.min(status!.completed + 1, status!.total)} of {status!.total}: {status!.current?.tenantName || "..."}
              </span>
              {status!.currentStep && (
                <span className="text-slate-500 dark:text-slate-400 truncate">
                  {status!.currentStep.step} ({status!.currentStep.percent}%)
                </span>
              )}
            </div>
            <div className="mt-1 h-1 bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
              <div className="h-full bg-indigo-600 dark:bg-indigo-400 transition-all" style={{ width: `${status!.total ? Math.round((status!.completed / status!.total) * 100) : 0}%` }} />
            </div>
            <div className="mt-0.5 text-[11px] text-slate-500 dark:text-slate-400">
              One tenant at a time{status!.source === "scheduled" ? " (started by auto-sync)" : ""}. You can leave this screen; it keeps going.
            </div>
          </div>
        )}

        {finished && (
          <div className="flex items-center gap-1.5">
            {failed.length === 0 && !status!.stopped ? (
              <CheckCircle2 size={13} className="text-emerald-600 dark:text-emerald-400" />
            ) : (
              <AlertTriangle size={13} className="text-amber-600 dark:text-amber-400" />
            )}
            <span>
              {status!.stopped ? "Stopped: " : "Last run: "}
              {status!.completed - failed.length} of {status!.total} synced
              {failed.length > 0 ? `, ${failed.length} failed` : ""}
              {status!.stopped ? `, ${status!.total - status!.completed} skipped` : ""} at {new Date(status!.finishedAt!).toLocaleTimeString()}
            </span>
          </div>
        )}

        {error && <span className="text-rose-600 dark:text-red-400">{error}</span>}
      </div>

      {failed.length > 0 && (
        <ul className="text-[11px] text-rose-700 dark:text-red-400 space-y-0.5">
          {failed.map((r) => (
            <li key={r.tenantId}>
              <span className="font-semibold">{r.tenantName}:</span> {r.error}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
};
