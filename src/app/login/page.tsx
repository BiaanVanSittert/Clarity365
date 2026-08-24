"use client";

import React, { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { ShieldCheck, Lock, KeyRound } from "lucide-react";

type Mode = "loading" | "setup" | "login";

export default function LoginPage() {
  const router = useRouter();
  const [mode, setMode] = useState<Mode>("loading");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    fetch("/api/auth/status")
      .then((res) => res.json())
      .then((data) => setMode(data.configured ? "login" : "setup"))
      .catch(() => setMode("login"));
  }, []);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password }),
      });
      const data = await res.json();
      if (!data.success) {
        if (data.needsSetup) {
          setMode("setup");
          throw new Error("No password has been set up yet — create one below.");
        }
        throw new Error(data.error || "Login failed.");
      }
      router.push("/");
      router.refresh();
    } catch (err: any) {
      setError(err.message || "An unexpected error occurred.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleSetup = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);
    try {
      const res = await fetch("/api/auth/setup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password, confirmPassword }),
      });
      const data = await res.json();
      if (!data.success) {
        throw new Error(data.error || "Setup failed.");
      }
      router.push("/");
      router.refresh();
    } catch (err: any) {
      setError(err.message || "An unexpected error occurred.");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen w-full bg-[#F8FAFC] flex items-center justify-center px-4">
      <div className="w-full max-w-sm bg-white border border-[#CBD5E1] rounded-sm shadow-sm p-6">
        <div className="flex items-center gap-2 mb-1">
          <div className="h-7 w-7 bg-slate-900 text-white rounded-sm flex items-center justify-center font-mono font-bold text-xs">
            C
          </div>
          <span className="text-sm font-bold tracking-tight text-slate-900">Clarity365</span>
        </div>
        <p className="text-xs text-slate-500 mb-5">Multi-Tenant M365 IRM &amp; Security Posture Suite</p>

        {mode === "loading" && <p className="text-xs text-slate-400">Checking setup status...</p>}

        {mode === "setup" && (
          <form onSubmit={handleSetup} className="space-y-3">
            <div className="p-2.5 bg-slate-50 border border-slate-200 text-slate-700 text-xs rounded-sm">
              First run — create the operator password used to sign in to Clarity365.
            </div>
            {error && (
              <div className="p-2.5 bg-red-50 border border-red-200 text-red-700 text-xs rounded-sm">{error}</div>
            )}
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">New Password</label>
              <div className="relative">
                <KeyRound size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
                <input
                  type="password"
                  required
                  autoFocus
                  minLength={8}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-8 pr-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white"
                  placeholder="At least 8 characters"
                />
              </div>
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">Confirm Password</label>
              <div className="relative">
                <KeyRound size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
                <input
                  type="password"
                  required
                  minLength={8}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="w-full pl-8 pr-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white"
                  placeholder="Re-enter password"
                />
              </div>
            </div>
            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full flex items-center justify-center gap-1.5 px-3.5 py-2 text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 rounded-sm transition-colors disabled:opacity-50"
            >
              <ShieldCheck size={14} />
              <span>{isSubmitting ? "Creating..." : "Create Password & Sign In"}</span>
            </button>
          </form>
        )}

        {mode === "login" && (
          <form onSubmit={handleLogin} className="space-y-3">
            {error && (
              <div className="p-2.5 bg-red-50 border border-red-200 text-red-700 text-xs rounded-sm">{error}</div>
            )}
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">Operator Password</label>
              <div className="relative">
                <Lock size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
                <input
                  type="password"
                  required
                  autoFocus
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-8 pr-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white"
                  placeholder="Enter password"
                />
              </div>
            </div>
            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full flex items-center justify-center gap-1.5 px-3.5 py-2 text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 rounded-sm transition-colors disabled:opacity-50"
            >
              <ShieldCheck size={14} />
              <span>{isSubmitting ? "Verifying..." : "Sign In"}</span>
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
