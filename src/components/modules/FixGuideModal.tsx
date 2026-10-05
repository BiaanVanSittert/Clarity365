"use client";

import React, { useState } from "react";
import { AlertTriangle, Check, Copy, ExternalLink, Undo2, ShieldCheck } from "lucide-react";
import { Modal } from "../common/Modal";
import type { ResolvedCommand, ResolvedFixGuide } from "@/lib/services/scenario-fix-guide-builder";
import { describePolicyImpact, type PolicyImpactPreview } from "@/lib/services/ca-policy-impact";

// "How to fix" guide for one Security Scenarios check on one tenant: portal
// steps and copyable commands. Guides only - nothing here changes the tenant.

const CommandBlock: React.FC<{ command: ResolvedCommand }> = ({ command }) => {
  const [copied, setCopied] = useState<"connect" | "script" | null>(null);
  const copy = (what: "connect" | "script", text: string) => {
    navigator.clipboard?.writeText(text);
    setCopied(what);
    setTimeout(() => setCopied(null), 1500);
  };
  const Block = ({ id, label, text }: { id: "connect" | "script"; label: string; text: string }) => (
    <div>
      <div className="flex items-center justify-between text-[10px] text-slate-500 dark:text-slate-400 mb-0.5">
        <span>{label}</span>
        <button type="button" onClick={() => copy(id, text)} className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-sm border border-[#CBD5E1] dark:border-slate-600 hover:bg-slate-50 dark:hover:bg-slate-700">
          {copied === id ? <Check size={10} /> : <Copy size={10} />} {copied === id ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="p-2 bg-slate-950 text-emerald-300 font-mono text-[11px] rounded-sm overflow-x-auto whitespace-pre">{text}</pre>
    </div>
  );
  return (
    <div className="space-y-1.5">
      <div className="text-[10px] font-semibold text-slate-600 dark:text-slate-300">
        {command.shellLabel} <span className="font-normal text-slate-500 dark:text-slate-400">(first time: {command.install})</span>
      </div>
      <Block id="connect" label="1. Connect" text={command.connect} />
      <Block id="script" label="2. Run" text={command.script} />
    </div>
  );
};

const Section: React.FC<{ title: string; children: React.ReactNode }> = ({ title, children }) => (
  <section className="space-y-1.5">
    <h4 className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">{title}</h4>
    {children}
  </section>
);

const PreviewBlock: React.FC<{ preview: PolicyImpactPreview }> = ({ preview }) => {
  const { headline, lines } = describePolicyImpact(preview);
  const tone =
    preview.blocked > 0
      ? "border-rose-300 dark:border-rose-800 bg-rose-50 dark:bg-rose-950/40"
      : preview.challenged > 0
        ? "border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/40"
        : "border-emerald-300 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-950/40";
  return (
    <div className={`p-2.5 rounded-sm border space-y-1 ${tone}`}>
      <p className="font-semibold text-slate-800 dark:text-slate-100">{headline}</p>
      <ul className="list-disc pl-5 space-y-0.5">
        {lines.map((l, i) => (
          <li key={i}>{l}</li>
        ))}
      </ul>
      <p className="text-[10px] text-slate-500 dark:text-slate-400">
        An estimate from the synced sign-ins only: every sign-in is treated as a sign-in to Office 365, and sign-ins older than the sync aren&apos;t included. The policy&apos;s own report-only results are the real test.
      </p>
    </div>
  );
};

export const FixGuideModal: React.FC<{ guide: ResolvedFixGuide; onClose: () => void }> = ({ guide: g, onClose }) => (
  <Modal isOpen onClose={onClose} title={g.title} subtitle={`How to fix · ${g.tenantName}`} maxWidth="3xl">
    <div className="space-y-4 text-xs text-slate-700 dark:text-slate-300 max-h-[75vh] overflow-y-auto pr-1">
      <p>{g.summary}</p>
      <p className="text-slate-500 dark:text-slate-400">
        <strong className="text-slate-700 dark:text-slate-200">Stops: </strong>
        {g.stops}
      </p>

      {g.warnings.length > 0 && (
        <div className="p-2.5 rounded-sm border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/50 text-amber-900 dark:text-amber-300 space-y-1">
          {g.warnings.map((w, i) => (
            <div key={i} className="flex items-start gap-1.5">
              <AlertTriangle size={12} className="mt-0.5 shrink-0" /> <span>{w}</span>
            </div>
          ))}
        </div>
      )}

      <Section title="Before you start">
        <ul className="list-disc pl-5 space-y-0.5">
          {g.prerequisites.licence && <li>Licence: {g.prerequisites.licence}</li>}
          <li>Admin role: {g.prerequisites.adminRole}</li>
          {(g.prerequisites.other || []).map((o, i) => (
            <li key={i}>{o}</li>
          ))}
        </ul>
      </Section>

      <Section title="Who is affected">
        <p>{g.impact}</p>
        {g.rollout && <p className="p-2 rounded-sm bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-700">{g.rollout}</p>}
      </Section>

      {g.preview && (
        <Section title="What this policy would have done">
          {g.preview.available ? (
            <PreviewBlock preview={g.preview.result} />
          ) : (
            <p className="text-slate-500 dark:text-slate-400">{g.preview.reason}</p>
          )}
        </Section>
      )}

      <Section title="Steps">
        <ol className="space-y-3">
          {g.steps.map((s, i) => (
            <li key={i} className="border border-slate-200 dark:border-slate-700 rounded-sm p-2.5 space-y-2">
              <div className="font-semibold text-slate-900 dark:text-slate-100">
                {i + 1}. {s.title}
              </div>
              {s.portal && (
                <div>
                  <a href={s.portal.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-indigo-700 dark:text-indigo-300 underline">
                    {s.portal.url.replace(/^https:\/\//, "")} <ExternalLink size={10} />
                  </a>
                  <ol className="mt-1 list-decimal pl-5 space-y-0.5">
                    {s.portal.steps.map((p, j) => (
                      <li key={j}>{p}</li>
                    ))}
                  </ol>
                </div>
              )}
              {s.command && <CommandBlock command={s.command} />}
              {s.note && <p className="text-slate-500 dark:text-slate-400">{s.note}</p>}
            </li>
          ))}
        </ol>
      </Section>

      <Section title="Confirm it worked">
        <p className="flex items-start gap-1.5">
          <ShieldCheck size={12} className="mt-0.5 shrink-0 text-emerald-600 dark:text-emerald-400" /> {g.verify.inClarity}
        </p>
        {g.verify.command && <CommandBlock command={g.verify.command} />}
      </Section>

      <Section title="Undo">
        <p className="flex items-start gap-1.5">
          <Undo2 size={12} className="mt-0.5 shrink-0" /> {g.undo.text}
        </p>
        {g.undo.command && <CommandBlock command={g.undo.command} />}
      </Section>

      <Section title="Microsoft documentation">
        <ul className="space-y-0.5">
          {g.learn.map((l) => (
            <li key={l.url}>
              <a href={l.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-indigo-700 dark:text-indigo-300 underline">
                {l.title} <ExternalLink size={10} />
              </a>{" "}
              <span className="text-slate-400 dark:text-slate-500">checked {l.checked}</span>
            </li>
          ))}
        </ul>
      </Section>
      <p className="text-[10px] text-slate-400 dark:text-slate-500">Clarity365 doesn&apos;t make these changes. You run them, then re-sync this tenant to see the result.</p>
    </div>
  </Modal>
);
