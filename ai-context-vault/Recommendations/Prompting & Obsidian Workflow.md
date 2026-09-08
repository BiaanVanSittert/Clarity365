---
tags:
---

# Prompting & Obsidian Workflow

How to get more out of Claude Code sessions on Clarity365 using this vault, and how to keep the vault itself honest.

## Prompt shorter, point instead of re-explaining
Instead of re-describing architecture in a prompt ("there's a tenant store that talks to Graph and..."), point at the note: *"See `ai-context-vault/Services/Tenant Store.md` — add a new method there for X."* Claude Code reads local files directly, so a pointer costs a few words; a re-explanation costs a paragraph and risks drifting from what's actually true. This matters most for the god nodes — [[Tenant Store]] and [[Domain Types]] — since those are the files any non-trivial prompt tends to touch.

## Name the blast radius up front
Before asking for a change to a hub file, open its note and check what links to it (Obsidian's **Backlinks** pane, bottom-right by default). If you're changing `ca-baseline-matcher.ts`, [[Baseline Matchers]] lists five direct consumers plus [[Analysis & Generation]] — naming those in the prompt ("...and check it doesn't break drift-analyzer or compliance-evaluator") gets you a more careful diff than a bare feature request does.

## Keep the vault from going stale like the git repo did
The whole reason this session started with a 203-commit surprise is that nobody was checking drift. The vault can rot the same way. Cheapest fix: add a line to this repo's own `CLAUDE.md` (project-level, not your global one) —
> When you add, rename, or remove a module, service, or API route, update the matching note in `ai-context-vault/` in the same session.

That turns vault upkeep into a normal part of the diff instead of a separate remembered chore.

## Use the graph view as a planning tool, not just a picture
Filter Obsidian's graph (bottom-left funnel icon) to one tag — `#fleet` before touching any fleet feature, `#service` when you want to see the dependency backbone without UI noise. If a change spans a visible cluster (e.g. all three `#fleet` modules plus [[Fleet Operations]]), that's a sign the prompt should describe it as one coordinated change, not three separate asks.

## Turn the [[Testing]] gap list into a checklist
Obsidian renders `- [ ]` as a clickable checkbox. Worth converting the untested-file list in [[Testing]] into checkboxes and checking one off per session you close a gap — a visible, shrinking list is a better prompt-writing aid ("next: auth.ts tests") than remembering what's covered.

## Complementary tool already in your setup: graphify
Your global Claude Code config has a `graphify` skill installed — it turns a codebase into a knowledge graph with automatic god-node and community detection. This vault was built by hand from three targeted scans; `/graphify` on this same repo would do it algorithmically and might surface dependency cycles or clusters this pass missed (e.g. confirming `tenant-store.ts` and `TenantSecuritySnapshot` really are the top god-nodes, or finding others). Worth running as a cross-check, not a replacement — its output format is different (a queryable graph, not an Obsidian vault) and wouldn't have made a browsable mindmap on its own.

## Re-scan cadence
Today's gap was extreme (203 commits) because nothing prompted a check. Rather than waiting for the next surprise, ask for a vault refresh after any large batch of merged work — e.g. "diff the vault against HEAD and update what's changed" is a much cheaper prompt than the full scan this session ran, since only the delta needs re-reading.

## Optional, if you want to go further
The vault was deliberately built with zero community plugins (portable, nothing to install). Two are worth it if this grows:
- **Dataview** — query notes like a database, e.g. list every module tagged `#fleet` with no corresponding test file.
- **Canvas** (built into Obsidian core, no plugin) — freeform diagram for planning a specific feature across modules, referencing existing notes.

Part of [[Clarity365 MOC]].
