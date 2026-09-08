# Clarity365

## AI context map
This repo has a hand-built Obsidian vault at `ai-context-vault/` documenting architecture, the data model, every service and module, the API surface, and known gaps (security, test coverage, structural risk). Start at `ai-context-vault/Clarity365 MOC.md` — it links out to everything else.

- Before changing `tenant-store.ts`, `types/index.ts`, `graph-client.ts`, or anything else the vault describes as a hub/god-object, read its note first and check what links to it, so you know the blast radius before touching it.
- Before adding a new module, service, or API route, check `ai-context-vault/` for the existing pattern in that category (e.g. how a baseline matcher is shaped, how a module wires up its API calls) and follow it unless there's a reason not to.
- After adding, renaming, or removing a module, service, or API route, update the matching note(s) in `ai-context-vault/` in the same session. Don't let the vault go stale — that's exactly how the git history itself drifted 203 commits before this vault existed.
- `ai-context-vault/Optimization/Optimization Plan.md` tracks known gaps. Check it before starting work in an area it flags, and update it when a gap closes or a new one turns up.
