# Clarity365

## AI Context Map

This repository has a structured Obsidian vault at `ai-context-vault/` documenting architecture, the data model, every service and module, the API surface, and known gaps (security, test coverage, structural risk). Start at `ai-context-vault/Clarity365 MOC.md`, which links out to all vault documents.

* Before changing `tenant-store.ts`, `types/index.ts`, `graph-client.ts`, or anything else the vault describes as a hub or core object, read its note first and check incoming links to understand the blast radius before touching it.
* Before adding a new module, service, or API route, check `ai-context-vault/` for the existing pattern in that category (such as baseline matcher structure or API wiring patterns) and follow established conventions.
* After adding, renaming, or removing a module, service, or API route, update the matching notes in `ai-context-vault/` in the same session so documentation stays synchronized.
* `ai-context-vault/Optimization/Optimization Plan.md` tracks known gaps. Check it before starting work in an area it flags, and update it when a gap closes or a new one turns up.
