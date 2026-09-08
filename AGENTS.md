# Clarity365: Agent Guidelines and Obsidian Knowledge Vault

## Mandatory Obsidian-First Workflow

The `ai-context-vault/` directory is the living architectural map and source of truth for Clarity365. The agent must adhere to the following strict rules:

### 1. Pre-Execution Context Check (Read)
* **Check Obsidian First**: Before answering architectural questions, researching bugs, or proposing code changes, you MUST read the corresponding notes in `ai-context-vault/`.
* **Navigation Anchor**: Always use [Clarity365 MOC.md](file:///c:/Users/BiaanVanSittert/Clarity365/ai-context-vault/Clarity365%20MOC.md) as the primary index to find relevant architecture, domain models, services, modules, or API routes.
* **Blast Radius Analysis**: Before modifying high-fan-out hub files (`tenant-store.ts`, `types/index.ts`, `graph-client.ts`, `fleet-operations.ts`), inspect their notes and incoming links/backlinks to understand dependencies.
* **Pattern Alignment**: Ensure newly proposed services or modules conform to established patterns documented in `ai-context-vault/Services/` (e.g., baseline matchers, data mappers, fleet operations).

### 2. Mandatory Vault Synchronization (Write)
* **Update in Same Session**: Whenever you add, rename, refactor, or delete a module, service, API endpoint, or data type, you MUST update the corresponding note(s) in `ai-context-vault/` within the same turn. Never defer documentation updates to a later task.
* **Maintain Link Integrity**: When creating or renaming files or concepts, update wikilinks (`[[Note Name]]`) to preserve the Obsidian graph.
* **Backlog & Gaps**: When addressing or finding technical debt, security gaps, or testing deficits, update [Optimization Plan.md](file:///c:/Users/BiaanVanSittert/Clarity365/ai-context-vault/Optimization/Optimization%20Plan.md) immediately.

### 3. Tooling Integration
* Utilize the `obsidian` MCP server (`obsidian-mcp-rs`) or direct filesystem read/write tools to interact with the vault seamlessly.
