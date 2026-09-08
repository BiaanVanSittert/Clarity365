---
tags: [module]
---

# SharePoint & Storage Policies

Quota bars and an external-sharing tier manager for SharePoint/OneDrive.

- **Component:** `SharePointStorageModule.tsx`
- **API routes:** `PUT /api/tenants/{id}/sharepoint`
- **Key types:** `SharePointSiteItem`, `SharePointTenantPolicy` :  see [[Domain Types]]
- **Renders:** `StatusPill`, `LocalOnlyNotice`, `EmptyStateRow`
- **Uses service:** [[Baseline Matchers]] (`sharepoint-baseline-matcher`)
- **Baseline source:** [[Baseline Definitions & Mock Data]] :  `SHAREPOINT_BASELINE_STANDARDS` (5 rules, none auto-fixed yet)

Part of [[Clarity365 MOC]].
