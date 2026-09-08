---
tags: [module, reporting]
---

# Executive Reporting (QBR)

Client-facing QBR generator :  scorecards, milestones, cost savings, print-to-PDF preview.

- **Component:** `ExecutiveReportingModule.tsx`
- **Backing call:** `report-generator.generateTenantQbrReport` (service call, not a fetch :  same underlying data as `GET /api/reports/qbr`)
- **Key types:** `ExecutiveQbrReport` :  see [[Domain Types]]
- **Renders:** [[Modals#ReportPreviewModal|ReportPreviewModal]] (print/PDF preview, used only here)
- **Uses service:** [[Analysis & Generation]] (`report-generator`, which itself pulls from `fleet-analyzer` + `ca-baseline-matcher`)

Part of [[Clarity365 MOC]]. One of the three "Phase 2" additions from the 203-commit gap, alongside [[Compliance Matrix (CIS-NIST-Essential 8)]] and the Fleet modules.
