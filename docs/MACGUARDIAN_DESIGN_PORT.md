# MacGuardian concepts in the Linux interface

Reference: https://github.com/abelxmendoza/MacGuardianWatchdog

Implemented from the native Mac app's design patterns:

- `DashboardView.swift`: branded page introduction, summary cards together, named quick actions, and a dedicated activity area. Linux continues to calculate its score from actual audit checks.
- `Components/SectionHeader.swift`: reusable headers with clear hierarchy.
- `Components/AlertBanner.swift`: contextual explanations for process impact and cache cleanup.
- `Components/SecurityCard.swift` and `RiskBadge.swift`: raised cards and explicit impact labels, with text rather than color alone communicating meaning.
- `ExecutionHistoryView.swift`: combine text search with a categorical filter; the process view now filters by impact. Expanded process groups survive filtering, sorting, and refresh.
- `ThemeColors.swift`: black and charcoal surfaces, purple primary actions, brighter secondary accents for readable GTK text.
- Progressive detail: simple process descriptions, expandable groups, and selectable advanced command details.

Backend-dependent concepts for future Linux work:

- Persistent execution history and incident timelines need a shared event model and storage covering every action.
- Network graphs and live threat monitoring need Linux collectors, connection attribution, and explicit collection status.
- Threat intelligence needs feed ingestion, freshness indicators, provenance, and offline/error handling.
- Remediation previews and rollback need a Linux action registry and recovery records before adding a remediation center.

These are not represented as functioning features or populated with simulated security results.
