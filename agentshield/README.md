# AgentShield — Platform & Enforcement demo

A responsive React security dashboard built with React 19, TypeScript, Vite 8,
Tailwind CSS v4, Recharts, and Lucide icons. **Frontend demo only. No backend is connected.**

## Location and preview

Implementation lives in `agentshield/frontend/src/`. The existing workspace's
`src/App.tsx` and `src/index.css` mount the module so it runs in Figma Make's
automatically managed preview. Dependencies and the Vite configuration remain at
the workspace root; this directory is not a separately installed application.

Open the Figma Make preview panel. No additional development server is needed.

## Included

- Overview with seeded metrics, period selection, activity chart, risk breakdown,
  event details, integration status, and fleet summary.
- Agent creation, demo key generation/rotation, disable/enable controls.
- Agent-specific capability toggles, editable scopes, domain restrictions,
  approval requirements, and a payment-budget input.
- Policy drafts, activation/deactivation, version history, and rollback UI.
- Exact-action approval review with masked values, comments, approve/reject,
  and a session audit event for each review.
- Audit search, decision filters, pagination, event details, CSV/JSON export.
- Ten local-only attack demonstrations and exportable results.
- Quarantine review, delete, and demo release.
- Workspace search (`Ctrl/Cmd+K`), notifications, settings, and demo sign-in.
- Mobile navigation and responsive layouts.

## Demo sign-in

The dashboard opens directly in the demo workspace. Sign out through the
top-right account menu to see the login screen:

- Email: `admin@agentshield.demo`
- Password: `demo-password`

These are public UI demo values, **not real credentials**. There is no JWT,
password hashing, identity verification, or server-side role enforcement.

## Commands

Run from the workspace root:

```sh
pnpm install
pnpm build
pnpm exec tsc --noEmit
pnpm exec vitest run --config agentshield/frontend/vitest.config.ts
pnpm exec playwright install chromium
pnpm exec playwright test --config agentshield/frontend/playwright.config.ts
```

Browser tests target the existing server on `$PORT` (fallback `3000`, as reported
by `figma make preview status`). Set `AGENTSHIELD_PREVIEW_URL` to override.
Do not launch an additional server in Figma Make.

## Structure

```text
agentshield/
  README.md
  INTEGRATION.md
  BUILD_STATUS.md
  frontend/
    playwright.config.ts
    vitest.config.ts
    tests/
      dashboard.spec.ts
    src/
      App.tsx
      styles.css
      components/
        ui.tsx
      pages/
        Overview.tsx
      services/
        demo.ts
        demo.test.ts
```

## Important limitations

All state is in memory and resets on reload. Summary metrics and chart samples
are seeded illustrations, not real monitored activity. New audit events and
simulator results exist only for the current session. Policy edits and permission
changes do not configure a real authorization engine.

The simulator evaluates local deterministic rules. It does **not** test a real
Execution Gateway, OPA, tenant isolation, approval signatures/replay prevention,
or OS/container boundaries. Audit integrity verification explicitly reports
"Not verified"; there is no cryptographic chain or append-only database.

No dangerous host commands, email delivery, filesystem access, or payments are
implemented. There is no API URL, PostgreSQL, Redis, Docker infrastructure, SDK,
or P1/P2/P3 Python module in this demo. See `INTEGRATION.md` for next steps.
