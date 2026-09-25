# Framework Design System

The approved interface is the compact operator workbench inherited from the user's local CP-API-Framework at `/Users/aforester/Documents/GitHub/CP-API-Framework`, originally inspired by the Hardening App. Single Policy Move extends that existing visual system; the application-specific patterns below take precedence over generic framework examples.

## Tokens
| Role | Value |
| --- | --- |
| Page | #eef2f7 |
| Surface | #ffffff |
| Subtle surface | #f8fafc |
| Navigation | #f4f6fa |
| Main text | #142033 |
| Secondary text | #526278 |
| Borders | #d8e0ea |
| Primary action | #ca004c |
| Primary hover | #a90040 |
| Selected surface | #ffe9f1 |
| Selected text / border | #a50040 / #f4c1d3 |

Use existing CSS variables; add named tokens for repeated new values. Green, amber, and red indicate actual status, with text labels as well as color.

## Typography and Geometry
Use local system sans-serif fonts and monospace for commands, JSON, IDs and output. No font downloads. Working headings are about 23px, labels 13px at weight 600, help text 12–13px. Login introduction may use 38px text; brand subtitle 25px. Keep uppercase and bold restrained.

Controls are at least 44px tall, with 6px corners. Status badges use 4px corners. The page has a 1440px maximum width and 20px side gutters. The desktop navigation is 244px wide. Content has 24px vertical and 28px horizontal padding. Prefer separators to nested cards.

## Layout
The framework login is a two-column introduction and form, maximum 1080px wide. Single Policy Move extends it to 1120px with management connection forms. Preserve password/API-key switching, conditional credential fields, TLS and large-environment options. The connection mode supports two domains on one MDS or independent endpoints, including standalone management and Smart-1 Cloud.

The workspace has a compact connection header followed by navigation and a content column. Single Policy Move uses five numbered views: Domains & policy, Preflight checks, Object changes, Rulebase preview, and Review & migrate. Source/destination selection stays attached to setup; subsequent plan views share a source-to-destination route strip. Unavailable navigation is disabled and the selected view retains the framework's pink selected surface and `aria-pressed` state.

At 850px or narrower, navigation moves above content and login becomes one column. Existing form breakpoints still apply. Long URLs and IDs can wrap; columnar output scrolls horizontally within its own container.

## Implementation
Styles load in order: `public/styles.css`, `public/workbench.css`, then the application extension `public/migration.css`. The migration screen uses `public/app.js`; it does not load the generic framework workbench controller. Preserve form IDs/listeners and reuse the existing surfaces, controls and CSS variables. Application body text is 14px, and desktop content padding is 28px.

Avoid decorative dashboards, animated backgrounds, marketing hero treatments, large empty cards and unrelated fonts. Motion should explain feedback or state and respect reduced-motion preferences if introduced.

## Verification
Check desktop and narrow screens, keyboard focus, selected navigation, long tenant URLs, MDS field expansion, password/API-key switching and output overflow. Use sample or intercepted responses for visual checks; do not run live gateway operations solely to validate styling.

## Migration Workflow Patterns

Use separated rows and compact summaries to explain a plan. Preflight rows pair an icon with a written result and reason. Object tables expose names, types, source definitions, destination matches and outcomes; search and outcome filters sit immediately above them. Object details compare source and destination definitions side by side, with monospace JSON available for inspection. Rule tables preserve visible section boundaries, disabled-rule treatment and a legend for object references. Raw API responses are disclosed below the main preview rather than replacing it.

Keep stage, review and publish visibly distinct. The final view uses a three-part sequence, a destination-name confirmation and a review checkbox before staging. Published or discarded outcomes and task status belong beside the operation log. The synthetic demo is labeled at entry and in its scenario controls; it must not appear to be a live connection.

### Status Semantics

| Meaning | Foreground / background | Application |
| --- | --- | --- |
| Passed / reuse | `--ok` (#18794e) / `--success-bg` (#edf7f1) | Passed checks, reused objects and matching references |
| Conflict / blocked / failed | `--error` (#aa2536) / `--error-bg` (#fff2f3) | Blocking checks, unresolved objects and errors |
| Create / information | `--blue` (#225d9b) / `--blue-bg` (#edf4fc) | New objects and informational workspace status |
| Neutral | `--muted` (#526278) / #edf1f6 | Step labels and neutral metadata |
| Warning, reserved | `--warn` (#9a6700) / `--amber-bg` (#fff8e7) | Existing warning tokens; no active migration badge variant is established |

Color always accompanies a readable label or explanation. The primary magenta remains an action/selection color, not a success or failure signal. Do not substitute a warning treatment for a blocking state.

### Responsive Extension

At 1100px and below, navigation narrows to 215px and content padding becomes 24px. At 850px and below, login stacks, navigation becomes a three-column grid above content, and sidebar safeguards/footer are hidden. At 520px and below, navigation uses two columns; domain routing, definition comparison and the migration sequence stack; the rescan action spans the route strip. Page gutters reduce to 12px and content padding to 22px vertically / 16px horizontally.

Object and rule tables retain minimum widths of 740px and 780px, respectively, with scrolling confined to their table containers. Long route names and JSON wrap. The inherited visible focus outline is 2px magenta with a 3px offset. Standard controls retain 44px minimum height; compact connection/route actions currently use 36px. Status-entry animation runs only when reduced motion is not requested.

### Local Assets

The migration screen loads local CSS and JavaScript and uses inline SVG for its brand and interface icons. Typography uses system sans-serif and system monospace stacks; no remote fonts, image services or runtime icon downloads are required. Upstream GitHub links are reference navigation, not asset dependencies.

### Verification Scope

These extensions are documented from the HTML/CSS source and the existing framework system. Desktop browser inspection uses CUA; it does not establish coverage of every workflow state. Mobile layouts have not been visually checked: the breakpoint descriptions above are source-reviewed behavior, not a claim of mobile visual validation. No live MDS environment or credentials were supplied, so synthetic preview checks cannot establish live migration correctness. Functional test results belong in the implementation handoff.

### Conflict resolution
Name conflicts expose a Resolve action in Object changes. The comparison panel offers a labeled import-name field, Apply rename, inline validation errors and Undo rename. Original source definitions stay visible; the table and rulebase display the chosen import name. Applying a rename regenerates the preview and clears staging acknowledgment. Overlap and unsupported-type blockers remain explicit.

### Workflow activity panel

A compact activity panel sits below the masthead across login and workspace views. Use the existing blue informational surface while running, amber for a completed scan requiring review, green for completed operations, and red for failures or unknown outcomes. Pair the current operation and live message with tabular elapsed time and last server-response age. Keep the timer outside the polite live region, use an indeterminate native progress indicator only while running, and hide its animation under reduced-motion preferences. Counts come from actual reads; avoid invented percentages or time estimates. Narrow layouts wrap the footer without truncating the operation message.
