# Error handling review

Historical review from September 24. For the current live-tested behavior, corrections to overlap/NAT handling, and remaining operational gaps, see [September 25 operational comparison](operations-comparison.md).

Reviewed 2026-09-24 by three independent agents covering export/dependencies, import/verification, and transport/session recovery, followed by integration review. Reference: CheckPointSW/ExportImportPolicyPackage revision `5e53c859adc13ba0ff7b0b3aa8541d240f6a5f44` (V6.3). This app adapts the workflow in JavaScript; it does not run the Python importer.

## What improved

| Area | Original Python | Current app |
| --- | --- | --- |
| Review before writing | Export/import CLI workflow | Object creation/reuse/conflict preview and visual rulebase; execution re-scans and checks the reviewed fingerprint |
| Global policy | Handles inherited layers during traversal/placement | Blocks migration for source or destination global assignments or inherited layers; malformed assignment status fails closed |
| Conflicts | Existing-object handling and reference mapping | Definition comparison, overlap checks, and explicit incoming-object rename; source and existing target objects remain intact |
| Unsupported objects | Can export/import placeholder objects | Blocks unsupported definitions, unresolved references, and upstream placeholder names |
| Failure behavior | Strict abort/discard is optional; supports batch publication | Stops staging on errors/warnings, attempts discard, reports failed discard as recovery required |
| Publication | Checks publish/discard results; can publish batches | Stages the supported migration before explicit publish; unknown and partial outcomes remain blocked pending reconciliation |
| Read-only source | Already supported upstream | Preserved; not a new improvement |

## Gaps found and fixed in this review

- Restored upstream normalization for inactive service settings and Drop-rule response fields. Normalize tracking and layer cleanup enums before object UID translation.
- Prevented unrelated tags from comparing as identical. Recursively validate dependencies before reusing groups.
- Blocked import missing-field placeholders in addition to export placeholders.
- Removed the rule-expiration exemption: expiration settings now block migration instead of silently disappearing. Supporting expiration requires an explicit adapter.
- Pagination advances by actual rules returned, validates totals/progress, and rejects repeated rules or inconsistent page bounds. Inventory pagination rejects duplicate UIDs and changing totals. Continued sections are retained once.
- Verify source object/layer and destination object identity when fetching full definitions. Include the selected package when reading access rulebases.
- Verify NAT fields/order, Access/NAT sections and tags, and attached package layer order; verification failures trigger discard.
- Reject truncated/aborted HTTP response bodies instead of leaving the request pending.
- Distinguish all-failed publish tasks from partial/unknown outcomes. A definitive failure becomes discardable only after inspecting remaining session changes.
- Prevent simultaneous unresolved migrations to the same exact MDS host/domain across connections within this app process.

## Follow-up improvements implemented

- A durable, nonsecret operation journal reserves unfinished destinations across restart. Atomic, fsynced records use restrictive permissions and whitelist persisted fields. Passwords, API keys, login SIDs, raw responses and policy definitions are not persisted.
- Freshly authenticated recovery inspects the original session UID, can resume only the same administrator’s disconnected API session, and verifies discard. Unknown publication cannot be retried or treated as rollback. A recovery panel provides these actions after login.
- Keepalive reduces session expiry during unresolved migrations; failed keepalive blocks publication and directs the operator to authenticated recovery.
- Framework capability probes negotiate the highest common version across MDS/source/destination. The matching official catalog is loaded on demand and the planned commands/fields are validated. The chosen version is pinned in the reviewed plan and journal through publication and recovery; v1.9-only environments can use v1.9.
- Created object and layer readback verifies identity and supported writable settings, including renamed objects, dependencies, tags, service normalization, and layer blade settings. Verification failure prevents staging success and triggers discard.
- Recovery actions on one record are serialized across browser connections. Destination reservation files also protect staging across processes sharing the same journal directory.

## Remaining boundaries

1. **Live release validation.** These changes are covered with API fixtures, failure injection and synthetic browser checks. Real MDS response defaults, permissions, publication and recovery behavior still require a controlled lab validation.
2. **Conservative recovery.** Missing task IDs after a publish interruption, unavailable historical sessions, and expired sessions the server cannot resume remain blocked for SmartConsole investigation. Recovery cannot reconstruct the full reviewed plan or continue partial staging. A damaged journal or orphan lock deliberately requires local investigation.
3. **Scope parity.** Supported object types/blades remain narrower than upstream. Automatic NAT, rule expiration and unmapped features block; they are not silently converted. Source-source equivalent objects remain separate creations rather than being deduplicated.
4. **Concurrency boundaries.** Host aliases, processes using different journal directories, and SmartConsole changes are outside local reservations. Recovery serialization within this app supplements, rather than replaces, Check Point’s session ownership enforcement.
5. **Schema strictness.** Unexpected writable defaults block migration until an explicit documented normalization is added. Advertised API compatibility is not proof that a complete policy will migrate.

## Validation and conclusion

`npm run check`: **112 tests passed**. The regression suite covers transport interruption, pagination, object/rule readback, compatibility gates, journal persistence/corruption, and authenticated recovery. Synthetic browser checks cover desktop/mobile layout, inspection, wrong-name refusal and verified discard. No live MDS was contacted.

The app improves reviewability and conservative execution for its supported scope. It is not a complete replacement for, or an across-the-board improvement over, the original utility. Validate the supported workflow against the actual MDS release before production use.
