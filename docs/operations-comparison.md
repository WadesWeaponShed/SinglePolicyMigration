> Historical audit: the current native implementation, batching results and validation boundaries are in [native feature comparison](native-feature-parity.md). Statements below describe their recorded run, not the latest feature set.

# Operational comparison after the R82.10 lab run

Reviewed 2026-09-25. Reference: local CheckPointSW/ExportImportPolicyPackage V6.3 checkout, revision `5e53c859adc13ba0ff7b0b3aa8541d240f6a5f44`. This is a source review and observed app run, not a timed head-to-head benchmark or a claim about the latest upstream release.

For the current feature-by-feature assessment, see [Native feature comparison](native-feature-parity.md). This document also retains historical lab results.

## Current correction

The user clarified that parity means native application features, not a Python runner. The wrapper has been retired. Native TP/HTTPS/exception staging, catalog-derived object adapters and archive handling are implemented and undergoing live validation. The historical Access-only run below remains evidence only for that original scope; it is not proof of complete native feature parity. The native path retains separate review, staging and publication instead of upstream intermediate publishes.

## Native expanded lab validation

On 2026-09-25, the native engine successfully staged and independently read back `CMA_LAB_Native_FullCoverage` in Prepotente through the app, using API v2.1. Publication was subsequently observed successful in the app. No policy was installed.

- 100 Access rules and 10 sections, one Threat Prevention rule, two HTTPS rules, and two disabled manual NAT rules. Both manual NAT positions, above and below automatic NAT, passed readback.
- Five imported layers. Check Point's mandatory empty IPS and first TP layer were retained; the generated TP rule was disabled and verified. Existing shared HTTPS defaults were not edited.
- 216 verified object reuses, zero unsupported definitions, four intentional name conflicts resolved with `_MIGRATED`.
- 129 logged writes, 17:55:35.250–17:56:03.348 UTC (28.1 seconds). Total stage operation, including the fresh scan and readback, was about 71 seconds. This is not a clean-destination throughput comparison.
- 166 automated tests passed. Exception groups and fresh object creation have unit coverage; a separate live native fixture is prepared but not yet run. The staged full test reused existing objects.

Live testing corrected outbound HTTPS certificate payloads, R82.10 `threat-section` exception wrappers, documented layer defaults, and NAT `Original` enum readback. Earlier failed attempts confirmed discard and released their destination reservations. Upstream archives are converted in JavaScript; this run used a native snapshot produced from the combined upstream fixture. Current upstream parser changes still require the next server restart to load in the app.

## Earlier Access-only result

The app reports successful publication from Katia / CMA_LAB_Policy to Prepotente / CMA_LAB_Policy_Migrated using API v2.1. The publish task reports `succeeded`, 100% progress. Source retained; no gateway policy installation.

- 198 objects created and 9 reused, including built-in dependencies; zero blockers at final review.
- 100 Access Control rules and 10 sections, one access layer.
- 313 logged staging writes: 198 object additions, 100 rules, 10 sections, one layer, one package, two package updates, one generated-layer deletion.
- First/last logged writes: 15:32:11.214–15:32:44.883 UTC, approximately 33.7 seconds. This excludes scan, readback verification, publication, and unlogged reads. It is not total migration duration.
- Source preview contained no manual NAT rules. Two generated NAT rules were excluded, together with empty NAT headers. This run does not validate a substantive NAT migration.
- HTTPS Inspection was explicitly excluded with a manual-migration notice.
- At that lab run: 138 passing tests. The native expansion has its own regression suite; the older Python wrapper checks are retired. Earlier lab failures exercised cleanup; the most recent failures reported confirmed discard, with reservations released.

## Comparison

| Area | Python utility at inspected revision | Current app | Assessment |
| --- | --- | --- | --- |
| Operator review | CLI export/import with archive and console output | Visual preflight, definitions, planned reuse/create, rule preview, downloadable plan | Improved reviewability |
| Name conflicts | Collision renaming and duplicate-handling flags | Exact definition comparison; explicit individual or bulk `_MIGRATED` rename | More control before writes; not a novel rename capability |
| Broad ranges | Importer sets `ignore-warnings` when creating objects | Broad address/port overlap alone no longer blocks or causes reuse; API warnings still stop staging | Removed app overrestriction; different warning policy |
| Progress | Console counts and percentages already exist | Workflow-wide status, actual scan counts, elapsed time, response age | Better GUI visibility, not a unique underlying capability |
| Publication | Automatic publish and supported batch publishing paths | One dedicated staged migration, explicit publish after verification | Stronger operator control; larger unpublished session |
| Failure cleanup | Strict option discards/aborts; publish error handling also discards | Staging errors automatically discard; definitive publish failure with remaining changes also discards; current-session zero-change verification | More consistent default cleanup; live automatic-discard path now exercised |
| Readback | Checks API replies and publish/task results | Reads created objects, layers, attachment order, rule fields and order before declaring staging complete | Additional independent verification |
| Drift/concurrency | No equivalent reviewed-plan fingerprint identified in reviewed import path | Rescan/fingerprint before writes; same-host/domain reservation with durable journal | Additional safeguards, but external admins/host aliases remain outside local locking |
| API compatibility | Version-aware transformations, batching and broad type dictionaries | Common-version negotiation, pinned nested catalog checks, catalog-derived named-object adapters and explicit policy handlers | New fields/types can grow with catalogs; special transformations still require tests |
| Portability | Export/import `.tar.gz`; separated export and import environments | Direct migration, native `.cma.gz` export/import, upstream `.tar.gz` CSV import in JavaScript | Native archives retain definitions and source identities; native exports are not Python CLI inputs |
| Coverage | HTTPS, Threat Prevention and many additional object adapters | Native Access, NAT, TP/exception and HTTPS planning/staging; catalog-derived objects and custom TP profile conversions | Expanded implementation; live verification breadth remains a separate measure |
| Throughput | `add-objects-batch` and rule batching paths | Sequential writes plus full definition/readback calls | Likely Python advantage at scale; not benchmarked |

The Bash scripts in this repository are fixture builders, not competing migration engines. They create the 200-object/100-rule source and six destination conflict/reuse objects. They require manual publication and cleanup. Their separate add/remove-by-name package attachment sequence supplied the working R82.10 pattern now used by the app.

## Material remaining gaps

1. **Manual NAT placement relative to automatic NAT.** Upstream explicitly preserves upper/lower placement using `__before_auto_rules` (`importing/import_objects.py`, NAT branch). This gap is now fixed in the native adapter and regression-tested. Both upper and lower placement have now passed the combined native lab readback using disabled manual rules. Enabled NAT and gateway-specific automatic NAT remain untested.
2. **Recovery after lost historical sessions.** New cleanup verifies the current dedicated API session after discard, resolving the repeated false recovery locks observed in the lab. Old records without that evidence, crashes, failed verification and uncertain publish outcomes still require recovery/manual investigation. This is not universally automatic recovery.
3. **Live validation breadth.** Successful synthetic Access Control publication is meaningful, but gateway-specific automatic NAT, enabled NAT object creation, live exception groups, custom TP profiles, inline-layer combinations, different releases, session rollover failure modes, and large inventories need targeted lab cases. There was no packet-flow or gateway-install test.
4. **Payload normalization remains adapter work.** Catalogs validate command shapes, not all nested field constraints. The live Track None and default-layer bugs demonstrated this limitation. Maintain real API response fixtures alongside synthetic cases.
5. **No throughput comparison yet.** Run both tools against equivalent clean destination snapshots, with identical publish boundaries where possible, recording total time, read/write calls, failures and resulting policy equality. Do not compare the app's write-only interval with a script's whole run.

## Recommendation

The app improves operator control and verification for its tested native Access/TP/HTTPS/mixed-NAT workflow. It is not yet a complete replacement for the Python utility. Specialized object workflows, scope/import options, archive interoperability, deployment environments and batching still differ; see the current feature matrix. The app no longer offers a Python execution workflow.

## Code references

- App: `src/workflows/objects.js`, `migration.js`, `discard.js`, `workbench.js`, `journal.js`; `public/app.js`.
- Python: `vendor/ExportImportPolicyPackage/importing/import_objects.py` (batching, warnings, NAT placement, strict failure); `importing/import_package.py` (publication); `exporting/export_objects.py` (NAT and tracking normalization); `utils.py` (scope and strict flags).
