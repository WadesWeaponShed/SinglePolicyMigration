# Source provenance

## API Framework

The user identified `/Users/aforester/Documents/GitHub/CP-API-Framework` as the design and structure reference. Inspected revision: `e7f51558a159af16091332063d42aaea8eddad9d` plus the working-tree files present at build time.

Copied framework files: `src/check-point-client.js`, `src/session-manager.js`, `public/styles.css`, `public/workbench.css`, and `DESIGN.md`. The session manager adds an optional read-only login flag and a generic task polling method. The native app now exposes MDS domain connections and independent management endpoints, including standalone management and Smart-1 Cloud. Existing framework login and generic-explorer pages are replaced by the requested migration workflow.

## ExportImportPolicyPackage

Repository: https://github.com/CheckPointSW/ExportImportPolicyPackage

Inspected revision: `5e53c859adc13ba0ff7b0b3aa8541d240f6a5f44` (CLI identifies itself as V6.3).

The app implements migration in Node.js; it does not run this utility or its SDK. The pinned source under `vendor/ExportImportPolicyPackage` is retained under Apache-2.0 for parity review. An earlier wrapper approach was rejected by the user and retired to `.reference/python-wrapper/`. Its published lab test packages are separate from native validation results.

Relevant reviewed files:

- `exporting/export_package.py`: package/layer traversal and per-component export.
- `exporting/export_access_rulebase.py`: dependency collection and recursive inline-layer traversal.
- `exporting/export_objects.py`: object resolution and normalization.
- `importing/import_package.py`: package/layer attachment and publication.
- `importing/import_objects.py`: name collision handling, reference remapping, strict failure paths and batch publication.
- `utils.py`: CLI flags and global-layer counting.

The separate native workflow adapts the dependency traversal approach but deliberately changes execution semantics: deterministic preflight, explicit definition comparison, no dummy replacements, reviewed renaming, narrowly acknowledged duplicate-IP warnings for explicit copies, no intermediate publishing, and no source deletion. Current feature coverage and live evidence are recorded in [native feature comparison](native-feature-parity.md). It is not certified by Check Point.

Command shapes were also checked against the framework's generated official v2.1 Management API catalog (`https://sc1.checkpoint.com/documents/latest/APIs/index.html`). A lab test against the operator's actual release is still required.

The framework's `src/catalog-manager.js`, `scripts/generate-command-catalog.mjs`, `scripts/update-catalogs.mjs`, and bundled v1.9/v2.1/v2.2 command catalogs are also included. The migration coverage report is specific to this app; catalog refreshes can extend ordinary CRUD adapters for new previews but never change an already reviewed operation’s execution schema. Fresh previews negotiate the highest common advertised API version using the framework capability/catalog mechanism.


## Native extension model

`adapters.js` compiles ordinary named CRUD adapters from the negotiated catalog. `policy-types.js` and `migration.js` implement ordered policy structures, dependency mapping, default-layer handling, exceptions, staging and readback. Catalog refreshes add documented fields to new previews; saved previews retain their schema and API version. `archives.js` and `upstream-archive.js` implement in-process archive parsing and export with no Python dependency.
