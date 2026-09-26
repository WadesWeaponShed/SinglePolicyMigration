# Single Policy Move

**Move one Check Point policy package with a preview of exactly what will change.**

Single Policy Move is a local web application for copying a policy package and its referenced objects between Check Point management domains or independent management endpoints. It discovers dependencies, compares destination objects, resolves supported name conflicts, and stages the result in a dedicated session. Independent readback verifies the staged policy before you publish it.

The migration engine, archive handling and API integration run natively in **Node.js and JavaScript**. The application does not execute Python scripts or require the Check Point Python SDK.

Despite the name, a move **retains the source** and creates a separate destination package. Publishing commits management changes; it does not install policy on gateways.

## Contents

- [Quick start](#quick-start)
- [What it migrates](#what-it-migrates)
- [Connections and prerequisites](#connections-and-prerequisites)
- [Migration workflow](#migration-workflow)
- [Object matching and conflicts](#object-matching-and-conflicts)
- [Migration options](#migration-options)
- [Archives](#archives)
- [API versions and future coverage](#api-versions-and-future-coverage)
- [Verification, failure handling and recovery](#verification-failure-handling-and-recovery)
- [Troubleshooting](#troubleshooting)
- [Security and local state](#security-and-local-state)
- [Testing and measured results](#testing-and-measured-results)
- [Generate a lab policy](#generate-a-lab-policy)
- [Development and architecture](#development-and-architecture)
- [Project origins](#project-origins)

## Quick start

### Requirements

- **Node.js 20 or newer**, with npm.
- A modern browser on the machine running the application.
- HTTPS access from that machine to the relevant Check Point Management API endpoints for live migrations.

The current project uses Node.js built-ins and has no npm runtime dependencies or frontend build step. From the repository directory:

```bash
node --version
npm start
```

Open **[http://127.0.0.1:3000](http://127.0.0.1:3000)**.

Choose **Explore a sample migration** to use synthetic data without credentials or network access to Check Point. The sample includes clean, conflicting and globally assigned policy scenarios; it never changes a management server.

To use a different local port:

```bash
PORT=3010 npm start
```

To run syntax checks and the automated test suite:

```bash
npm run check
```

Stop the server with `Ctrl+C`. Resolve staged migrations before restarting; browser connections and credentials are held in memory, while recovery records persist on disk.

## What it migrates

One selected package and its required dependencies form a migration. This is not a full management-server backup or an all-packages transfer.

| Area | Native behavior |
| --- | --- |
| Access Control | Ordered layers, recursive inline layers, section headers, disabled rules, actions, logging and supported rule settings. |
| Objects and groups | Dependency-based creation, nested groups, exact-definition reuse, conflict resolution and UID remapping. Ordinary named-object adapters derive writable fields from the negotiated API catalog. |
| Manual NAT | Rules and sections, including placement above or below automatically generated rules. |
| Automatic NAT | NAT settings travel with required objects; Check Point generates their rules. Generated rows are not copied individually or used to pull otherwise unneeded objects into a migration. |
| Threat Prevention | Layers, rules, custom profiles, direct exceptions and shared exception groups. Shared groups are scoped to imported rules, with that scope disclosed in preview. |
| HTTPS Inspection | Layers, rules, supported blade settings and certificate references. Custom certificate reuse requires matching public certificate identity. |
| Gateways and clusters | Supported definitions, interfaces, blade settings, cluster members and priorities. Source-management references are mapped to destination management; SIC must be established separately. |
| External objects | Updatable-object repository identity and data-center object identity, subject to verified destination prerequisites. External connections and credentials are not cloned. |
| Archives | Native `.cma.gz` snapshots and upstream-compatible CSV/tar `.tar.gz` import and export, implemented in JavaScript. |

### Boundaries that matter

- Unknown policy features, unmapped attributes, cyclic dependencies and unverified object identities block migration instead of being silently dropped or replaced with placeholders.
- A documented creation command is not proof that every object of that type is migratable. Required inputs, dependencies, normalization and readback must also succeed.
- Private keys and SIC trust cannot be recovered from ordinary policy exports. Import required certificate material and establish destination trust separately.
- Named management/log-server references other than the recognized source management require explicit handling; they are not silently reassigned.
- Destination package installation targets are deliberately empty for administrator configuration. Rule-level installation references are preserved or blocked when unsupported.
- Dynamic layers and unsupported package blades require dedicated handling. The application does not translate arbitrary policy constructs into approximations.

See the [feature-by-feature comparison](docs/native-feature-parity.md) for the implementation, evidence and remaining validation boundaries.

## Connections and prerequisites

### Choose a connection mode

| Mode | Use it for | Inputs |
| --- | --- | --- |
| **Two domains on one MDS** | Source and destination domains on the same Multi-Domain Server. | MDS host/port, password or API key, then domain selection. |
| **Separate management endpoints** | Different MDS servers, independently authenticated domains, standalone management or Smart-1 Cloud endpoints. | Separate source/destination addresses and credentials. Specify an MDS domain name or UID; leave the domain empty for standalone management. Enable the Smart-1 Cloud option for a tenant URL. |

Source sessions request read-only access. Destination changes use a dedicated migration session. Independent endpoints can use different authentication methods and TLS settings.

An optional **HTTP or HTTPS CONNECT proxy** applies to both endpoints. Proxy authentication is supported; its credentials are sent to the proxy rather than forwarded to the management API.

### Management access

The connecting account must be permitted to use the Management API from the application's machine. It needs:

- Read access to source packages, layers, rules and referenced objects.
- Read access to destination inventory and definitions.
- Destination permissions for the objects, policy structures, sessions and publication involved in the selected migration.
- For MDS domains, visibility of domains and global assignments through the relevant management root.

Missing required permissions or incomplete API responses stop the workflow. No credentials are preconfigured in this repository.

### Global policy assignments

Both MDS domains are checked for global policy assignments, and full package details are checked for inherited Global Domain layers. **An assignment blocks migration even if the operator has not installed it.** Global objects and uncertain assignment status also block.

If necessary, resolve the assignment through your normal management procedure and generate a new preview. Single Policy Move does not remove global assignments automatically. These checks run before staging and again before publication; they are not a historical audit of installed gateway policy.

## Migration workflow

### 1. Connect and select a package

Connect the management endpoints. In single-MDS mode, select different source and destination domains and choose **Load source policies**. Select one source package and enter a new destination package name.

Expand **Migration options** to choose components, section handling, an object suffix, an import tag or an API version pin.

### 2. Generate and review the preview

The scan reads source policy and dependencies, enumerates destination names/types, expands relevant destination definitions, and builds a plan. Preview creates no policy objects or rules.

Review the five workspace views:

| View | What to review |
| --- | --- |
| **Domains & policy** | Source, destination, package name, options and API coverage. |
| **Preflight checks** | Compatibility, global assignments, prerequisite checks, blockers and migration notices. |
| **Object changes** | Objects to create/reuse, conflicting names and full source/destination definitions. |
| **Rulebase preview** | Selected layers, sections, order, disabled rules and reference mappings; expandable raw settings provide additional detail. |
| **Review & migrate** | Final counts, scope and destination confirmation. |

Download the JSON plan if you need a review record. Progress appears below **Unfinished migrations**, with elapsed time, current activity and the age of the last successful status response.

### 3. Resolve conflicts

Resolve supported name conflicts individually or use **Rename all conflicts** to apply the `_MIGRATED` suffix to eligible incoming objects. Review the rebuilt plan afterward. Unsupported definitions and ambiguous equivalents still require resolution; the rename action does not override them.

### 4. Stage

Type the exact destination package name and acknowledge the review, then choose **Stage migration**.

Before its first policy write, the application:

1. Requires a clean destination session.
2. Rechecks global assignments, source policy and destination inventory.
3. Confirms that the new scan matches the reviewed plan and API schema.
4. Reserves the destination in the recovery journal.

Plans expire after **15 minutes**. A changed source, destination, engine revision or execution schema requires a fresh preview.

The importer creates dependencies before dependents, builds policy structures, remaps references and preserves rule order. Eligible operations use API batches, but the migration remains unpublished throughout staging.

### 5. Review staged changes and finish

A successful stage means independent destination readback passed. Inspect the unpublished changes in SmartConsole, then choose either:

- **Publish destination changes** to commit the dedicated migration session. Success requires a confirmed successful publish task.
- **Discard staged changes** to remove its unpublished changes. Cleanup is confirmed by reading the dedicated session and verifying zero changes.

Both actions require the destination package name. Source policy remains in place. Configure destination installation targets and perform any policy installation separately.

## Object matching and conflicts

The application compares **exact policy-relevant definitions**, including recursively resolved dependencies. Address containment and port-range overlap are not equivalence: a host is not reused as an all-addresses range, and a single-port service is not reused as a broad high-port range.

| Outcome | Meaning |
| --- | --- |
| **Create** | A supported definition needs a new destination object, including an explicitly requested suffixed copy. |
| **Reuse** | An existing destination object has a verified equivalent definition. Rules and groups use its destination UID. |
| **Conflict** | A name collides with a different definition/type, or multiple equivalent objects make reuse ambiguous. |
| **Unsupported** | A required definition or dependency cannot be represented or verified safely. |

Name collisions are checked case-insensitively. A unique equivalent under a different name can be reused where the object's type allows it. Built-ins, DNS names, repository identities and certificates have additional identity rules.

Comments, colors and tags do not determine traffic equivalence. Reused objects retain destination metadata; newly created objects retain supported source metadata. Full definitions remain visible for review.

Renaming changes the incoming copy and its mapped references. It does not overwrite an existing object. Proposed names are checked against destination objects, other incoming names and reserved package/layer names. Rename choices are revalidated during rescan and before staging. Force-overwrite and arbitrary object substitution are not offered.

## Migration options

| Option | Behavior |
| --- | --- |
| **Policy components** | Select Access Control, Threat Prevention, HTTPS Inspection and manual NAT independently. Component selection also applies to export. |
| **Preserve section headers** | Keep headings, or omit Access/HTTPS/NAT headings while retaining rule order. TP exception-group ownership remains intact. |
| **Rebuild gateways at destination** | Explicitly resolve each referenced gateway in the preview. Select an existing destination gateway without modifying it, or create a minimal gateway or cluster using a new name and an operator-provided destination IPv4/IPv6 address. Source gateway configuration is omitted. New clusters require manual member and cluster-mode configuration. Disabled by default. |
| **Suffix for imported objects** | Request separate copies of eligible user objects. Built-in, DNS-domain, certificate and repository-defined identities retain their required names. |
| **Tag new objects** | Create or match a migration tag and apply it to newly created supported objects. Reused destination objects are not edited. |
| **Migration API version** | Request a shared supported version, such as `v1.9`, instead of automatic negotiation. |

An exact destination match under the requested suffixed name may be reused. Differently named equivalents do not defeat an explicit copy request. Duplicate-IP host copies are disclosed in preview; only their exact reviewed warning can be acknowledged. Unrelated warnings stop staging.

In gateway rebuild mode, open **Resolve** for each gateway or cluster in the objects preview. Mappings retain rule and group references using the selected destination UID. A minimal gateway or cluster needs manual SIC, interfaces, topology, blade, routing, NAT and (where applicable) Smart-1 Cloud onboarding configuration before policy installation. Source IPs, MaaS tunnel addresses and gateway settings are not copied automatically. Readback checks the requested minimal definition and accepts destination-generated defaults; this mode deliberately does not claim source gateway configuration parity. Minimal clusters retain the simple-cluster type but do not copy source members; add members and configure the cluster mode manually. Existing mapped gateways are never configured by the app. Mapping decisions are included in preview drift checks. Gateway rebuild applies to live and archive imports; exports retain complete source definitions and dependencies.

API v2.1 ignores Threat Prevention profile tags. The optional import tag therefore excludes those profiles with a notice; existing source profile tags block when they cannot be preserved.

A NAT-only migration creates the empty Access context required by the destination package. Automatic NAT follows required objects regardless of whether generated rules appeared in the source rulebase.

Named automatic-NAT installation gateways are resolved to one exact source gateway or cluster and remapped with other references. In rebuild mode, resolve those gateway choices before their networks and parent groups can be compared. Ambiguous or missing gateway names remain blocked. Destination readback resolves returned gateway names before verifying NAT settings.

Shared built-in IPS layers are copied into separate destination layers for this policy; sharing with other source packages is not recreated. Copied rules and exceptions are verified. Empty non-writable Threat Prevention permissions and `shared: false` are response defaults; nonempty permissions and unsupported sharing on ordinary threat layers remain blocked. Referenced IPS protections must exist in the destination. Country and other Updatable Objects require an initialized destination repository; use **Update destination repository** in Preflight checks to run `update-updatable-objects-repository-content` in the destination management context, then rescan. The button waits for any returned task, verifies repository access, and expires the old preview. It does not publish the migration or install policy. Preview never initializes external repositories automatically.

## Archives

Export the selected policy, or upload an archive and choose **Preview archive migration**. Archive imports use the same comparison, preflight, staging and readback engine as live-source migrations. They still require an authenticated destination; the current workspace also requires connected source/destination contexts.

| Format | Purpose | Important properties |
| --- | --- | --- |
| **Native `.cma.gz`** | Preserve a detailed snapshot for Single Policy Move. | Retains source UIDs, layer settings, exceptions and NAT placement. Not an input format for the upstream Python CLI. |
| **Upstream CSV/tar `.tar.gz`** | Interchange with ExportImportPolicyPackage-style archives. | Converts references to names and preserves supported nested policy structures. Ambiguous names or unrepresentable certificate identity are rejected; use native format in those cases. |

The application parses archives in process; it does not invoke Python or extract an uploaded archive into a working directory. Native archives retain the existing `cma-policy` format identifier and `.cma.gz` extension for compatibility with archives created before the product rename.

The upload limit is **128 MiB**; native expanded payloads are limited to **256 MiB**. Archives contain network and policy data. Store them accordingly. Neither format is a substitute for a complete management backup or a portable collection of private keys, external-service credentials and SIC trust.

## API versions and future coverage

Automatic negotiation selects the highest compatible version explicitly advertised by the connected contexts. Bundled catalogs cover **v1.9, v2.1 and v2.2**; other advertised versions can load their official documentation on demand.

The chosen version and execution schema are recorded in the preview and remain pinned through staging, publication, task polling and recovery. If support disappears or required documentation cannot be loaded, the operation blocks instead of silently changing versions.

In **Domains & policy → API versions & migration coverage**:

1. Choose a documented version.
2. Select **Check coverage** to inspect catalog commands and implemented migration handling.
3. Select **Update official catalogs** to refresh documentation used by new previews.

You can also update cached catalogs from the repository:

```bash
npm run catalog:update
```

Restart an already running server to load CLI-updated caches. Catalog updates require access to Check Point's official documentation; failed updates preserve the active catalogs.

The extension model separates schema from behavior:

- Ordinary named CRUD adapters derive supported writable fields from the selected catalog.
- Nested request validation checks documented types and values before staging.
- Policy ordering, special references, API response normalization and verification use explicit native handlers.
- New API fields and compatible object contracts can extend coverage without rebuilding a Python wrapper. New semantics still need implementation and tests.

A catalog command count is **not** a count of live-certified object types. The coverage browser's version selector is also distinct from the migration's API pin.

## Verification, failure handling and recovery

### What is verified

Staging reads created objects and layers back from the destination. It checks supported writable definitions, rule fields, logging, section/rule order, inline-parent relationships, layer attachments, exception groups and manual NAT placement. Gateway inherited profile values are checked for changed effective behavior. Required generated defaults are handled explicitly rather than mistaken for imported rows.

For R82.10, required empty IPS/default TP layers remain attached, and generated TP rules are disabled and verified. Generated HTTPS defaults are removed by identity after imported rules exist. Existing shared layers are not modified.

### Failures and uncertain outcomes

| Situation | Behavior |
| --- | --- |
| Preflight or fresh-scan failure | No migration writes; resolve the issue and generate a new preview. |
| Known terminal staging failure | Automatically discard the dedicated session's unpublished changes and verify zero changes. |
| Readback mismatch | Stop and discard instead of presenting the migration as publishable. |
| Discard cannot be verified | Preserve a recovery record and keep the destination reserved. |
| Creation task may still be running | Preserve the task identity; establish its terminal outcome before discard. |
| Publish outcome is unknown | Keep the reservation. Inspect the recorded task/session; do not blindly republish or assume discard can undo publication. |
| Expired read-only source/root session | Reauthenticate that context from in-memory credentials without replacing a destination staging session. |

Read requests and idempotent keepalive receive bounded transient retries. Policy writes are never automatically replayed. A successful batch task is not sufficient on its own: session validations and independent readback must also pass.

### Recover after interruption

1. Reconnect to the same destination management address and port, using the appropriate domain and credentials.
2. Open **Unfinished migrations** and refresh the recovery records.
3. Use **Inspect original session** to determine the recorded session/task outcome.
4. If appropriate, use **Recover session & discard**, confirming the exact package name.
5. Generate a new preview after the reservation has been safely released.

Recovery uses Check Point's session ownership and switching rules. The application does not take over another administrator's active session, resume partial staging, or repeat an uncertain publish. Ambiguous or unavailable historical state may require SmartConsole inspection before the reservation can be released.

Do not delete `.recovery/` to bypass a reservation. It records why a destination may still contain changes or have a running task. Processes sharing this directory honor the same destination reservations; hostname aliases, different journal directories and external administrators are outside that local coordination boundary.

## Troubleshooting

| Message or symptom | Next step |
| --- | --- |
| Global policy assigned | Resolve the assignment/inherited policy through management, then rescan. An uninstalled but assigned global policy still blocks. |
| Source or destination changed after preview | Generate a fresh preview and review its differences. The app has not proceeded with the stale plan. |
| Name conflict | Review both definitions; rename the incoming object individually or use the eligible bulk rename action. |
| Multiple equivalent objects | Resolve the ambiguity. Broad renaming does not select an arbitrary destination identity. |
| Unsupported object or unmapped attribute | Inspect the reported field/type and API coverage. It needs a verified native representation, not a placeholder. |
| Missing certificate or external prerequisite | Import matching certificate material or prepare the required external connection/inventory, then rescan. |
| Staged definition/rule count differs | Readback found a mismatch. Confirm the reported discard outcome and inspect the operation log before retrying. |
| An unfinished migration owns the destination | Use the recovery panel to inspect and resolve the original session. |
| Original session not found | Do not assume the migration was discarded. Inspect the available task/session history and SmartConsole state. |
| Status connection interrupted | Allow polling to recover; do not start the same operation again while its outcome is unknown. |
| Connection or permissions failure | Check the endpoint, API access policy, credentials, domain, TLS/proxy settings and required read/write permissions. |

Keep the operation message and relevant log when investigating a failure. Remove credentials, private material and sensitive policy data before sharing diagnostics.

## Security and local state

This is a **local operator application**, not a hosted multi-user service. The server binds to `127.0.0.1`, validates local hosts/origins, and uses opaque HttpOnly, SameSite=Strict browser session cookies. Check Point credentials and login SIDs stay in server memory rather than browser storage. There is no general-purpose API-command or Gaia execution route.

TLS verification follows the selected connection options. The single-MDS form currently defaults to allowing unverified/self-signed certificates; uncheck that option to verify the server certificate. Independent endpoint TLS options are configured separately.

| Location | Contents and lifecycle |
| --- | --- |
| Server memory | Connections, credentials, API login SIDs, previews and detailed job state. Lost on restart. |
| `.recovery/` | Nonsecret operation/session identifiers, destination, API version, state and known task/package IDs. Written durably before migration writes. Retain across restarts. |
| `.catalog-cache/` | Cached API documentation used to compile versioned schemas. |
| Downloaded plans/archives | Operator-managed policy data and review artifacts. Protect them as network configuration information. |

The recovery journal is not a full audit log. Multi-user authentication, remotely exposed deployment and durable detailed audit storage are outside the current application boundary.

## Testing and measured results

The automated suite uses fixtures, mocked management behavior and local HTTP/TLS tests; it does not log in to a Check Point environment.

```bash
npm test        # Tests
npm run check   # Syntax checks and all tests
```

The recorded native validation on **R82.10 / API v2.1** includes:

- **234 passing automated tests** at the documented validation checkpoint.
- A migration with **200 created objects, 16 reuses, 105 rules, five imported layers and 10 sections**, followed by independent readback and verified discard.
- Separate live validation of inline layers, gateway and two-member cluster definitions, custom TP profiles, direct/shared TP exceptions, mixed NAT and HTTPS rules.
- A native JavaScript CSV/tar export re-imported through the application workflow.
- Confirmed cleanup of final test migrations with zero unresolved recovery records.

The same 200-object native workload was measured before and after per-scan definition caching:

| Operation | Before | After |
| --- | ---: | ---: |
| Preview | 43.140 s | 16.197 s |
| Stage, fresh scan and independent readback | 78.686 s | 43.822 s |
| Combined | 121.826 s | 60.019 s |

The final workload used **53 mutation submissions overall**. Batching reduced creation submissions for its 200 objects and 100 Access rules to **24**, compared with 300 individual additions. Task polling, validation and readback are additional operations.

These are single lab measurements, not performance guarantees or a matched speed comparison against Python. Live evidence establishes the tested v2.1 cases; catalog and automated coverage do not certify every release, deployment or object combination. No gateway policy installation or packet-flow test was part of these validation runs.

- [Feature comparison and detailed evidence](docs/native-feature-parity.md)
- [Machine-readable lab results](docs/native-lab-results.json)
- [Historical operations comparison](docs/operations-comparison.md)

## Generate a lab policy

Two Bash helpers create repeatable test data. They require Bash; execution also requires `mgmt_cli` and `jq`. On Gaia, make its bundled `jq` available in `PATH` if necessary.

### Source: 200 objects and 100 Access rules

[`scripts/build-test-policy.sh`](scripts/build-test-policy.sh) generates a new package with 100 Access rules, 10 section headers, and these 200 objects:

| Type | Count |
| --- | ---: |
| Hosts | 70 |
| Networks | 40 |
| Address ranges | 20 |
| TCP services | 20 |
| UDP services | 20 |
| ICMP services | 10 |
| DNS domains | 10 |
| Network groups | 6 |
| Service groups | 3 |
| Group with exclusion | 1 |

Rules vary actions, logging, enabled state, negation and multiple-value fields. Coverage rules reference every object through nested groups. The final rule is an enabled Drop cleanup rule. This helper generates Access test data; the broader TP/HTTPS/NAT/inline validation uses separate fixtures.

Preview commands without connecting:

```bash
bash scripts/build-test-policy.sh --prefix CMA_LAB --seed 42 > /tmp/cma-lab-preview.sh
```

On the lab MDS in Expert mode, open a **new dedicated source-domain session**. Replace the example domain name:

```bash
umask 077
mgmt_cli login -r true -d "SOURCE_DOMAIN_NAME" --format json > source-session.json
bash scripts/build-test-policy.sh --execute --session source-session.json --prefix CMA_LAB --seed 42
```

The helper stages changes only. Review the session, then publish to make the fixture visible to migration scans:

```bash
mgmt_cli publish -s source-session.json --format json
mgmt_cli logout -s source-session.json --format json
rm source-session.json
```

If generation fails, discard instead of publishing:

```bash
mgmt_cli discard -s source-session.json --format json
mgmt_cli logout -s source-session.json --format json
rm source-session.json
```

The script creates and attaches an explicit Access layer, accommodating packages with zero, one or multiple generated defaults. Detached generated layers are left in the domain. Global assignments are detected before test-object creation; resolve them explicitly before using the generator. No policy is installed.

Use a fresh prefix for subsequent independent fixtures. A seed makes output repeatable for the same Bash version. Existing destination equivalents can reduce the number of newly created objects during migration.

### Destination: a handful of conflicts

[`scripts/build-test-conflicts.sh`](scripts/build-test-conflicts.sh) creates six destination objects using the same prefix:

```bash
# Preview only
bash scripts/build-test-conflicts.sh --prefix CMA_LAB

# Stage in a fresh destination-domain session
umask 077
mgmt_cli login -r true -d "DESTINATION_DOMAIN_NAME" --format json > destination-session.json
bash scripts/build-test-conflicts.sh --prefix CMA_LAB --execute --session destination-session.json
```

Review and publish that session before scanning. If it fails or is unwanted, discard it. Log out and remove the session file when finished, using the same lifecycle shown above.

| Object | Destination difference | Expected outcome |
| --- | --- | --- |
| `CMA_LAB_Host_1` | Address `192.0.2.11` | Name conflict |
| `CMA_LAB_Net_1` | Subnet `198.51.100.0/24` | Name conflict |
| `CMA_LAB_TCP_1` | TCP port `65001` | Name conflict |
| `CMA_LAB_Host_2` | Network object instead of host | Type/name conflict |
| `CMA_LAB_ICMP_0` | Same ICMP type `0` | Reuse |
| `.lab-0.CMA-LAB.invalid` | Same DNS definition | Reuse |

Other existing objects can introduce additional outcomes. The helper adds objects only; it does not overwrite existing definitions, create a policy, publish, or install policy.

## Development and architecture

The project uses native Node.js ES modules and plain HTML/CSS/JavaScript. No bundler or frontend framework is required.

| Command | Purpose |
| --- | --- |
| `npm start` | Start the local server. |
| `npm run dev` | Run Node's watch mode; restarts clear in-memory connections. |
| `npm test` | Run the automated tests. |
| `npm run check` | Check server/frontend syntax and run all tests. |
| `npm run catalog:update` | Refresh official API catalogs. |

```text
public/                      Browser UI and styles
src/server.js                Local workflow routes and static serving
src/check-point-client.js    HTTPS transport, redaction and bounded read retries
src/proxy-agent.js           HTTP/HTTPS CONNECT proxy transport
src/session-manager.js       Authentication, contexts, throttling and task polling
src/catalog-manager.js       Versioned API catalogs
src/workflows/
  workbench.js               Connection and migration lifecycle
  endpoints.js               Independent management endpoint handling
  migration.js               Scan, plan, stage and independent verification
  objects.js                 Normalization, exact comparison and UID translation
  adapters.js                Catalog-derived ordinary object contracts
  policy-types.js            Policy-specific schemas and field handling
  batch.js                   Native batch submission and task validation
  compatibility.js           API negotiation and request validation
  archives.js                Native policy snapshots
  upstream-archive.js        Upstream archive decoding and conversion
  upstream-export.js         JavaScript CSV/tar archive writing
  journal.js                 Durable destination reservations and recovery state
  discard.js                 Verified session cleanup
  engine.js                  Trusted migration-module reloading
  demo.js                    Synthetic demonstration data
scripts/                     Catalog tooling and lab generators
test/                        Unit and integration regression tests
docs/                        Feature comparison, evidence and provenance
vendor/ExportImportPolicyPackage/
                             Pinned behavior reference; not runtime execution
```

Trusted migration modules reload between operations while sessions remain in memory. Their revision is part of preview validity. Changes to the server, Workbench or archive integration may require a restart; finish or recover pending work first.

### Adding migration support

1. Check the relevant command and nested field schemas in the target API catalog.
2. Establish how source identities, dependencies and read-only response fields map to creation inputs.
3. Preserve policy meaning; reject unavailable secrets or prerequisites explicitly.
4. Add request validation and independent destination readback checks.
5. Cover failure/discard behavior and asynchronous task uncertainty in tests.
6. Validate against a representative lab release and record the evidence and limits.

Do not make an unsupported feature appear successful by suppressing mismatches, reusing an arbitrary same-named object, or substituting a dummy object. Keep credentials and private lab artifacts out of the repository.

## Project origins

Single Policy Move was previously named **CMA to CMA**. The broader name reflects support for independent management endpoints and archive workflows while retaining the focus on one policy package at a time. Existing archive formats and recovery records remain compatible; renaming the product does not require renaming your checkout directory.

The native structure and visual system originate from **CP-API-Framework**. Check Point's **ExportImportPolicyPackage** is a pinned behavior reference for traversal, object handling and archive interoperability. The vendored V6.3 source is retained under its Apache-2.0 license; the application does not run it. See [source provenance](docs/upstream.md) and the license included with the vendored project.

This project is not certified by Check Point. Feature coverage, release-specific behavior and live validation claims are documented in this repository rather than inferred from the reference tool's capabilities.

### Refresh destination IPS content

For policies with Threat Prevention layers, **Update destination IPS now** in Preflight checks calls `run-ips-update` on the destination using the preview's API version. It requests the latest package, waits for the returned task, and expires the preview so a fresh scan checks protection availability. An uncertain task is polled again instead of submitting another update. Missing task IDs remain unconfirmed and require inspection in SmartConsole. Active migrations must be resolved first. This action does not publish the migration, install policy, or guarantee that a missing or retired protection will become available.

### Acknowledge manual IPS exceptions

When a referenced IPS protection cannot be verified in the destination, Preflight lists the affected exception occurrences. Review the list, check the acknowledgment, and choose **Accept manual handling & rescan** to continue without those entire exceptions. Other policy rules and references remain subject to normal validation. The full omitted source exceptions and their owning layers/rules are retained in `manualFollowups` in the downloaded plan and a warning remains at final review. Recreate or replace them manually before installing policy. Use **Undo manual handling & rescan** to restore normal checks. Changes to the acknowledged exception definitions invalidate the acknowledgment; the app does not remove protection selectors from an exception or silently widen its scope.
