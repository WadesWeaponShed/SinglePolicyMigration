# Native feature comparison — 2026-09-25

Reference: vendored Check Point ExportImportPolicyPackage V6.3, revision `5e53c859adc13ba0ff7b0b3aa8541d240f6a5f44`. This compares the checked-in implementation, not an unexamined latest upstream release. The app executes JavaScript directly; Python and the Check Point Python SDK are not runtime dependencies.

## What is better

The native app combines a reviewed, fingerprinted plan, exact-definition conflict handling, unpublished batched creation, independent destination readback, and verified discard. The reference has batching too; the app's advantage is retaining those safeguards around the whole migration instead of requiring intermediate publication. This is not a claim that every management version or arbitrary object is proven, nor a matched Python speed benchmark.

| Capability | Native implementation and evidence |
| --- | --- |
| Access rules and sections | Ordered and inline layers, action/logging translation, disabled rules, sections, dependency mapping. A 100-rule/10-section workload passed live readback. |
| Manual and automatic NAT | Manual rules retain their position above/below generated rules. New static-NAT object settings passed creation/readback; generated rows are not separately copied. |
| Threat Prevention | Rules, custom profiles, direct exceptions, shared exception groups and profile response-to-request conversions. Custom profile and both exception forms passed live readback. Shared groups are explicitly scoped to imported rules. |
| HTTPS Inspection | Native layers/rules, blades and certificate references. Inbound/outbound policy rows passed live readback. Missing custom certificate material requires separate import; name alone never proves certificate identity. |
| Objects | Catalog-derived writable schemas, recursive references, exact semantics and independent readback. A live run created 200 objects covering hosts, networks, ranges, services, DNS and groups. |
| Gateways and clusters | Native writable settings, interfaces, blades, inactive-field normalization, member name collision checks and suffixes. SIC trust is established separately. Active settings without a writable representation block. |
| External objects | Updatable repository identity and data-center connection prerequisites are preserved and checked; deleted or absent external prerequisites block. Contract-tested; no external repository was available in this lab. |
| Conflicts | Exact definitions rather than subnet/port containment; reviewed reuse, individual/bulk rename and configurable suffix. Existing destination objects remain unchanged. |
| Scope and tagging | Independent Access/TP/HTTPS/NAT selection, optional section omission and import tags. Live suffix/tag/section-omission test passed. API v2.1 ignores profile tags: optional tags exclude profiles with a notice, while loss of existing profile tags blocks. |
| Archive import/export | Native UID-preserving `.cma.gz` and upstream CSV/tar read/write, entirely in JavaScript. Native-written upstream archive passed live re-import, including TP exceptions. Ambiguous names or unrepresentable certificate identity require native format. |
| Connections | One MDS or independently authenticated source/destination endpoints; direct management servers, CMA domains, Smart-1 Cloud URLs, password/API key, per-endpoint TLS and authenticated HTTP/HTTPS CONNECT proxy. Independent CMA endpoint mode passed live connection/migration checks; cloud/standalone transport contracts are tested, not live-certified here. |
| API growth | Common-version negotiation or explicit pin, official catalog refresh, nested field validation and asynchronous command metadata. Catalog growth enables compatible CRUD fields/types; new semantics still require adapters and tests. Catalog candidate counts are not support claims. |
| Scale | Dependency-safe object batches and contiguous eligible rule batches, bounded full-definition reads, bulk host/network/TCP/UDP inventory pages. Nondefault logging flags fall back to individual calls. No intermediate migration publish. |
| Failure handling | Automatic discard on known terminal staging failures, verified zero changes and destination release; durable recovery for unknown asynchronous or publication outcomes. Expired read-only sessions renew without replacing the staging session. Only reads and idempotent keepalive receive transient retries. |

## Live management-plane evidence

All runs used R82.10/API v2.1 on the authorized Donut lab. No policy was installed on gateways. Test migrations below were staged, independently read back and deliberately discarded unless marked published.

| Run | Evidence |
| --- | --- |
| Earlier Access migration | 198 objects created; 100 rules and 10 sections; published. |
| `CMA_LAB_Native_FullCoverage` | 105 rules, five imported layers, 216 reused objects, 10 sections; publication observed, 253 published changes. |
| `CMA_NATIVE_Exception_Options` | Six rules, five layers, two creates/14 reuse; suffix, import tag, omitted sections and direct/shared TP exceptions. |
| `CMA_NATIVE_Export_Roundtrip` | JavaScript-produced upstream CSV/tar uploaded and migrated through the app; exception/order readback passed. |
| `CMA_NATIVE_AutoNAT_Verify` | Eight rules, four creates/14 reuse; new static auto-NAT host plus manual rules above/below generated NAT. |
| `CMA_NATIVE_Profile_Verify` | Custom TP profile including extended protection attributes and overrides; direct/shared exceptions; 19 seconds total. |
| `CMA_NATIVE_Cluster_Verify` | Two-member ClusterXL definition, priorities and gateway settings, one rule/one section; asynchronous creation and native readback passed in 12.532 seconds, then verified discard. |
| `CMA_NATIVE_Inline_Verify` | Ordered parent and inline child, two disabled rules/two sections; action, child reference, parent relationship and order passed native Workbench readback in 8.203 seconds, then verified discard. |
| `CMA_NATIVE_Gateway_Verify` | Live Katia `Standard` policy: two creates/21 reuse, six rules/five layers; gateway settings and management references passed full readback in 16.727 seconds, then verified discard. |
| `CMA_NATIVE_Batch_Verify` | 200 created objects, 16 reuse, 105 rules, five layers and 10 sections; full readback passed. Initial run took 80 seconds including recheck and readback. |

The batch run submitted 190 ordinary objects in four batches (50/50/50/40), ten dependent groups individually, and 100 Access rules in ten batches. That is **24 creation submissions for those 300 entities**, compared with 300 individual adds: 92% fewer creation submissions. It excludes task polling, validation, other policy writes and readback. The logged mutation phase across the full run spanned 20.621 seconds. Python also supports batching; this is not a measured speedup over Python.

Required R82.10 generated IPS/default TP layers remain attached; the IPS layer is verified empty and generated TP rules disabled. This is deliberate semantic handling, not literal equality of all generated row counts.

## Final repeat benchmark

After bulk inventory reads and per-scan definition caching, the same 200-create/16-reuse, 105-rule fixture passed again with identical mutation counts and independent readback. The published destination was unchanged between runs; each run was discarded.

| Native operation | Before signature caching | Final run | Reduction |
| --- | ---: | ---: | ---: |
| Preview | 43.140 s | 16.197 s | 62.5% |
| Stage, fresh scan and full readback | 78.686 s | 43.822 s | 44.3% |
| Combined | 121.826 s | 60.019 s | 50.7% |

These are single lab measurements, not a statistical performance guarantee or a Python timing comparison. The final run used 53 mutation submissions overall, including 24 for 200 objects plus 100 Access rules. Gateway and cluster runs were repeated with inherited profile-value verification enabled and passed. All four final native runs have verified discard records; there are zero unresolved migrations. See [machine-readable results](native-lab-results.json).

The final automated regression suite passes **235 tests**, including failed readback/discard, uncertain asynchronous tasks, API version pins, independent endpoints, real local TLS/proxy transport, exact object matching, archive conversions, and named Threat Prevention exception action readback.

## Combined stress test

`SPM_CHAOS_20260925` passed native staging and independent readback in Katia: 234 new objects, 307 Access rules across ordered and nested inline layers, 30 HTTPS rules, 12 Threat Prevention rules with two custom profiles, 12 direct exceptions, two shared exception groups, 20 manual NAT rules, and ten automatic-NAT objects. The fixture included IPv6 and dual-stack dependencies. This test exposed and led to a fix for named TP exception actions being returned as built-in UIDs during readback.

The operator subsequently reported completing, publishing, and confirming the move to Prepotente. Destination publication and visual confirmation are operator-reported; this run did not establish packet-flow behavior or performance relative to Python.

## Intentional boundaries

The app does not clone source sessions/root credentials, invent placeholder objects, reset SIC, install policy, silently accept changed destination objects, or automatically replay uncertain writes. Custom certificate private keys cannot be recovered from a policy export; matching material must exist in the destination. Version v1.9/v2.2 schemas and proxy/standalone behavior have automated coverage, but live runs here establish v2.1 behavior only. No packet-flow test or matched end-to-end Python benchmark was performed.

Primary implementations: `src/workflows/{migration,objects,adapters,batch,archives,upstream-archive,compatibility,workbench,endpoints}.js`, `src/{check-point-client,proxy-agent,session-manager}.js`, and `public/app.js`. Reference behavior: vendored `utils.py`, `lists_and_dictionaries.py`, `importing/import_objects.py`, `importing/import_package.py`, and `exporting/special_treatment_objects.py`.
