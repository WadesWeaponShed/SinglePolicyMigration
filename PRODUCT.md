# Single Policy Move
<!-- impeccable:product-schema 1 -->
## Platform
web
## Stack
Native Node.js, HTML, CSS and JavaScript inherited from the user's local CP-API-Framework.
## Product Purpose
Move one Check Point policy package and its referenced objects between management domains or independent management endpoints, with an object-level and rulebase preview before changes.
## Users
Check Point management and MDS administrators.
## Capabilities and Constraints
MDS domains, independent management endpoints, and native archive workflows. Block globally assigned policies, unknown global status, object conflicts and unsupported policy features. Scan the destination before staging. Retain the source; migration creates a separate destination package. Stage and publish are distinct actions. Never install policy automatically.
## Brand Commitments
Use CP-API-Framework's design and structure: local reference at /Users/aforester/Documents/GitHub/CP-API-Framework. Preserve its native stack and connection/session boundary.
## Evidence on Hand
CheckPointSW/ExportImportPolicyPackage at 5e53c859adc13ba0ff7b0b3aa8541d240f6a5f44. Native workflows validated in an R82.10/API v2.1 lab; see docs/native-feature-parity.md. Demo data must be labeled synthetic.
