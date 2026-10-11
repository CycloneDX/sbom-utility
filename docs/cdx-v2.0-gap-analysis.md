# CycloneDX v2.0 — Go Struct Gap Analysis (P0–P4)

**Branch:** `cdx-2`  
**Schema:** `resources/schema/cyclonedx/2.0/cyclonedx-2.0-bundled.schema.json`  
**Status:** Pre-release / early development

---

## Already Done

| Item | File | Status |
|------|------|--------|
| Schema file | `resources/schema/cyclonedx/2.0/cyclonedx-2.0-bundled.schema.json` | ✅ present |
| config.json v2.0 entry | `resources/config/config.json` | ✅ present (`version=2.0`, `variant=development`, `specFormat` key group) |
| `PROPKEY_ID_CYCLONEDX_V2` constant | `schema/constants.go` | ✅ present (`"specFormat"`) |

---

## P0 — `CDXBom` top-level breaking changes

**File:** `schema/cyclonedx.go`

| Field | v1.x | v2.0 | Action |
|-------|------|------|--------|
| `BOMFormat` | `json:"bomFormat"` | `json:"specFormat"` | **CHANGE** — key renamed; `PROPKEY_ID_CYCLONEDX_V2` constant already set; BOM struct needs a parallel field or unmarshal logic must handle both |
| `Signature` | `*JSFSignature` (single, JSF 0.82) | `signatures` (array, JSS/ITU-T X.590) | **CHANGE** — add `Signatures *[]JSFSignature`; keep old `Signature` with `cdx:"-2.0"` for backward compat |
| `Perspectives` | — | new top-level array | **ADD** — `Perspectives *[]CDXPerspective` (new type, see P4) |

> Root cause: v2.0 renames the format discriminator key (`bomFormat` → `specFormat`) and shifts from a single JSF 0.82 signature object to an array of JSS/X.590 signatures.

---

## P1 — `CDXComponent` mass field removal + new identity model

**File:** `schema/cyclonedx.go`

v2.0 removes flat identifier fields and replaces them with a structured identity model (`parties` + `identifiers`).

### Fields removed in v2.0

| Field | Last version | Action |
|-------|-------------|--------|
| `Purl` | v1.x | **REMOVE** (v2.0); annotate `cdx:"-2.0"` |
| `Cpe` | v1.x | **REMOVE** (v2.0); annotate `cdx:"-2.0"` |
| `Swid` | v1.x | **REMOVE** (v2.0); annotate `cdx:"-2.0"` |
| `OmniborId` | added v1.6 | **REMOVE** (v2.0); annotate `cdx:"-2.0"` |
| `Swhid` | added v1.6 | **REMOVE** (v2.0); annotate `cdx:"-2.0"` |
| `Author` | deprecated v1.6 | **REMOVE** (v2.0); annotate `cdx:"-2.0"` |
| `Modified` | deprecated v1.4 | **REMOVE** (v2.0); annotate `cdx:"-2.0"` |
| `Publisher` | v1.x | **REMOVE** (v2.0); annotate `cdx:"-2.0"` |
| `Supplier` | v1.x | **REMOVE** (v2.0); annotate `cdx:"-2.0"` |
| `Manufacturer` | added v1.6 | **REMOVE** (v2.0); annotate `cdx:"-2.0"` |
| `Signature` | added v1.4 | **CHANGE** → `Signatures` array |

### Fields added in v2.0

| Field | Type | Notes |
|-------|------|-------|
| `Parties` | `*[]CDXParty` | New structured identity party model (see P4) |
| `Identifiers` | `*[]CDXComponentIdentifier` | Structured identity claims replacing flat purl/cpe/swid |
| `Signatures` | `*[]JSFSignature` | Array replaces single `Signature` |

> **Strategy:** Because `CDXComponent` is shared across v1.2–v2.0, removed fields should be kept with `omitempty` and annotated `cdx:"-2.0"`; new fields annotated `cdx:"+2.0"`.

---

## P2 — `CDXMetadata` — `distributionConstraints` not wired up

**File:** `schema/cyclonedx.go`

> ✅ `CDXDistributionConstraints` type is already defined in `schema/cyclonedx_patents.go` — it just needs to be added as a field on `CDXMetadata`.

| Field | v1.x | v2.0 | Action |
|-------|------|------|--------|
| `DistributionConstraints` | — | `distributionConstraints` object (contains `tlp`) | **ADD** `DistributionConstraints *CDXDistributionConstraints \`json:"distributionConstraints,omitempty" cdx:"+2.0"\`` |

The TLP enum values (`CLEAR`, `GREEN`, `AMBER`, `AMBER_AND_STRICT`, `RED`) are already modelled by `CDXTlpClassification` in `cyclonedx_patents.go` — no new types needed.

---

## P3 — Crypto struct field changes (v1.7 → v2.0)

**File:** `schema/cyclonedx_crypto.go`

### `CDXAlgorithmProperties`

| Field | v1.7 | v2.0 | Action |
|-------|------|------|--------|
| `Curve` | deprecated v1.7 | removed | **REMOVE** (v2.0); annotate `cdx:"-2.0"` |
| `ImplementationPlatform` | `interface{}` (string or `[]string` workaround) | `[]string` only | **CHANGE** — can now be `*[]string`; `interface{}` workaround was for this exact transition. Keep `interface{}` or branch on specVersion. |
| `SecProperties` | — | `[]string` | **ADD** `SecProperties *[]string \`json:"secProperties,omitempty" cdx:"+2.0"\`` |

### `CDXCertificateProperties`

| Field | v1.7 | v2.0 | Action |
|-------|------|------|--------|
| `SignatureAlgorithmRef` | deprecated v1.7 | removed | **REMOVE** (v2.0); annotate `cdx:"-2.0"` |
| `SubjectPublicKeyRef` | deprecated v1.7 | removed | **REMOVE** (v2.0); annotate `cdx:"-2.0"` |
| `CertificateState` | `*CDXCertificateState` (single object) | `[]CDXCertificateState` (array) | **CHANGE** → `*[]CDXCertificateState` |

### `CDXRelatedCryptoMaterialProperties`

| Field | v1.7 | v2.0 | Action |
|-------|------|------|--------|
| `AlgorithmRef` | added v1.6 | removed | **REMOVE** (v2.0); annotate `cdx:"-2.0"` |
| `KeyUsage` | — | `[]string` | **ADD** `KeyUsage *[]string \`json:"keyUsage,omitempty" cdx:"+2.0"\`` |

### `CDXProtocolProperties`

| Field | v1.7 | v2.0 | Action |
|-------|------|------|--------|
| `CryptoRefArray` | deprecated v1.7 | removed | **REMOVE** (v2.0); annotate `cdx:"-2.0"` |

---

## P4 — New types + signatures-as-arrays throughout

### Signatures propagation

Old `Signature` fields must be retained with `cdx:"-2.0"` so v1.x documents continue to unmarshal correctly.

| Struct | File | Current | v2.0 addition |
|--------|------|---------|----------------|
| `CDXBom` | `cyclonedx.go` | `Signature *JSFSignature` | Add `Signatures *[]JSFSignature \`cdx:"+2.0"\`` |
| `CDXComponent` | `cyclonedx.go` | `Signature *JSFSignature` | Add `Signatures *[]JSFSignature \`cdx:"+2.0"\`` |
| `CDXService` | `cyclonedx.go` | `Signature *JSFSignature` | Add `Signatures *[]JSFSignature \`cdx:"+2.0"\`` |
| `CDXDeclaration` | `cyclonedx_declarations.go` | `Signature *JSFSignature` | Add `Signatures *[]JSFSignature \`cdx:"+2.0"\`` |

### New file: `schema/cyclonedx_party.go`

v2.0 introduces a rich party module replacing flat `supplier`/`manufacturer` on `CDXComponent`.

| New Go type | Schema definition | Key fields |
|-------------|-------------------|------------|
| `CDXParty` | `cyclonedx-party-2.0 / party` | `BOMRef`, `Roles`, `Organization`, `Person`, `System`, `Persona`, `Relations`, `Tags`, `Properties`, `ExternalReferences` |
| `CDXPartyOrganization` | `organization` | `Name`, `LegalName`, `Description`, `Jurisdiction`, `Identifiers`, `FormerNames`, `Aliases`, `Url`, `Addresses` |
| `CDXPartyPerson` | `person` | `Name`, `SortName`, `HonorificPrefix`, `HonorificSuffix`, `JobTitle`, `Email`, `Phone`, `Url`, `Address`, `Affiliation` |
| `CDXPartySystem` | `system` | `Kind`, `Ref`, `Identifiers`, `Permissions` |
| `CDXPartyPersona` | `persona` | (mirrors person with contextual attributes) |
| `CDXPartyRole` | `role` | Pre-defined or custom role string |
| `CDXPartyRelation` | `partyRelations` | Typed relationships between parties |
| `CDXComponentIdentifier` | `identifier` | `BOMRef`, `Party`, `Identities` (replaces flat purl/cpe/swid) |

### New type: `CDXPerspective`

Added to `schema/cyclonedx.go` or a new `schema/cyclonedx_perspectives.go`.

| Field | Type |
|-------|------|
| `BOMRef` | `*CDXRefType` |
| `Name` | `string` |
| `Description` | `string` |
| `Domains` | `*[]interface{}` (oneOf: pre-defined enum string or custom object) |
| `Mappings` | `*[]CDXPerspectiveMapping` |
| `ExternalReferences` | `*[]CDXExternalReference` |
| `Properties` | `*[]CDXProperty` |

`CDXPerspectiveMapping` fields: `Expression`, `NativeName`, `NativeDescription`, `Relevance`, `Weight`, `Rationale`.

---

## Work Items by File

| File | Priority | Summary |
|------|----------|---------|
| `schema/cyclonedx.go` | P0, P1, P2 | `CDXBom`: `specFormat` field, `Signatures`, `Perspectives`; `CDXComponent`: remove 10 dropped fields, add `Parties`/`Identifiers`/`Signatures`; `CDXMetadata`: add `DistributionConstraints`; `CDXService`: add `Signatures` |
| `schema/cyclonedx_crypto.go` | P3 | Add `SecProperties`; mark `Curve` deprecated; `CertificateState` → array; remove deprecated refs/`AlgorithmRef`/`CryptoRefArray`; add `KeyUsage` |
| `schema/cyclonedx_declarations.go` | P4 | `CDXDeclaration`: add `Signatures *[]JSFSignature` |
| `schema/cyclonedx_party.go` *(new)* | P4 | `CDXParty`, `CDXPartyOrganization`, `CDXPartyPerson`, `CDXPartySystem`, `CDXPartyPersona`, `CDXPartyRole`, `CDXPartyRelation`, `CDXComponentIdentifier` |
| `schema/cyclonedx_perspectives.go` *(new)* | P4 | `CDXPerspective`, `CDXPerspectiveMapping` |
