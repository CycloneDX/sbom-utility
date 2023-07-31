/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package schema

const (
	KEY_ANNOTATIONS = "annotations"
	KEY_COMPONENTS  = "components"
	KEY_LICENSES    = "licenses"
	KEY_METADATA    = "metadata"
	KEY_SERVICES    = "services"
)

// Note: CycloneDX v1.2, 1.3, 1.4, 1.5 schema properties are currently supported
// TODO: make ALL struct pointer references for (future) editing needs

// For convenience, we provide named vars. for testing for zero-length (empty) structs
var EMPTY_CDXLicense = CDXLicense{}

// NOTE: During parsing, any fields not explicitly included in the structure
// will still be added as generic "interface{}" types
// v1.3: added "compositions"
// v1.4: added "vulnerabilities", "signature"
// v1.5: added "annotations", "formulation", "properties"
type CDXBom struct {
	BOMFormat          string                 `json:"bomFormat,omitempty"`
	SpecVersion        string                 `json:"specVersion,omitempty"`
	SerialNumber       string                 `json:"serialNumber,omitempty"`
	Version            int                    `json:"version,omitempty"`
	Metadata           *CDXMetadata           `json:"metadata,omitempty"`
	Components         *[]CDXComponent        `json:"components,omitempty"`
	Services           *[]CDXService          `json:"services,omitempty"`
	ExternalReferences []CDXExternalReference `json:"externalReferences,omitempty"`
	Dependencies       []CDXDependency        `json:"dependencies,omitempty"`
	Compositions       []CDXCompositions      `json:"compositions,omitempty" cdx:"+1.3"`    // v1.3 added
	Vulnerabilities    []CDXVulnerability     `json:"vulnerabilities,omitempty" cdx:"+1.4"` // v1.4 added
	Signature          JSFSignature           `json:"signature,omitempty" cdx:"+1.4"`       // v1.4 added
	Annotations        []CDXAnnotation        `json:"annotations,omitempty" cdx:"+1.5"`     // v1.5 added
	Formulation        []CDXFormula           `json:"formulation,omitempty" cdx:"+1.5"`     // v1.5 added
	Properties         []CDXProperty          `json:"properties,omitempty" cdx:"+1.5"`      // v1.5 added
}

// v1.2: existed
// v1.3: added "licenses", "properties"
// v1.5: added "lifecycles"
type CDXMetadata struct {
	Timestamp    string                     `json:"timestamp,omitempty"`
	Tools        interface{}                `json:"tools,omitempty"` // v1.2: added.v1.5: "tools" is now an interface{}
	Authors      []CDXOrganizationalContact `json:"authors,omitempty"`
	Component    CDXComponent               `json:"component,omitempty"`
	Manufacturer CDXOrganizationalEntity    `json:"manufacturer,omitempty"`
	Supplier     CDXOrganizationalEntity    `json:"supplier,omitempty"`
	Licenses     []CDXLicenseChoice         `json:"licenses,omitempty"`   // v1.3 added
	Properties   []CDXProperty              `json:"properties,omitempty"` // v1.3 added
	Lifecycles   []CDXLifecycle             `json:"lifecycles,omitempty"` // v1.5 added
}

// v1.2: existed
// v1.3: added: "evidence", "properties"
// v1.4: added: "releaseNotes", "signature"
// v1.4: changed: "version" no longer required
// v1.4: deprecated: "modified", "cpe", "swid"
// v1.5: added
// Note: "bom-ref" is a "refType" which is a constrained `string`
// TODO: "mime-type" SHOULD become "media-type" which is more modern/inclusive
// TODO: Remove "service" from "Type" enum. as "service" now exists (deprecate in future versions)
type CDXComponent struct {
	Primary            bool                    `json:"-"`              // Proprietary: do NOT marshal/unmarshal
	Type               string                  `json:"type,omitempty"` // Constraint: enum [see schema]
	MimeType           string                  `json:"mime-type,omitempty"`
	BOMRef             CDXRefType              `json:"bom-ref,omitempty"`
	Supplier           CDXOrganizationalEntity `json:"supplier,omitempty"`
	Author             string                  `json:"author,omitempty"`
	Publisher          string                  `json:"publisher,omitempty"`
	Group              string                  `json:"group,omitempty"`
	Name               string                  `json:"name,omitempty"`
	Version            string                  `json:"version,omitempty"`
	Description        string                  `json:"description,omitempty"`
	Scope              string                  `json:"scope,omitempty"` // Constraint: "enum": ["required","optional","excluded"]
	Hashes             []CDXHash               `json:"hashes,omitempty"`
	Licenses           []CDXLicenseChoice      `json:"licenses,omitempty"`
	Copyright          string                  `json:"copyright,omitempty"`
	Cpe                string                  `json:"cpe,omitempty"`      // See: https://nvd.nist.gov/products/cpe
	Purl               string                  `json:"purl,omitempty"`     // See: https://github.com/package-url/purl-spec
	Swid               CDXSwid                 `json:"swid,omitempty"`     // See: https://www.iso.org/standard/65666.html
	Pedigree           CDXPedigree             `json:"pedigree,omitempty"` // anon. type
	ExternalReferences []CDXExternalReference  `json:"externalReferences,omitempty"`
	Components         []CDXComponent          `json:"components,omitempty"`
	Evidence           CDXComponentEvidence    `json:"evidence,omitempty"`                  // v1.3: added
	Properties         []CDXProperty           `json:"properties,omitempty"`                // v1.3: added
	Modified           bool                    `json:"modified,omitempty" cdx:"deprecated"` // v1.4: deprecated
	ReleaseNotes       []CDXReleaseNotes       `json:"releaseNotes,omitempty"`              // v1.4: added
	Signature          JSFSignature            `json:"signature,omitempty"`                 // v1.4: added
	ModelCard          CDXModelCard            `json:"modelCard,omitempty"`                 // v1.5: added
	Data               []CDXComponentData      `json:"data,omitempty"`                      // v1.5: added
}

// v1.5 added
// The general theme or subject matter of the data being specified.
// TODO: "contents" is plural, but it is not an array
type CDXComponentData struct {
	BOMRef         CDXRefType            `json:"bom-ref,omitempty"`
	Type           string                `json:"type,omitempty"` // Constraint: "enum": ["source-code","configuration","dataset","definition","other"]
	Name           string                `json:"name,omitempty"`
	Contents       CDXContent            `json:"contents,omitempty"`
	Classification CDXDataClassification `json:"classification,omitempty"`
	SensitiveData  []string              `json:"sensitiveData,omitempty"`
	Graphics       CDXGraphicsCollection `json:"graphics,omitempty"`
	Description    string                `json:"description,omitempty"`
	Governance     CDXDataGovernance     `json:"governance,omitempty"`
}

// v1.5 added
type CDXContent struct {
	Attachment CDXAttachment `json:"attachment,omitempty"`
	Url        string        `json:"url,omitempty"`
	Properties []CDXProperty `json:"properties,omitempty"`
}

// v1.5 added
type CDXDataGovernance struct {
	Custodians []CDXDataGovernanceResponsibleParty   `json:"custodians,omitempty"`
	Stewards   [][]CDXDataGovernanceResponsibleParty `json:"stewards,omitempty"`
	Owners     [][]CDXDataGovernanceResponsibleParty `json:"owners,omitempty"`
}

// v1.5 added
// Constraints: "oneOf": ["organization", "contact"]
type CDXDataGovernanceResponsibleParty struct {
	Organization CDXOrganizationalEntity  `json:"organization,omitempty"`
	Contact      CDXOrganizationalContact `json:"contact,omitempty"`
}

// v1.2: existed
// v1.3: added: "properties"
// v1.4: added: "releaseNotes", "signature"
// v1.5: moved "data" object elements into "serviceData" object
// v1.5: added "trustZone"
// -----
// TODO: a service is not all auth or not auth.; that is, we have multiple endpoints
// but only 1 boolean for "authenticated" (open spec. issue)
// TODO: Not sure the intent of having "nested" (hierarchical) services?
// TODO: Should support OpenAPI specification (documents) as canonical descriptors
// TODO: v1.2 "licenses" used to be an anon. type until v1.3 intro. the `LicenseChoice` def.
// validate a v1.2 SBOM wit the anon. type parses properly
type CDXService struct {
	BOMRef             CDXRefType              `json:"bom-ref,omitempty"`
	Provider           CDXOrganizationalEntity `json:"provider,omitempty"`
	Group              string                  `json:"group,omitempty"`
	Name               string                  `json:"name,omitempty"`
	Version            string                  `json:"version,omitempty"`
	Description        string                  `json:"description,omitempty"`
	Endpoints          []string                `json:"endpoints,omitempty"`
	Authenticated      bool                    `json:"authenticated,omitempty"`
	XTrustBoundary     bool                    `json:"x-trust-boundary,omitempty"`
	TrustZone          string                  `json:"trustZone,omitempty"`
	Data               []CDXServiceData        `json:"data,omitempty"`
	Licenses           []CDXLicenseChoice      `json:"licenses,omitempty"`
	ExternalReferences []CDXExternalReference  `json:"externalReferences,omitempty"`
	Services           []CDXService            `json:"services,omitempty"`
	Properties         []CDXProperty           `json:"properties,omitempty"`   // v1.3: added
	ReleaseNotes       []CDXReleaseNotes       `json:"releaseNotes,omitempty"` // v1.4: added
	Signature          JSFSignature            `json:"signature,omitempty"`    // v1.4: added
}

// v1.5: added. aggregated related date from v1.2-v1.4 and added additional fields
// v1.2-v1.4: "flow", "classification" existed
// TODO: "source" is a "oneOf" type (both currently resolve to string), but needs to be its own anonymous type
// TODO: "destination" is a "oneOf" type (both currently resolve to string), but needs to be its own anonymous type
type CDXServiceData struct {
	Flow           string                `json:"externalReferences,omitempty"`
	Classification CDXDataClassification `json:"classification,omitempty"`
	Name           string                `json:"name,omitempty"`        // v1.5: added
	Description    string                `json:"description,omitempty"` // v1.5: added
	Governance     CDXDataGovernance     `json:"governance,omitempty"`  // v1.5: added
	Source         string                `json:"source,omitempty"`      // v1.5: added
	Destination    string                `json:"destination,omitempty"` // v1.5: added
}

// v1.2: existed as an anon. type in the "component" type defn.
// The "Notes" (plural) should likely be multiple strings or text annotations
// TODO: create top-level defn. for "pedigree" anon. type
type CDXPedigree struct {
	Ancestors   []CDXComponent `json:"ancestors,omitempty"`
	Descendants []CDXComponent `json:"descendants,omitempty"`
	Variants    []CDXComponent `json:"variants,omitempty"`
	Commits     []CDXCommit    `json:"commits,omitempty"`
	Patches     []CDXPatch     `json:"patches,omitempty"`
	Notes       string         `json:"notes,omitempty"`
}

// v1.2: existed
// v1.4: deprecated
// See: https://www.iso.org/standard/65666.html
type CDXSwid struct {
	TagId      string        `json:"tagId,omitempty"`
	Name       string        `json:"name,omitempty"`
	Version    string        `json:"version,omitempty"`
	TagVersion int           `json:"tagVersion,omitempty"`
	Patch      bool          `json:"patch,omitempty"`
	Text       CDXAttachment `json:"attachment,omitempty"`
	Url        string        `json:"url,omitempty"`
}

// v1.2: was an anon. type in schema
// v1.3: created explicit schema object type
// Note: "oneOf": ["license", "expression"] is required
type CDXLicenseChoice struct {
	License CDXLicense `json:"license,omitempty"`
	//Expression string     `json:"expression,omitempty"`
	CDXLicenseExpression
}

// v1.5: added
type CDXLicenseExpression struct {
	Expression string     `json:"expression,omitempty"`
	BomRef     CDXRefType `json:"bom-ref,omitempty"`
}

// v1.2: was an anon. type
// v1.3: created
// Note: "id" SHOULD be an SPDX license ID
// Note: "oneOf": ["id", "name"] is required
type CDXLicense struct {
	Id         string        `json:"id,omitempty"`
	Name       string        `json:"name,omitempty"`
	Text       CDXAttachment `json:"text,omitempty"`
	Url        string        `json:"url,omitempty"`
	BomRef     CDXRefType    `json:"bom-ref,omitempty"`    // v1.5: added
	Licensing  CDXLicensing  `json:"licensing,omitempty"`  // v1.5: added
	Properties []CDXProperty `json:"properties,omitempty"` // v1.5: added
}

// v1.5: added
type CDXLicensing struct {
	AltIds        []string             `json:"altIds,omitempty"`
	Licensor      CDXLicenseLegalParty `json:"licensor,omitempty"`
	Licensee      CDXLicenseLegalParty `json:"licensee,omitempty"`
	Purchaser     CDXLicenseLegalParty `json:"purchaser,omitempty"`
	PurchaseOrder string               `json:"purchaseOrder,omitempty"`
	LicenseTypes  []string             `json:"licenseTypes,omitempty"` // Constraint: enum[see schema]
	LastRenewal   string               `json:"lastRenewal,omitempty"`
	Expiration    string               `json:"expiration,omitempty"`
}

// v1.2: existed
// TODO: GitHub PRs MAY have more than 1 commit (committer); CDX needs to account for this
type CDXCommit struct {
	Uid       string                `json:"uid,omitempty"`
	Url       string                `json:"url,omitempty"`
	Message   string                `json:"message,omitempty"`
	Author    CDXIdentifiableAction `json:"author,omitempty"`
	Committer CDXIdentifiableAction `json:"committer,omitempty"`
}

// v1.2: existed
type CDXPatch struct {
	Type     string     `json:"type,omitempty"`
	Diff     CDXDiff    `json:"diff,omitempty"`
	Resolves []CDXIssue `json:"resolves,omitempty"`
}

// v1.2: existed
// v1.3 "url" type changed from `string` (with constraints) to an "iri-reference"
type CDXDiff struct {
	Text CDXAttachment `json:"text,omitempty"`
	Url  string        `json:"url,omitempty"` // v1.3: type changed to "iri-reference"
}

// v1.2: existed
// Note: v1.2 Bug: there appears to be a bug in the 1.2 spec. where the type for
// "references" is declared an array of "no type" (it likely should be `string`)
// Not sure how a parser will treat this... perhaps as an `interface{}`?
// v1.3: fixed to be []string
type CDXIssue struct {
	Type        string    `json:"type,omitempty"`
	Id          string    `json:"id,omitempty"`
	Name        string    `json:"name,omitempty"`
	Description string    `json:"description,omitempty"`
	Source      CDXSource `json:"source,omitempty"`
	References  []string  `json:"references,omitempty"` // v1.3: added missing `string` type
}

// v1.2: existed as anon. type
// Note: this is an anonymous type defined within "issue" defn. (i.e., "CDXIssue")
type CDXSource struct {
	Name string `json:"name,omitempty"`
	Url  string `json:"url,omitempty"`
}

// v1.2: existed
// TODO: We should suggest this be "deprecated" and instead add "timestamp" and
// other fields to OrganizationalContact (or similar)
// TODO: should have "signage" information (e.g., evidence, public key)
type CDXIdentifiableAction struct {
	Timestamp string `json:"timestamp,omitempty"`
	Name      string `json:"name,omitempty"`
	Email     string `json:"email,omitempty"`
}

// v1.2: existed
// v1.3: added "hashes"
// v1.4: `Type` field: added value "release-notes" to enum.
type CDXExternalReference struct {
	Url     string    `json:"url,omitempty"`
	Comment string    `json:"comment,omitempty"`
	Type    string    `json:"type,omitempty"`
	Hashes  []CDXHash `json:"hashes,omitempty"` // v1.3: added
}

// v1.2: existed
// v1.4: "ref" and "dependsOn" became type "refType" which is a constrained `string`
// v1.5: "ref": is now a constrained "string" of type "#/definitions/refLinkType"
// v1.5: "dependsOn": is now a constrained "string" of type "#/definitions/refLinkType"
type CDXDependency struct {
	Ref       CDXRefLinkType   `json:"ref,omitempty"`
	DependsOn []CDXRefLinkType `json:"dependsOn,omitempty"`
}

// v1.2: existed
// Note: "flow" is of type "dataFlow" which is a constrained `string` type
// v1.5: removed.  No longer an object; no it is a "string" ( "flow" moved out as "string" into "serviceData" object)
// type CDXDataClassification struct {
// 	Flow           string `json:"flow,omitempty"`
// 	Classification string `json:"classification,omitempty"`
// }

// v1.5 added. Replaced former "object" type in favor of "string"
// Data classification tags data according to its type, sensitivity, and value if altered,
// stolen, or destroyed.
type CDXDataClassification string // Constraint: "enum": ["inbound", "outbound", "bi-directional", "unknown"]

// v1.3: created "copyright" defn.
type CDXCopyright struct {
	Text string `json:"text,omitempty"`
}

// v1.3: created "componentEvidence" defn.
type CDXComponentEvidence struct {
	Licenses  []CDXLicense   `json:"licenses,omitempty"`
	Copyright []CDXCopyright `json:"copyright,omitempty"`
}

// v1.3: created "compositions" defn.
// v1.4: added "signature"
// v1.5: added "bom-ref", "vulnerabilities"
// Note: "aggregate" is type `aggregateType` which is a constrained string
// TODO: Should not be plural; open issue against v2.0 schema
type CDXCompositions struct {
	Aggregate       string             `json:"aggregate,omitempty"`
	Assemblies      []string           `json:"assemblies,omitempty"`
	Dependencies    []string           `json:"dependencies,omitempty"`
	Signature       JSFSignature       `json:"signature,omitempty"`       // v1.4: added
	Vulnerabilities []CDXVulnerability `json:"vulnerabilities,omitempty"` // v1.5: added
	BOMRef          CDXRefType         `json:"bom-ref,omitempty"`         // v1.5: added
}

// v1.4: created "releaseNotes" defn.
// TODO: should be singular "releaseNote"
type CDXReleaseNotes struct {
	Type          string        `json:"type,omitempty"`
	Title         string        `json:"title,omitempty"`
	FeaturedImage string        `json:"featuredImage,omitempty"`
	SocialImage   string        `json:"socialImage,omitempty"`
	Description   string        `json:"description,omitempty"`
	Timestamp     string        `json:"timestamp,omitempty"`
	Aliases       []string      `json:"aliases,omitempty"`
	Tags          []string      `json:"tags,omitempty"`
	Resolves      []CDXIssue    `json:"resolves,omitempty"`
	Notes         []CDXNote     `json:"notes,omitempty"`
	Properties    []CDXProperty `json:"properties,omitempty"`
}

type CDXLifecycle struct {
	//  v1.5: "enum": [ "design", "pre-build", "build", "post-build", "operations", "discovery", "decommission"]
	Phase              string `json:"phase,omitempty"`
	CDXNameDescription        // name, description
}
