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
	KEY_METADATA   = "metadata"
	KEY_COMPONENTS = "components"
	KEY_LICENSES   = "licenses"
)

// Note: CycloneDX v1.2, 1.3, 1.4 schema properties are currently supported

// For convenience, we provide named vars. for testing for zero-length (empty) structs
var EMPTY_CDXLicense = CDXLicense{}

// NOTE: During parsing, any fields not explicitly included in the structure
// will still be added as generic "interface{}" types
// v1.3 added "compositions"
// v1.4 added "vulnerabilities", "signature"
// v1.5 added "annotations", "formulation", "properties"
type CDXBom struct {
	BomFormat          string                 `json:"bomFormat,omitempty"`
	SpecVersion        string                 `json:"specVersion,omitempty"`
	SerialNumber       string                 `json:"serialNumber,omitempty"`
	Version            int                    `json:"version,omitempty"`
	Metadata           *CDXMetadata           `json:"metadata,omitempty"`
	Components         []CDXComponent         `json:"components,omitempty"`
	Services           []CDXService           `json:"services,omitempty"`
	Dependencies       []CDXDependency        `json:"dependencies,omitempty"`
	ExternalReferences []CDXExternalReference `json:"externalReferences,omitempty"`
	Compositions       []CDXCompositions      `json:"compositions,omitempty" cdx:"1.3"`     // v1.3 added
	Vulnerabilities    []CDXVulnerability     `json:"vulnerabilities,omitempty" cdx:"v1.4"` // v1.4 added
	Annotations        []CDXAnnotation        `json:"annotations,omitempty" cdx:"1.5"`      // v1.5 added
	Formulation        []CDXFormula           `json:"formulation,omitempty" cdx:"1.5"`      // v1.5 added
	Properties         []CDXProperty          `json:"properties,omitempty" cdx:"1.5"`       // v1.5 added
	// TODO: Issue #27: Signature CDXSignature `json:"signature,omitempty" cdx:"1.4"` // v1.4 added
}

// v1.2: existed
// v1.3: added "licenses", "properties"
// v1.5: added "lifecycles"
type CDXMetadata struct {
	// Hashes       []CDXHash                  `json:"hashes,omitempty"` // TBD: verify this was never part of spec. in v1.2 (and removed)
	Timestamp    string                     `json:"timestamp,omitempty"`
	Tools        []CDXTool                  `json:"tools,omitempty"`
	Authors      []CDXOrganizationalContact `json:"authors,omitempty"`
	Component    CDXComponent               `json:"component,omitempty"`
	Manufacturer CDXOrganizationalEntity    `json:"manufacturer,omitempty"`
	Supplier     CDXOrganizationalEntity    `json:"supplier,omitempty"`
	Licenses     []CDXLicenseChoice         `json:"licenses,omitempty"`   // v1.3 added
	Properties   []CDXProperty              `json:"properties,omitempty"` // v1.3 added
	Lifecycles   []CDXLifecycle             `json:"lifecycles,omitempty"` // v1.5 added
}

// v1.4 added
type CDXRefType string // v1.5 added "minLength": 1

// v1.5 added Stringer interface
func (ref CDXRefType) String() string {
	return string(ref)
}

// v1.5 added
type CDXRefLinkType CDXRefType // "allOf": [{"$ref": "#/definitions/refType"}]

// v1.5 added Stringer interface
func (ref CDXRefLinkType) String() string {
	return string(ref)
}

// v1.5 added
type CDXBomLinkDocumentType string // "format": "iri-reference", "pattern": "^urn:cdx: ... "

// v1.5 added Stringer interface
func (link CDXBomLinkDocumentType) String() string {
	return string(link)
}

// v1.5 added
type CDXBomLinkElementType string // "format": "iri-reference", "pattern": "^urn:cdx: ... "

// v1.5 added Stringer interface
func (link CDXBomLinkElementType) String() string {
	return string(link)
}

// v1.5 added
// TODO see what happens if we use a struct with the 2 possible types
type CDXBomLink string //  "anyOf": ["#/definitions/bomLinkDocumentType", "#/definitions/bomLinkElementType"]

func (link CDXBomLink) String() string {
	return string(link)
}

// v1.2: existed
// v1.3: added: "evidence", "properties"
// v1.4: added: "releaseNotes", "signature"
// v1.4: changed: "version" no longer required
// v1.4: deprecated: "modified", "cpe", "swid"
// Note: "bom-ref" is a "refType" which is a constrained `string`
// TODO: "mime-type" SHOULD become "media-type" which is more modern/inclusive
// TODO: Remove "service" from "Type" enum. as "service" now exists (deprecate in future versions)
type CDXComponent struct {
	Primary            bool                    `json:"-"` // Proprietary: do NOT marshal/unmarshal
	Purl               string                  `json:"purl,omitempty"`
	BomRef             CDXRefType              `json:"bom-ref,omitempty"`
	Type               string                  `json:"type,omitempty"`
	MimeType           string                  `json:"mime-type,omitempty"`
	Name               string                  `json:"name,omitempty"`
	Version            string                  `json:"version,omitempty"`
	Description        string                  `json:"description,omitempty"`
	Copyright          string                  `json:"copyright,omitempty"`
	Publisher          string                  `json:"publisher,omitempty"`
	Group              string                  `json:"group,omitempty"`
	Scope              string                  `json:"scope,omitempty"`
	Manufacturer       CDXOrganizationalEntity `json:"manufacturer,omitempty"`
	Supplier           CDXOrganizationalEntity `json:"supplier,omitempty"`
	Licenses           []CDXLicenseChoice      `json:"licenses,omitempty"`
	Hashes             []CDXHash               `json:"hashes,omitempty"`
	Author             string                  `json:"author,omitempty"`
	ExternalReferences []CDXExternalReference  `json:"externalReferences,omitempty"`
	Components         []CDXComponent          `json:"components,omitempty"`
	Pedigree           CDXPedigree             `json:"pedigree,omitempty"`     // anon. type
	Evidence           CDXComponentEvidence    `json:"evidence,omitempty"`     // v1.3: added
	Properties         []CDXProperty           `json:"properties,omitempty"`   // v1.3: added
	Modified           bool                    `json:"modified,omitempty"`     // v1.4: deprecated
	Cpe                string                  `json:"cpe,omitempty"`          // v1.4: deprecated
	Swid               CDXSwid                 `json:"swid,omitempty"`         // v1.4: deprecated
	ReleaseNotes       []CDXReleaseNotes       `json:"releaseNotes,omitempty"` // v1.4: added
	// TODO: Signature []CDXSignature `json:"signature,omitempty"` // v1.4: added
}

// v1.2: existed
// v1.3: added: "properties"
// v1.4: added: "releaseNotes", "signature"
// -----
// TODO: a service is not all auth or not auth.; that is, we have multiple endpoints
// but only 1 boolean for "authenticated" (open spec. issue)
// TODO: Not sure the intent of having "nested" (hierarchical) services?
// TODO: Should support OpenAPI specification (documents) as canonical descriptors
// TODO: v1.2 "licenses" used to be an anon. type until v1.3 intro. the `LicenseChoice` def.
// validate a v1.2 SBOM wit the anon. type parses properly
type CDXService struct {
	BomRef             CDXRefType              `json:"bom-ref,omitempty"`
	Provider           CDXOrganizationalEntity `json:"provider,omitempty"`
	Group              string                  `json:"group,omitempty"`
	Name               string                  `json:"name,omitempty"`
	Version            string                  `json:"version,omitempty"`
	Description        string                  `json:"description,omitempty"`
	Endpoints          []string                `json:"endpoints,omitempty"`
	Authenticated      bool                    `json:"authenticated,omitempty"`
	XTrustBoundary     bool                    `json:"x-trust-boundary,omitempty"`
	Data               []CDXDataClassification `json:"data,omitempty"`
	Licenses           []CDXLicenseChoice      `json:"licenses,omitempty"`
	ExternalReferences []CDXExternalReference  `json:"externalReferences,omitempty"`
	Services           []CDXService            `json:"services,omitempty"`
	Properties         []CDXProperty           `json:"properties,omitempty"`   // v1.3: added
	ReleaseNotes       []CDXReleaseNotes       `json:"releaseNotes,omitempty"` // v1.4: added
	Signature          JSFSignature            `json:"signature,omitempty"`    // v1.4: added
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
// v1.4: added "externalReferences"
type CDXTool struct {
	Vendor             string                 `json:"vendor,omitempty"`
	Name               string                 `json:"name,omitempty"`
	Version            string                 `json:"version,omitempty"`
	Hashes             []CDXHash              `json:"hashes,omitempty"`
	ExternalReferences []CDXExternalReference `json:"externalReferences,omitempty"` // v1.4: added
}

// v1.2: existed
// v1.5: added "bom-ref"
type CDXOrganizationalEntity struct {
	BomRef  CDXRefType                 `json:"bom-ref,omitempty"` // v1.5 added
	Name    string                     `json:"name,omitempty"`
	Url     []string                   `json:"url,omitempty"`
	Contact []CDXOrganizationalContact `json:"contact,omitempty"`
}

// v1.2: existed
// v1.5: added "bom-ref"
type CDXOrganizationalContact struct {
	BomRef CDXRefType `json:"bom-ref,omitempty"` // v1.5 added
	Name   string     `json:"name,omitempty"`
	Email  string     `json:"email,omitempty"`
	Phone  string     `json:"phone,omitempty"`
}

// v1.2: existed
// v1.4: deprecated
type CDXSwid struct {
	TagId      string        `json:"tagId,omitempty"`
	Name       string        `json:"name,omitempty"`
	Version    string        `json:"version,omitempty"`
	TagVersion int           `json:"tagVersion,omitempty"`
	Patch      bool          `json:"patch,omitempty"`
	Text       CDXAttachment `json:"attachment,omitempty"`
	Url        string        `json:"url,omitempty"`
}

// v1.2: existed
type CDXAttachment struct {
	ContentType string `json:"contentType,omitempty"`
	Encoding    string `json:"encoding,omitempty"`
	Content     string `json:"content,omitempty"`
}

// v1.2: existed
// Note: "alg" is of type "hash-alg" which is a constrained `string` type
// Note: "content" is of type "hash-content" which is a constrained `string` type
type CDXHash struct {
	Alg     string `json:"alg,omitempty"`
	Content string `json:"content,omitempty"`
}

// v1.2: was an anon. type
// v1.3: created
// Note: "oneOf": ["license", "expression"] is required
type CDXLicenseChoice struct {
	License    CDXLicense `json:"license,omitempty"`
	Expression string     `json:"expression,omitempty"`
}

// v1.2: was an anon. type
// v1.3: created
// Note: "oneOf": ["id", "name"] is required
type CDXLicense struct {
	Id   string        `json:"id,omitempty"`
	Name string        `json:"name,omitempty"`
	Text CDXAttachment `json:"text,omitempty"`
	Url  string        `json:"url,omitempty"`
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
type CDXDependency struct {
	Ref       string   `json:"ref,omitempty"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// v1.2: existed
// Note: "flow" is of type "dataFlow" which is a constrained `string` type
type CDXDataClassification struct {
	Flow           string `json:"flow,omitempty"`
	Classification string `json:"classification,omitempty"`
}

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
// Note: "aggregate" is type `aggregateType` which is a constrained string
// TODO: Should not be plural; open issue against v2.0 schema
type CDXCompositions struct {
	Aggregate    string       `json:"aggregate,omitempty"`
	Assemblies   []string     `json:"assemblies,omitempty"`
	Dependencies []string     `json:"dependencies,omitempty"`
	Signature    JSFSignature `json:"signature,omitempty"` // v1.4: added
}

// v1.3: created "property" defn.
type CDXProperty struct {
	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`
}

// v1.4: created "note" defn.
// Note: "locale" is of type "localeType" which is a constrained `string`
type CDXNote struct {
	Locale string        `json:"locale,omitempty"`
	Text   CDXAttachment `json:"attachment,omitempty"`
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

// v1.4: created "releaseNotes" defn.
// Note: "url" is of type "iri-reference"
type CDXAdvisory struct {
	Title string `json:"title,omitempty"`
	Url   string `json:"url,omitempty"`
}

// v1.4: created "rating" defn.
// Note: "score" is of type "number" which should map to `float64`
// Note: "severity" is of type "severity" which is a constrained `string`
// Note: "method" is of type "scoreMethod" which is a constrained `string`
type CDXRating struct {
	Source        CDXVulnerabilitySource `json:"source,omitempty"`
	Score         float64                `json:"score,omitempty"`
	Severity      string                 `json:"severity,omitempty"`
	Method        string                 `json:"method,omitempty"`
	Vector        string                 `json:"vector,omitempty"`
	Justification string                 `json:"justification,omitempty"`
}

// v1.4: created "vulnerabilitySource" defn.
// Note: "url" is of type "string" (and not an "iri-reference")
// TODO: "url" SHOULD be an "iri-reference"
type CDXVulnerabilitySource struct {
	Url  string `json:"url,omitempty"`
	Name string `json:"name,omitempty"`
}

// v1.4: created "vulnerability" defn.
// Note: "bom-ref" is a "ref-type" which is a constrained `string`
// Note: "cwes" is a array of "cwe" which is a constrained `int`
type CDXVulnerability struct {
	BomRef         CDXRefType             `json:"bom-ref,omitempty"`
	Id             string                 `json:"id,omitempty"`
	Source         CDXVulnerabilitySource `json:"source,omitempty"`
	References     []CDXReference         `json:"references"` // an anon. type
	Ratings        []CDXRating            `json:"ratings,omitempty"`
	Cwes           []int                  `json:"cwes,omitempty"`
	Description    string                 `json:"description,omitempty"`
	Detail         string                 `json:"detail,omitempty"`
	Recommendation string                 `json:"recommendation,omitempty"`
	Advisories     []CDXAdvisory          `json:"advisories,omitempty"`
	Created        string                 `json:"created,omitempty"`
	Published      string                 `json:"published,omitempty"`
	Updated        string                 `json:"updated,omitempty"`
	Credits        CDXCredit              `json:"credits,omitempty"` // anon. type
	Tools          []CDXTool              `json:"tools,omitempty"`
	Analysis       CDXAnalysis            `json:"analysis,omitempty"` // anon. type
	Affects        []CDXAffect            `json:"affects,omitempty"`  // anon. type
	Properties     []CDXProperty          `json:"properties,omitempty"`
	// v1.5 properties follow
	Rejected string `json:"rejected,omitempty"` // v1.5: added
}

// v1.4 This is an anonymous type used in CDXVulnerability
type CDXReference struct {
	Id     string                 `json:"id,omitempty"`
	Source CDXVulnerabilitySource `json:"source,omitempty"`
}

// v1.4: created "credit" defn. to represent the in-line, anon. type
// found in the "vulnerability" type defn.
// TODO: create top-level defn. for "credit" anon. type
type CDXCredit struct {
	Organizations []CDXOrganizationalEntity  `json:"organizations,omitempty"`
	Individuals   []CDXOrganizationalContact `json:"individuals,omitempty"`
}

// v1.4: created "analysis" def. to represent an in-line, anon. type
// defined in the "vulnerability" object defn.
// Note: "state" is an "impactAnalysisState" type which is a constrained enum. of type `string`
// Note: "justification" is an "impactAnalysisJustification" type which is a constrained enum. of type `string`
// TODO: create top-level defn. for "analysis" anon. type
// TODO: "response" is also "in-lined" as a constrained enum. of `string`, but SHOULD be declared at top-level
type CDXAnalysis struct {
	State         string   `json:"state,omitempty"`
	Justification string   `json:"justification,omitempty"`
	Response      []string `json:"response,omitempty"` // anon. type
	Detail        string   `json:"detail,omitempty"`
}

// v1.4: created "analysis" def. to represent an in-line, anon. type
// Note: This anon. "type" ONLY includes a single array of another in-line type
// TODO: create top-level defn. for "affect" anon. type
type CDXAffect struct {
	Versions []CDXVersionRange `json:"versions,omitempty"` // anon. type
}

// v1.4: created "version" def. to represent an in-line, anon. type
// Note "version" is a top-level defn. that is a constrained `string` type
// Note "affectedStatus" is a top-level defn. that is an enum. of `string` type
// Note: Both "version" constrains strings to a min/mac (1, 1024) length
// this concept SHOULD APPLY to all free-form text entries (e.g., descriptive text)
// TODO: create top-level defn. for "versions" (a.k.a. "versionRange") anon. type (name TBD)
type CDXVersionRange struct {
	Version string `json:"version,omitempty"`
	Range   string `json:"range,omitempty"`
	Status  string `json:"status,omitempty"`
}

// v1.5 "annotations" and sub-schema added ("required": ["subjects","annotator","timestamp","text"])
type CDXAnnotation struct {
	BomRef    CDXRefType   `json:"bom-ref,omitempty"`
	Subjects  []CDXSubject `json:"subjects,omitempty"`
	Annotator CDXAnnotator `json:"annotator,omitempty"`
	Timestamp string       `json:"timestamp,omitempty"`
	Text      string       `json:"text,omitempty"`
	Signature JSFSignature `json:"signature,omitempty"`
}

// v1.5 added to represent the anonymous type defined in the "annotations" object
// Note: Since CDXSubject can be one of 2 other types (i.e., "#/definitions/refLinkType"
// and "#/definitions/bomLinkElementType") which both are "string" types
// we can also make it a "string" type as it does not affect constraint validation.
type CDXSubject string

// v1.5 added to represent the anonymous type defined in the "annotations" object
// required" oneOf: organization, individual, component, service
type CDXAnnotator struct {
	Organization CDXOrganizationalEntity  `json:"organization,omitempty"`
	Individual   CDXOrganizationalContact `json:"individual,omitempty"`
	Component    CDXComponent             `json:"component,omitempty"`
	Service      CDXService               `json:"service,omitempty"`
}

// "annotations": {
// 	"properties": {

// 	  "timestamp": {
// 		"type": "string",
// 		"format": "date-time",
// 		"title": "Timestamp",
// 		"description": "The date and time (timestamp) when the annotation was created."
// 	  },
// 	  "text": {
// 		"type": "string",
// 		"title": "Text",
// 		"description": "The textual content of the annotation."
// 	  },
// 	  "signature": {
// 		"$ref": "#/definitions/signature",
// 		"title": "Signature",
// 		"description": "Enveloped signature in [JSON Signature Format (JSF)](https://cyberphone.github.io/doc/security/jsf.html)."
// 	  }
// 	}
//   },

//   "modelCard": {
// 	"$comment": "Model card support in CycloneDX is derived from TensorFlow Model Card Toolkit released under the Apache 2.0 license and available from https://github.com/tensorflow/model-card-toolkit/blob/main/model_card_toolkit/schema/v0.0.2/model_card.schema.json. In addition, CycloneDX model card support includes portions of VerifyML, also released under the Apache 2.0 license and available from https://github.com/cylynx/verifyml/blob/main/verifyml/model_card_toolkit/schema/v0.0.4/model_card.schema.json.",
// 	"type": "object",
// 	"title": "Model Card",
// 	"description": "A model card describes the intended uses of a machine learning model and potential limitations, including biases and ethical considerations. Model cards typically contain the training parameters, which datasets were used to train the model, performance metrics, and other relevant data useful for ML transparency. This object SHOULD be specified for any component of type `machine-learning-model` and MUST NOT be specified for other component types.",
// 	"additionalProperties": false,
// 	"properties": {
// 	  "bom-ref": {
// 		"$ref": "#/definitions/refType",
// 		"title": "BOM Reference",
// 		"description": "An optional identifier which can be used to reference the model card elsewhere in the BOM. Every bom-ref MUST be unique within the BOM."
// 	  },
// 	  "modelParameters": {
// 		"type": "object",
// 		"title": "Model Parameters",
// 		"description": "Hyper-parameters for construction of the model.",
// 		"additionalProperties": false,
// 		"properties": {
// 		  "approach": {
// 			"type": "object",
// 			"title": "Approach",
// 			"description": "The overall approach to learning used by the model for problem solving.",
// 			"additionalProperties": false,
// 			"properties": {
// 			  "type": {
// 				"type": "string",
// 				"title": "Learning Type",
// 				"description": "Learning types describing the learning problem or hybrid learning problem.",
// 				"enum": [
// 				  "supervised",
// 				  "unsupervised",
// 				  "reinforcement-learning",
// 				  "semi-supervised",
// 				  "self-supervised"
// 				]
// 			  }
// 			}
// 		  },
// 		  "task": {
// 			"type": "string",
// 			"title": "Task",
// 			"description": "Directly influences the input and/or output. Examples include classification, regression, clustering, etc."
// 		  },
// 		  "architectureFamily": {
// 			"type": "string",
// 			"title": "Architecture Family",
// 			"description": "The model architecture family such as transformer network, convolutional neural network, residual neural network, LSTM neural network, etc."
// 		  },
// 		  "modelArchitecture": {
// 			"type": "string",
// 			"title": "Model Architecture",
// 			"description": "The specific architecture of the model such as GPT-1, ResNet-50, YOLOv3, etc."
// 		  },
// 		  "datasets": {
// 			"type": "array",
// 			"title": "Datasets",
// 			"description": "The datasets used to train and evaluate the model.",
// 			"items" : {
// 			  "oneOf" : [
// 				{
// 				  "title": "Inline Component Data",
// 				  "$ref": "#/definitions/componentData"
// 				},
// 				{
// 				  "type": "object",
// 				  "title": "Data Component Reference",
// 				  "additionalProperties": false,
// 				  "properties": {
// 					"ref": {
// 					  "anyOf": [
// 						{
// 						  "title": "Ref",
// 						  "$ref": "#/definitions/refLinkType"
// 						},
// 						{
// 						  "title": "BOM-Link Element",
// 						  "$ref": "#/definitions/bomLinkElementType"
// 						}
// 					  ],
// 					  "title": "Reference",
// 					  "description": "References a data component by the components bom-ref attribute"
// 					}
// 				  }
// 				}
// 			  ]
// 			}
// 		  },
// 		  "inputs": {
// 			"type": "array",
// 			"title": "Inputs",
// 			"description": "The input format(s) of the model",
// 			"items": { "$ref": "#/definitions/inputOutputMLParameters" }
// 		  },
// 		  "outputs": {
// 			"type": "array",
// 			"title": "Outputs",
// 			"description": "The output format(s) from the model",
// 			"items": { "$ref": "#/definitions/inputOutputMLParameters" }
// 		  }
// 		}
// 	  },
// 	  "quantitativeAnalysis": {
// 		"type": "object",
// 		"title": "Quantitative Analysis",
// 		"description": "A quantitative analysis of the model",
// 		"additionalProperties": false,
// 		"properties": {
// 		  "performanceMetrics": {
// 			"type": "array",
// 			"title": "Performance Metrics",
// 			"description": "The model performance metrics being reported. Examples may include accuracy, F1 score, precision, top-3 error rates, MSC, etc.",
// 			"items": { "$ref": "#/definitions/performanceMetric" }
// 		  },
// 		  "graphics": { "$ref": "#/definitions/graphicsCollection" }
// 		}
// 	  },
// 	  "considerations": {
// 		"type": "object",
// 		"title": "Considerations",
// 		"description": "What considerations should be taken into account regarding the model's construction, training, and application?",
// 		"additionalProperties": false,
// 		"properties": {
// 		  "users": {
// 			"type": "array",
// 			"title": "Users",
// 			"description": "Who are the intended users of the model?",
// 			"items": {
// 			  "type": "string"
// 			}
// 		  },
// 		  "useCases": {
// 			"type": "array",
// 			"title": "Use Cases",
// 			"description": "What are the intended use cases of the model?",
// 			"items": {
// 			  "type": "string"
// 			}
// 		  },
// 		  "technicalLimitations": {
// 			"type": "array",
// 			"title": "Technical Limitations",
// 			"description": "What are the known technical limitations of the model? E.g. What kind(s) of data should the model be expected not to perform well on? What are the factors that might degrade model performance?",
// 			"items": {
// 			  "type": "string"
// 			}
// 		  },
// 		  "performanceTradeoffs": {
// 			"type": "array",
// 			"title": "Performance Tradeoffs",
// 			"description": "What are the known tradeoffs in accuracy/performance of the model?",
// 			"items": {
// 			  "type": "string"
// 			}
// 		  },
// 		  "ethicalConsiderations": {
// 			"type": "array",
// 			"title": "Ethical Considerations",
// 			"description": "What are the ethical (or environmental) risks involved in the application of this model?",
// 			"items": { "$ref": "#/definitions/risk" }
// 		  },
// 		  "fairnessAssessments": {
// 			"type": "array",
// 			"title": "Fairness Assessments",
// 			"description": "How does the model affect groups at risk of being systematically disadvantaged? What are the harms and benefits to the various affected groups?",
// 			"items": {
// 			  "$ref": "#/definitions/fairnessAssessment"
// 			}
// 		  }
// 		}
// 	  },
// 	  "properties": {
// 		"type": "array",
// 		"title": "Properties",
// 		"description": "Provides the ability to document properties in a name-value store. This provides flexibility to include data not officially supported in the standard without having to use additional namespaces or create extensions. Unlike key-value stores, properties support duplicate names, each potentially having different values. Property names of interest to the general public are encouraged to be registered in the [CycloneDX Property Taxonomy](https://github.com/CycloneDX/cyclonedx-property-taxonomy). Formal registration is OPTIONAL.",
// 		"items": {"$ref": "#/definitions/property"}
// 	  }
// 	}
//   },
//   "inputOutputMLParameters": {
// 	"type": "object",
// 	"title": "Input and Output Parameters",
// 	"additionalProperties": false,
// 	"properties": {
// 	  "format": {
// 		"description": "The data format for input/output to the model. Example formats include string, image, time-series",
// 		"type": "string"
// 	  }
// 	}
//   },
//   "componentData": {
// 	"type": "object",
// 	"additionalProperties": false,
// 	"required": [
// 	  "type"
// 	],
// 	"properties": {
// 	  "bom-ref": {
// 		"$ref": "#/definitions/refType",
// 		"title": "BOM Reference",
// 		"description": "An optional identifier which can be used to reference the dataset elsewhere in the BOM. Every bom-ref MUST be unique within the BOM."
// 	  },
// 	  "type": {
// 		"type": "string",
// 		"title": "Type of Data",
// 		"description": "The general theme or subject matter of the data being specified.\n\n* __source-code__ = Any type of code, code snippet, or data-as-code.\n* __configuration__ = Parameters or settings that may be used by other components.\n* __dataset__ = A collection of data.\n* __definition__ = Data that can be used to create new instances of what the definition defines.\n* __other__ = Any other type of data that does not fit into existing definitions.",
// 		"enum": [
// 		  "source-code",
// 		  "configuration",
// 		  "dataset",
// 		  "definition",
// 		  "other"
// 		]
// 	  },
// 	  "name": {
// 		"description": "The name of the dataset.",
// 		"type": "string"
// 	  },
// 	  "contents": {
// 		"type": "object",
// 		"title": "Data Contents",
// 		"description": "The contents or references to the contents of the data being described.",
// 		"additionalProperties": false,
// 		"properties": {
// 		  "attachment": {
// 			"title": "Data Attachment",
// 			"description": "An optional way to include textual or encoded data.",
// 			"$ref": "#/definitions/attachment"
// 		  },
// 		  "url": {
// 			"type": "string",
// 			"title": "Data URL",
// 			"description": "The URL to where the data can be retrieved.",
// 			"format": "iri-reference"
// 		  },
// 		  "properties": {
// 			"type": "array",
// 			"title": "Configuration Properties",
// 			"description": "Provides the ability to document name-value parameters used for configuration.",
// 			"items": {
// 			  "$ref": "#/definitions/property"
// 			}
// 		  }
// 		}
// 	  },
// 	  "classification": {
// 		"$ref": "#/definitions/dataClassification"
// 	  },
// 	  "sensitiveData": {
// 		"type": "array",
// 		"description": "A description of any sensitive data in a dataset.",
// 		"items": {
// 		  "type": "string"
// 		}
// 	  },
// 	  "graphics": { "$ref": "#/definitions/graphicsCollection" },
// 	  "description": {
// 		"description": "A description of the dataset. Can describe size of dataset, whether it's used for source code, training, testing, or validation, etc.",
// 		"type": "string"
// 	  },
// 	  "governance": {
// 		"type": "object",
// 		"title": "Data Governance",
// 		"$ref": "#/definitions/dataGovernance"
// 	  }
// 	}
//   },
//   "dataGovernance": {
// 	"type": "object",
// 	"title": "Data Governance",
// 	"additionalProperties": false,
// 	"properties": {
// 	  "custodians": {
// 		"type": "array",
// 		"title": "Data Custodians",
// 		"description": "Data custodians are responsible for the safe custody, transport, and storage of data.",
// 		"items": { "$ref": "#/definitions/dataGovernanceResponsibleParty" }
// 	  },
// 	  "stewards": {
// 		"type": "array",
// 		"title": "Data Stewards",
// 		"description": "Data stewards are responsible for data content, context, and associated business rules.",
// 		"items": { "$ref": "#/definitions/dataGovernanceResponsibleParty" }
// 	  },
// 	  "owners": {
// 		"type": "array",
// 		"title": "Data Owners",
// 		"description": "Data owners are concerned with risk and appropriate access to data.",
// 		"items": { "$ref": "#/definitions/dataGovernanceResponsibleParty" }
// 	  }
// 	}
//   },
//   "dataGovernanceResponsibleParty": {
// 	"type": "object",
// 	"additionalProperties": false,
// 	"properties": {
// 	  "organization": {
// 		"title": "Organization",
// 		"$ref": "#/definitions/organizationalEntity"
// 	  },
// 	  "contact": {
// 		"title": "Individual",
// 		"$ref": "#/definitions/organizationalContact"
// 	  }
// 	},
// 	"oneOf":[
// 	  {
// 		"required": ["organization"]
// 	  },
// 	  {
// 		"required": ["contact"]
// 	  }
// 	]
//   },
//   "graphicsCollection": {
// 	"type": "object",
// 	"title": "Graphics Collection",
// 	"description": "A collection of graphics that represent various measurements.",
// 	"additionalProperties": false,
// 	"properties": {
// 	  "description": {
// 		"description": "A description of this collection of graphics.",
// 		"type": "string"
// 	  },
// 	  "collection": {
// 		"description": "A collection of graphics.",
// 		"type": "array",
// 		"items": { "$ref": "#/definitions/graphic" }
// 	  }
// 	}
//   },
//   "graphic": {
// 	"type": "object",
// 	"additionalProperties": false,
// 	"properties": {
// 	  "name": {
// 		"description": "The name of the graphic.",
// 		"type": "string"
// 	  },
// 	  "image": {
// 		"title": "Graphic Image",
// 		"description": "The graphic (vector or raster). Base64 encoding MUST be specified for binary images.",
// 		"$ref": "#/definitions/attachment"
// 	  }
// 	}
//   },
//   "performanceMetric": {
// 	"type": "object",
// 	"additionalProperties": false,
// 	"properties": {
// 	  "type": {
// 		"description": "The type of performance metric.",
// 		"type": "string"
// 	  },
// 	  "value": {
// 		"description": "The value of the performance metric.",
// 		"type": "string"
// 	  },
// 	  "slice": {
// 		"description": "The name of the slice this metric was computed on. By default, assume this metric is not sliced.",
// 		"type": "string"
// 	  },
// 	  "confidenceInterval": {
// 		"description": "The confidence interval of the metric.",
// 		"type": "object",
// 		"additionalProperties": false,
// 		"properties": {
// 		  "lowerBound": {
// 			"description": "The lower bound of the confidence interval.",
// 			"type": "string"
// 		  },
// 		  "upperBound": {
// 			"description": "The upper bound of the confidence interval.",
// 			"type": "string"
// 		  }
// 		}
// 	  }
// 	}
//   },
//   "risk": {
// 	"type": "object",
// 	"additionalProperties": false,
// 	"properties": {
// 	  "name": {
// 		"description": "The name of the risk.",
// 		"type": "string"
// 	  },
// 	  "mitigationStrategy": {
// 		"description": "Strategy used to address this risk.",
// 		"type": "string"
// 	  }
// 	}
//   },
//   "fairnessAssessment": {
// 	"type": "object",
// 	"title": "Fairness Assessment",
// 	"description": "Information about the benefits and harms of the model to an identified at risk group.",
// 	"additionalProperties": false,
// 	"properties": {
// 	  "groupAtRisk": {
// 		"type": "string",
// 		"description": "The groups or individuals at risk of being systematically disadvantaged by the model."
// 	  },
// 	  "benefits": {
// 		"type": "string",
// 		"description": "Expected benefits to the identified groups."
// 	  },
// 	  "harms": {
// 		"type": "string",
// 		"description": "Expected harms to the identified groups."
// 	  },
// 	  "mitigationStrategy": {
// 		"type": "string",
// 		"description": "With respect to the benefits and harms outlined, please describe any mitigation strategy implemented."
// 	  }
// 	}
//   },
//   "dataClassification": {
// 	"type": "string",
// 	"title": "Data Classification",
// 	"description": "Data classification tags data according to its type, sensitivity, and value if altered, stolen, or destroyed."
//   },

type CDXFormula struct {

	//	  "formula": {
	//		"title": "Formula",
	//		"description": "Describes workflows and resources that captures rules and other aspects of how the associated BOM component or service was formed.",
	//		"type": "object",
	//		"additionalProperties": false,
	//		"properties": {
	//		  "bom-ref": {
	//			"title": "BOM Reference",
	//			"description": "An optional identifier which can be used to reference the formula elsewhere in the BOM. Every bom-ref MUST be unique within the BOM.",
	//			"$ref": "#/definitions/refType"
	//		  },
	//		  "components": {
	//			"title": "Components",
	//			"description": "Transient components that are used in tasks that constitute one or more of this formula's workflows",
	//			"type": "array",
	//			"items": {
	//			  "$ref": "#/definitions/component"
	//			},
	//			"uniqueItems": true
	//		  },
	//		  "services": {
	//			"title": "Services",
	//			"description": "Transient services that are used in tasks that constitute one or more of this formula's workflows",
	//			"type": "array",
	//			"items": {
	//			  "$ref": "#/definitions/service"
	//			},
	//			"uniqueItems": true
	//		  },
	//		  "workflows": {
	//			"title": "Workflows",
	//			"description": "List of workflows that can be declared to accomplish specific orchestrated goals and independently triggered.",
	//			"$comment": "Different workflows can be designed to work together to perform end-to-end CI/CD builds and deployments.",
	//			"type": "array",
	//			"items": {
	//			  "$ref": "#/definitions/workflow"
	//			},
	//			"uniqueItems": true
	//		  },
	//		  "properties": {
	//			"type": "array",
	//			"title": "Properties",
	//			"items": {
	//			  "$ref": "#/definitions/property"
	//			}
	//		  }
	//		}
	//	  },
}

type CDXWorkflow struct {

	//	  "workflow": {
	//		"title": "Workflow",
	//		"description": "A specialized orchestration task.",
	//		"$comment": "Workflow are as task themselves and can trigger other workflow tasks.  These relationships can be modeled in the taskDependencies graph.",
	//		"type": "object",
	//		"required": [
	//		  "bom-ref",
	//		  "uid",
	//		  "taskTypes"
	//		],
	//		"additionalProperties": false,
	//		"properties": {
	//		  "bom-ref": {
	//			"title": "BOM Reference",
	//			"description": "An optional identifier which can be used to reference the workflow elsewhere in the BOM. Every bom-ref MUST be unique within the BOM.",
	//			"$ref": "#/definitions/refType"
	//		  },
	//		  "uid": {
	//			"title": "Unique Identifier (UID)",
	//			"description": "The unique identifier for the resource instance within its deployment context.",
	//			"type": "string"
	//		  },
	//		  "name": {
	//			"title": "Name",
	//			"description": "The name of the resource instance.",
	//			"type": "string"
	//		  },
	//		  "description": {
	//			"title": "Description",
	//			"description": "A description of the resource instance.",
	//			"type": "string"
	//		  },
	//		  "resourceReferences": {
	//			"title": "Resource references",
	//			"description": "References to component or service resources that are used to realize the resource instance.",
	//			"type": "array",
	//			"uniqueItems": true,
	//			"items": {
	//			  "$ref": "#/definitions/resourceReferenceChoice"
	//			}
	//		  },
	//		  "tasks": {
	//			"title": "Tasks",
	//			"description": "The tasks that comprise the workflow.",
	//			"$comment": "Note that tasks can appear more than once as different instances (by name or UID).",
	//			"type": "array",
	//			"uniqueItems": true,
	//			"items": {
	//			  "$ref": "#/definitions/task"
	//			}
	//		  },
	//		  "taskDependencies": {
	//			"title": "Task dependency graph",
	//			"description": "The graph of dependencies between tasks within the workflow.",
	//			"type": "array",
	//			"uniqueItems": true,
	//			"items": {
	//			  "$ref": "#/definitions/dependency"
	//			}
	//		  },
	//		  "taskTypes": {
	//			"title": "Task types",
	//			"description": "Indicates the types of activities performed by the set of workflow tasks.",
	//			"$comment": "Currently, these types reflect common CI/CD actions.",
	//			"type": "array",
	//			"items": {
	//			  "$ref": "#/definitions/taskType"
	//			}
	//		  },
	//		  "trigger": {
	//			"title": "Trigger",
	//			"description": "The trigger that initiated the task.",
	//			"$ref": "#/definitions/trigger"
	//		  },
	//		  "steps": {
	//			"title": "Steps",
	//			"description": "The sequence of steps for the task.",
	//			"type": "array",
	//			"items": {
	//			  "$ref": "#/definitions/step"
	//			},
	//			"uniqueItems": true
	//		  },
	//		  "inputs": {
	//			"title": "Inputs",
	//			"description": "Represents resources and data brought into a task at runtime by executor or task commands",
	//			"examples": ["a `configuration` file which was declared as a local `component` or `externalReference`"],
	//			"type": "array",
	//			"items": {
	//			  "$ref": "#/definitions/inputType"
	//			},
	//			"uniqueItems": true
	//		  },
	//		  "outputs": {
	//			"title": "Outputs",
	//			"description": "Represents resources and data output from a task at runtime by executor or task commands",
	//			"examples": ["a log file or metrics data produced by the task"],
	//			"type": "array",
	//			"items": {
	//			  "$ref": "#/definitions/outputType"
	//			},
	//			"uniqueItems": true
	//		  },
	//		  "timeStart": {
	//			"title": "Time start",
	//			"description": "The date and time (timestamp) when the task started.",
	//			"type": "string",
	//			"format": "date-time"
	//		  },
	//		  "timeEnd": {
	//			"title": "Time end",
	//			"description": "The date and time (timestamp) when the task ended.",
	//			"type": "string",
	//			"format": "date-time"
	//		  },
	//		  "workspaces": {
	//			"title": "Workspaces",
	//			"description": "A set of named filesystem or data resource shareable by workflow tasks.",
	//			"type": "array",
	//			"uniqueItems": true,
	//			"items": {
	//			  "$ref": "#/definitions/workspace"
	//			}
	//		  },
	//		  "runtimeTopology": {
	//			"title": "Runtime topology",
	//			"description": "A graph of the component runtime topology for workflow's instance.",
	//			"$comment": "A description of the runtime component and service topology.  This can describe a partial or complete topology used to host and execute the task (e.g., hardware, operating systems, configurations, etc.),",
	//			"type": "array",
	//			"uniqueItems": true,
	//			"items": {
	//			  "$ref": "#/definitions/dependency"
	//			}
	//		  },
	//		  "properties": {
	//			"type": "array",
	//			"title": "Properties",
	//			"items": {
	//			  "$ref": "#/definitions/property"
	//			}
	//		  }
	//		}
	//	  },
}

type CDXTask struct {

	//	  "task": {
	//		"title": "Task",
	//		"description": "Describes the inputs, sequence of steps and resources used to accomplish a task and its output.",
	//		"$comment": "Tasks are building blocks for constructing assemble CI/CD workflows or pipelines.",
	//		"type": "object",
	//		"required": [
	//		  "bom-ref",
	//		  "uid",
	//		  "taskTypes"
	//		],
	//		"additionalProperties": false,
	//		"properties": {
	//		  "bom-ref": {
	//			"title": "BOM Reference",
	//			"description": "An optional identifier which can be used to reference the task elsewhere in the BOM. Every bom-ref MUST be unique within the BOM.",
	//			"$ref": "#/definitions/refType"
	//		  },
	//		  "uid": {
	//			"title": "Unique Identifier (UID)",
	//			"description": "The unique identifier for the resource instance within its deployment context.",
	//			"type": "string"
	//		  },
	//		  "name": {
	//			"title": "Name",
	//			"description": "The name of the resource instance.",
	//			"type": "string"
	//		  },
	//		  "description": {
	//			"title": "Description",
	//			"description": "A description of the resource instance.",
	//			"type": "string"
	//		  },
	//		  "resourceReferences": {
	//			"title": "Resource references",
	//			"description": "References to component or service resources that are used to realize the resource instance.",
	//			"type": "array",
	//			"uniqueItems": true,
	//			"items": {
	//			  "$ref": "#/definitions/resourceReferenceChoice"
	//			}
	//		  },
	//		  "taskTypes": {
	//			"title": "Task types",
	//			"description": "Indicates the types of activities performed by the set of workflow tasks.",
	//			"$comment": "Currently, these types reflect common CI/CD actions.",
	//			"type": "array",
	//			"items": {
	//			  "$ref": "#/definitions/taskType"
	//			}
	//		  },
	//		  "trigger": {
	//			"title": "Trigger",
	//			"description": "The trigger that initiated the task.",
	//			"$ref": "#/definitions/trigger"
	//		  },
	//		  "steps": {
	//			"title": "Steps",
	//			"description": "The sequence of steps for the task.",
	//			"type": "array",
	//			"items": {
	//			  "$ref": "#/definitions/step"
	//			},
	//			"uniqueItems": true
	//		  },
	//		  "inputs": {
	//			"title": "Inputs",
	//			"description": "Represents resources and data brought into a task at runtime by executor or task commands",
	//			"examples": ["a `configuration` file which was declared as a local `component` or `externalReference`"],
	//			"type": "array",
	//			"items": {
	//			  "$ref": "#/definitions/inputType"
	//			},
	//			"uniqueItems": true
	//		  },
	//		  "outputs": {
	//			"title": "Outputs",
	//			"description": "Represents resources and data output from a task at runtime by executor or task commands",
	//			"examples": ["a log file or metrics data produced by the task"],
	//			"type": "array",
	//			"items": {
	//			  "$ref": "#/definitions/outputType"
	//			},
	//			"uniqueItems": true
	//		  },
	//		  "timeStart": {
	//			"title": "Time start",
	//			"description": "The date and time (timestamp) when the task started.",
	//			"type": "string",
	//			"format": "date-time"
	//		  },
	//		  "timeEnd": {
	//			"title": "Time end",
	//			"description": "The date and time (timestamp) when the task ended.",
	//			"type": "string",
	//			"format": "date-time"
	//		  },
	//		  "workspaces": {
	//			"title": "Workspaces",
	//			"description": "A set of named filesystem or data resource shareable by workflow tasks.",
	//			"type": "array",
	//			"items": {
	//			  "$ref": "#/definitions/workspace"
	//			},
	//			"uniqueItems": true
	//		  },
	//		  "runtimeTopology": {
	//			"title": "Runtime topology",
	//			"description": "A graph of the component runtime topology for task's instance.",
	//			"$comment": "A description of the runtime component and service topology.  This can describe a partial or complete topology used to host and execute the task (e.g., hardware, operating systems, configurations, etc.),",
	//			"type": "array",
	//			"items": {
	//			  "$ref": "#/definitions/dependency"
	//			},
	//			"uniqueItems": true
	//		  },
	//		  "properties": {
	//			"type": "array",
	//			"title": "Properties",
	//			"items": {
	//			  "$ref": "#/definitions/property"
	//			}
	//		  }
	//		}
	//	  },
}

type CDXStep struct {

	//	  "step": {
	//		"type": "object",
	//		"description": "Executes specific commands or tools in order to accomplish its owning task as part of a sequence.",
	//		"additionalProperties": false,
	//		"properties": {
	//		  "name": {
	//			"title": "Name",
	//			"description": "A name for the step.",
	//			"type": "string"
	//		  },
	//		  "description": {
	//			"title": "Description",
	//			"description": "A description of the step.",
	//			"type": "string"
	//		  },
	//		  "commands": {
	//			"title": "Commands",
	//			"description": "Ordered list of commands or directives for the step",
	//			"type": "array",
	//			"items": {
	//			  "$ref": "#/definitions/command"
	//			}
	//		  },
	//		  "properties": {
	//			"type": "array",
	//			"title": "Properties",
	//			"items": {
	//			  "$ref": "#/definitions/property"
	//			}
	//		  }
	//		}
	//	  },
}

type CDXCommand struct {

	//	  "command": {
	//		"type": "object",
	//		"additionalProperties": false,
	//		"properties": {
	//		  "executed": {
	//			"title": "Executed",
	//			"description": "A text representation of the executed command.",
	//			"type": "string"
	//		  },
	//		  "properties": {
	//			"type": "array",
	//			"title": "Properties",
	//			"items": {
	//			  "$ref": "#/definitions/property"
	//			}
	//		  }
	//		}
	//	  },
}

type CDXWorkspace struct {
	//	  "workspace": {
	//		"title": "Workspace",
	//		"description": "A named filesystem or data resource shareable by workflow tasks.",
	//		"type": "object",
	//		"required": [
	//		  "bom-ref",
	//		  "uid"
	//		],
	//		"additionalProperties": false,
	//		"properties": {
	//		  "bom-ref": {
	//			"title": "BOM Reference",
	//			"description": "An optional identifier which can be used to reference the workspace elsewhere in the BOM. Every bom-ref MUST be unique within the BOM.",
	//			"$ref": "#/definitions/refType"
	//		  },
	//		  "uid": {
	//			"title": "Unique Identifier (UID)",
	//			"description": "The unique identifier for the resource instance within its deployment context.",
	//			"type": "string"
	//		  },
	//		  "name": {
	//			"title": "Name",
	//			"description": "The name of the resource instance.",
	//			"type": "string"
	//		  },
	//		  "aliases": {
	//			"title": "Aliases",
	//			"description": "The names for the workspace as referenced by other workflow tasks. Effectively, a name mapping so other tasks can use their own local name in their steps.",
	//			"type": "array",
	//			"items": {"type": "string"}
	//		  },
	//		  "description": {
	//			"title": "Description",
	//			"description": "A description of the resource instance.",
	//			"type": "string"
	//		  },
	//		  "resourceReferences": {
	//			"title": "Resource references",
	//			"description": "References to component or service resources that are used to realize the resource instance.",
	//			"type": "array",
	//			"uniqueItems": true,
	//			"items": {
	//			  "$ref": "#/definitions/resourceReferenceChoice"
	//			}
	//		  },
	//		  "accessMode": {
	//			"title": "Access mode",
	//			"description": "Describes the read-write access control for the workspace relative to the owning resource instance.",
	//			"type": "string",
	//			"enum": [
	//			  "read-only",
	//			  "read-write",
	//			  "read-write-once",
	//			  "write-once",
	//			  "write-only"
	//			]
	//		  },
	//		  "mountPath": {
	//			"title": "Mount path",
	//			"description": "A path to a location on disk where the workspace will be available to the associated task's steps.",
	//			"type": "string"
	//		  },
	//		  "managedDataType": {
	//			"title": "Managed data type",
	//			"description": "The name of a domain-specific data type the workspace represents.",
	//			"$comment": "This property is for CI/CD frameworks that are able to provide access to structured, managed data at a more granular level than a filesystem.",
	//			"examples": ["ConfigMap","Secret"],
	//			"type": "string"
	//		  },
	//		  "volumeRequest": {
	//			"title": "Volume request",
	//			"description": "Identifies the reference to the request for a specific volume type and parameters.",
	//			"examples": ["a kubernetes Persistent Volume Claim (PVC) name"],
	//			"type": "string"
	//		  },
	//		  "volume": {
	//			"title": "Volume",
	//			"description": "Information about the actual volume instance allocated to the workspace.",
	//			"$comment": "The actual volume allocated may be different than the request.",
	//			"examples": ["see https://kubernetes.io/docs/concepts/storage/persistent-volumes/"],
	//			"$ref": "#/definitions/volume"
	//		  },
	//		  "properties": {
	//			"type": "array",
	//			"title": "Properties",
	//			"items": {
	//			  "$ref": "#/definitions/property"
	//			}
	//		  }
	//		}
	//	  },
}

type CDXVolume struct {
	//	  "volume": {
	//		"title": "Volume",
	//		"description": "An identifiable, logical unit of data storage tied to a physical device.",
	//		"type": "object",
	//		"additionalProperties": false,
	//		"properties": {
	//		  "uid": {
	//			"title": "Unique Identifier (UID)",
	//			"description": "The unique identifier for the volume instance within its deployment context.",
	//			"type": "string"
	//		  },
	//		  "name": {
	//			"title": "Name",
	//			"description": "The name of the volume instance",
	//			"type": "string"
	//		  },
	//		  "mode": {
	//			"title": "Mode",
	//			"description": "The mode for the volume instance.",
	//			"type": "string",
	//			"enum": [
	//			  "filesystem", "block"
	//			],
	//			"default": "filesystem"
	//		  },
	//		  "path": {
	//			"title": "Path",
	//			"description": "The underlying path created from the actual volume.",
	//			"type": "string"
	//		  },
	//		  "sizeAllocated": {
	//			"title": "Size allocated",
	//			"description": "The allocated size of the volume accessible to the associated workspace. This should include the scalar size as well as IEC standard unit in either decimal or binary form.",
	//			"examples": ["10GB", "2Ti", "1Pi"],
	//			"type": "string"
	//		  },
	//		  "persistent": {
	//			"title": "Persistent",
	//			"description": "Indicates if the volume persists beyond the life of the resource it is associated with.",
	//			"type": "boolean"
	//		  },
	//		  "remote": {
	//			"title": "Remote",
	//			"description": "Indicates if the volume is remotely (i.e., network) attached.",
	//			"type": "boolean"
	//		  },
	//		  "properties": {
	//			"type": "array",
	//			"title": "Properties",
	//			"items": {
	//			  "$ref": "#/definitions/property"
	//			}
	//		  }
	//		}
	//	  },
}

type CDXTrigger struct {
	//	  "trigger": {
	//		"title": "Trigger",
	//		"description": "Represents a resource that can conditionally activate (or fire) tasks based upon associated events and their data.",
	//		"type": "object",
	//		"additionalProperties": false,
	//		"required": [
	//		  "type",
	//		  "bom-ref",
	//		  "uid"
	//		],
	//		"properties": {
	//		  "bom-ref": {
	//			"title": "BOM Reference",
	//			"description": "An optional identifier which can be used to reference the trigger elsewhere in the BOM. Every bom-ref MUST be unique within the BOM.",
	//			"$ref": "#/definitions/refType"
	//		  },
	//		  "uid": {
	//			"title": "Unique Identifier (UID)",
	//			"description": "The unique identifier for the resource instance within its deployment context.",
	//			"type": "string"
	//		  },
	//		  "name": {
	//			"title": "Name",
	//			"description": "The name of the resource instance.",
	//			"type": "string"
	//		  },
	//		  "description": {
	//			"title": "Description",
	//			"description": "A description of the resource instance.",
	//			"type": "string"
	//		  },
	//		  "resourceReferences": {
	//			"title": "Resource references",
	//			"description": "References to component or service resources that are used to realize the resource instance.",
	//			"type": "array",
	//			"uniqueItems": true,
	//			"items": {
	//			  "$ref": "#/definitions/resourceReferenceChoice"
	//			}
	//		  },
	//		  "type": {
	//			"title": "Type",
	//			"description": "The source type of event which caused the trigger to fire.",
	//			"type": "string",
	//			"enum": [
	//			  "manual",
	//			  "api",
	//			  "webhook",
	//			  "scheduled"
	//			]
	//		  },
	//		  "event": {
	//			"title": "Event",
	//			"description": "The event data that caused the associated trigger to activate.",
	//			"$ref": "#/definitions/event"
	//		  },
	//		  "conditions": {
	//			"type": "array",
	//			"uniqueItems": true,
	//			"items": {
	//			  "$ref": "#/definitions/condition"
	//			}
	//		  },
	//		  "timeActivated": {
	//			"title": "Time activated",
	//			"description": "The date and time (timestamp) when the trigger was activated.",
	//			"type": "string",
	//			"format": "date-time"
	//		  },
	//		  "inputs": {
	//			"title": "Inputs",
	//			"description": "Represents resources and data brought into a task at runtime by executor or task commands",
	//			"examples": ["a `configuration` file which was declared as a local `component` or `externalReference`"],
	//			"type": "array",
	//			"items": {
	//			  "$ref": "#/definitions/inputType"
	//			},
	//			"uniqueItems": true
	//		  },
	//		  "outputs": {
	//			"title": "Outputs",
	//			"description": "Represents resources and data output from a task at runtime by executor or task commands",
	//			"examples": ["a log file or metrics data produced by the task"],
	//			"type": "array",
	//			"items": {
	//			  "$ref": "#/definitions/outputType"
	//			},
	//			"uniqueItems": true
	//		  },
	//		  "properties": {
	//			"type": "array",
	//			"title": "Properties",
	//			"items": {
	//			  "$ref": "#/definitions/property"
	//			}
	//		  }
	//		}
	//	  },
	//	  "event": {
}

type CDXEvent struct {
	//		"title": "Event",
	//		"description": "Represents something that happened that may trigger a response.",
	//		"type": "object",
	//		"additionalProperties": false,
	//		"properties": {
	//		  "uid": {
	//			"title": "Unique Identifier (UID)",
	//			"description": "The unique identifier of the event.",
	//			"type": "string"
	//		  },
	//		  "description": {
	//			"title": "Description",
	//			"description": "A description of the event.",
	//			"type": "string"
	//		  },
	//		  "timeReceived": {
	//			"title": "Time Received",
	//			"description": "The date and time (timestamp) when the event was received.",
	//			"type": "string",
	//			"format": "date-time"
	//		  },
	//		  "data": {
	//			"title": "Data",
	//			"description": "Encoding of the raw event data.",
	//			"$ref": "#/definitions/attachment"
	//		  },
	//		  "source": {
	//			"title": "Source",
	//			"description": "References the component or service that was the source of the event",
	//			"$ref": "#/definitions/resourceReferenceChoice"
	//		  },
	//		  "target": {
	//			"title": "Target",
	//			"description": "References the component or service that was the target of the event",
	//			"$ref": "#/definitions/resourceReferenceChoice"
	//		  },
	//		  "properties": {
	//			"type": "array",
	//			"title": "Properties",
	//			"items": {
	//			  "$ref": "#/definitions/property"
	//			}
	//		  }
	//		}
	//	  },
}

type CDXInputType struct {
	//	  "inputType": {
	//		"title": "Input type",
	//		"description": "Type that represents various input data types and formats.",
	//		"type": "object",
	//		"oneOf": [
	//		  {
	//			"required": [
	//			  "resource"
	//			]
	//		  },
	//		  {
	//			"required": [
	//			  "parameters"
	//			]
	//		  },
	//		  {
	//			"required": [
	//			  "environmentVars"
	//			]
	//		  },
	//		  {
	//			"required": [
	//			  "data"
	//			]
	//		  }
	//		],
	//		"additionalProperties": false,
	//		"properties": {
	//		  "source": {
	//			"title": "Source",
	//			"description": "A references to the component or service that provided the input to the task (e.g., reference to a service with data flow value of `inbound`)",
	//			"examples": [
	//			  "source code repository",
	//			  "database"
	//			],
	//			"$ref": "#/definitions/resourceReferenceChoice"
	//		  },
	//		  "target": {
	//			"title": "Target",
	//			"description": "A reference to the component or service that received or stored the input if not the task itself (e.g., a local, named storage workspace)",
	//			"examples": [
	//			  "workspace",
	//			  "directory"
	//			],
	//			"$ref": "#/definitions/resourceReferenceChoice"
	//		  },
	//		  "resource": {
	//			"title": "Resource",
	//			"description": "A reference to an independent resource provided as an input to a task by the workflow runtime.",
	//			"examples": [
	//			  "reference to a configuration file in a repository (i.e., a bom-ref)",
	//			  "reference to a scanning service used in a task (i.e., a bom-ref)"
	//			],
	//			"$ref": "#/definitions/resourceReferenceChoice"
	//		  },
	//		  "parameters": {
	//			"title": "Parameters",
	//			"description": "Inputs that have the form of parameters with names and values.",
	//			"type": "array",
	//			"uniqueItems": true,
	//			"items": {
	//			  "$ref": "#/definitions/parameter"
	//			}
	//		  },
	//		  "environmentVars": {
	//			"title": "Environment variables",
	//			"description": "Inputs that have the form of parameters with names and values.",
	//			"type": "array",
	//			"uniqueItems": true,
	//			"items": {
	//			  "oneOf": [
	//				{
	//				  "$ref": "#/definitions/property"
	//				},
	//				{
	//				  "type": "string"
	//				}
	//			  ]
	//			}
	//		  },
	//		  "data": {
	//			"title": "Data",
	//			"description": "Inputs that have the form of data.",
	//			"$ref": "#/definitions/attachment"
	//		  },
	//		  "properties": {
	//			"type": "array",
	//			"title": "Properties",
	//			"items": {
	//			  "$ref": "#/definitions/property"
	//			}
	//		  }
	//		}
	//	  },
}

type CDXOutputType struct {
	//	  "outputType": {
	//		"type": "object",
	//		"oneOf": [
	//		  {
	//			"required": [
	//			  "resource"
	//			]
	//		  },
	//		  {
	//			"required": [
	//			  "environmentVars"
	//			]
	//		  },
	//		  {
	//			"required": [
	//			  "data"
	//			]
	//		  }
	//		],
	//		"additionalProperties": false,
	//		"properties": {
	//		  "type": {
	//			"title": "Type",
	//			"description": "Describes the type of data output.",
	//			"type": "string",
	//			"enum": [
	//			  "artifact",
	//			  "attestation",
	//			  "log",
	//			  "evidence",
	//			  "metrics",
	//			  "other"
	//			]
	//		  },
	//		  "source": {
	//			"title": "Source",
	//			"description": "Component or service that generated or provided the output from the task (e.g., a build tool)",
	//			"$ref": "#/definitions/resourceReferenceChoice"
	//		  },
	//		  "target": {
	//			"title": "Target",
	//			"description": "Component or service that received the output from the task (e.g., reference to an artifactory service with data flow value of `outbound`)",
	//			"examples": ["a log file described as an `externalReference` within its target domain."],
	//			"$ref": "#/definitions/resourceReferenceChoice"
	//		  },
	//		  "resource": {
	//			"title": "Resource",
	//			"description": "A reference to an independent resource generated as output by the task.",
	//			"examples": [
	//			  "configuration file",
	//			  "source code",
	//			  "scanning service"
	//			],
	//			"$ref": "#/definitions/resourceReferenceChoice"
	//		  },
	//		  "data": {
	//			"title": "Data",
	//			"description": "Outputs that have the form of data.",
	//			"$ref": "#/definitions/attachment"
	//		  },
	//		  "environmentVars": {
	//			"title": "Environment variables",
	//			"description": "Outputs that have the form of environment variables.",
	//			"type": "array",
	//			"items": {
	//			  "oneOf": [
	//				{
	//				  "$ref": "#/definitions/property"
	//				},
	//				{
	//				  "type": "string"
	//				}
	//			  ]
	//			},
	//			"uniqueItems": true
	//		  },
	//		  "properties": {
	//			"type": "array",
	//			"title": "Properties",
	//			"items": {
	//			  "$ref": "#/definitions/property"
	//			}
	//		  }
	//		}
	//	  },
}

type CDXResourceReferenceChoice struct {

	//	  "resourceReferenceChoice": {
	//		"title": "Resource reference choice",
	//		"description": "A reference to a locally defined resource (e.g., a bom-ref) or an externally accessible resource.",
	//		"$comment": "Enables reference to a resource that participates in a workflow; using either internal (bom-ref) or external (externalReference) types.",
	//		"type": "object",
	//		"additionalProperties": false,
	//		"properties": {
	//		  "ref": {
	//			"title": "BOM Reference",
	//			"description": "References an object by its bom-ref attribute",
	//			"anyOf": [
	//			  {
	//				"title": "Ref",
	//				"$ref": "#/definitions/refLinkType"
	//			  },
	//			  {
	//				"title": "BOM-Link Element",
	//				"$ref": "#/definitions/bomLinkElementType"
	//			  }
	//			]
	//		  },
	//		  "externalReference": {
	//			"title": "External reference",
	//			"description": "Reference to an externally accessible resource.",
	//			"$ref": "#/definitions/externalReference"
	//		  }
	//		},
	//		"oneOf": [
	//		  {
	//			"required": [
	//			  "ref"
	//			]
	//		  },
	//		  {
	//			"required": [
	//			  "externalReference"
	//			]
	//		  }
	//		]
	//	  },
}

type CDXCondition struct {
	//	  "condition": {
	//		"title": "Condition",
	//		"description": "A condition that was used to determine a trigger should be activated.",
	//		"type": "object",
	//		"additionalProperties": false,
	//		"properties": {
	//		  "description": {
	//			"title": "Description",
	//			"description": "Describes the set of conditions which cause the trigger to activate.",
	//			"type": "string"
	//		  },
	//		  "expression": {
	//			"title": "Expression",
	//			"description": "The logical expression that was evaluated that determined the trigger should be fired.",
	//			"type": "string"
	//		  },
	//		  "properties": {
	//			"type": "array",
	//			"title": "Properties",
	//			"items": {
	//			  "$ref": "#/definitions/property"
	//			}
	//		  }
	//		}
	//	  },
}

type CDXTaskType struct {

	//	  "taskType": {
	//		"type": "string",
	//		"enum": [
	//		  "copy",
	//		  "clone",
	//		  "lint",
	//		  "scan",
	//		  "merge",
	//		  "build",
	//		  "test",
	//		  "deliver",
	//		  "deploy",
	//		  "release",
	//		  "clean",
	//		  "other"
	//		]
	//	  },
	//	  "parameter": {
	//		"title": "Parameter",
	//		"description": "A representation of a functional parameter.",
	//		"type": "object",
	//		"additionalProperties": false,
	//		"properties": {
	//		  "name": {
	//			"title": "Name",
	//			"description": "The name of the parameter.",
	//			"type": "string"
	//		  },
	//		  "value": {
	//			"title": "Value",
	//			"description": "The value of the parameter.",
	//			"type": "string"
	//		  },
	//		  "dataType": {
	//			"title": "Data type",
	//			"description": "The data type of the parameter.",
	//			"type": "string"
	//		  }
	//		}
	//	  },
}

// v1.5 new type for "metadata"
type CDXNameDescription struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

type CDXLifecycle struct {
	//  v1.5: "enum": [ "design", "pre-build", "build", "post-build", "operations", "discovery", "decommission"]
	Phase              string `json:"phase,omitempty"`
	CDXNameDescription        // name, description
}

// // TODO: implement JSF schema
// // https://github.com/CycloneDX/specification/blob/master/schema/jsf-0.82.schema.json
// type CDXSignature struct {
// 	KeyType string `json:"keyType,omitempty"`
// }
