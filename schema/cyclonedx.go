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

import (
	"encoding/json"
	"reflect"
)

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
	// v1.3 added "compositions"
	Compositions []CDXCompositions `json:"compositions,omitempty" cdx:"v1.3"`
	// v1.4 added "vulnerabilities", "signature"
	Vulnerabilities []CDXVulnerability `json:"vulnerabilities,omitempty" cdx:"v1.4"`
	// TODO: Issue #23: Signature CDXSignature `json:"signature,omitempty"`
}

// v1.2: existed
type CDXMetadata struct {
	Timestamp    string                     `json:"timestamp,omitempty"`
	Tools        []CDXTool                  `json:"tools,omitempty"`
	Authors      []CDXOrganizationalContact `json:"authors,omitempty"`
	Component    CDXComponent               `json:"component,omitempty"`
	Manufacturer CDXOrganizationalEntity    `json:"manufacturer,omitempty"`
	Supplier     CDXOrganizationalEntity    `json:"supplier,omitempty"`
	Hashes       []CDXHash                  `json:"hashes,omitempty"`
	// v1.3: added "licenses", "properties"
	Licenses   []CDXLicenseChoice `json:"licenses,omitempty"`
	Properties []CDXProperty      `json:"properties,omitempty"`
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
	BomRef             string                  `json:"bom-ref,omitempty"`
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
// TODO: a service is not all auth or not auth.; that is, we have mult. endpoints
// but only 1 boolean for "authenticated" (open spec. issue)
// TODO: Not sure the intent of having "nested" (hierarchical) services?
// TODO: Should support OpenAPI specification (documents) as canonical descriptors
// TODO: v1.2 "licenses" used to be an anon. type until v1.3 intro. the `LicenseChoice` def.
// validate a v1.2 SBOM wit the anon. type parses properly
type CDXService struct {
	BomRef             string                  `json:"bom-ref,omitempty"`
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
	Signature          CDXSignature            `json:"signature,omitempty"`    // v1.4: added
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
type CDXOrganizationalEntity struct {
	Name    string                     `json:"name,omitempty"`
	Url     []string                   `json:"url,omitempty"`
	Contact []CDXOrganizationalContact `json:"contact,omitempty"`
}

// v1.2: existed
type CDXOrganizationalContact struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
	Phone string `json:"phone,omitempty"`
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
// TODO: Should not be plural
type CDXCompositions struct {
	Aggregate    string       `json:"aggregate,omitempty"`
	Assemblies   []string     `json:"assemblies,omitempty"`
	Dependencies []string     `json:"dependencies,omitempty"`
	Signature    CDXSignature `json:"signature,omitempty"` // v1.4: added
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
	BomRef         string                 `json:"bom-ref,omitempty"`
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

// TODO: implement JSF schema
// https://github.com/CycloneDX/specification/blob/master/schema/jsf-0.82.schema.json
type CDXSignature struct {
	KeyType string `json:"keyType,omitempty"`
}

// --------------------------------------
// UnMarshal from JSON
// --------------------------------------

func UnMarshalDocument(data interface{}) (*CDXBom, error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// we need to marshal the data to normalize it to a []byte
	jsonString, errMarshal := json.Marshal(data)

	if errMarshal != nil {
		return nil, errMarshal
	}

	// optimistically, prepare the receiving structure and unmarshal
	var bom CDXBom
	errUnmarshal := json.Unmarshal(jsonString, &bom)

	if errUnmarshal != nil {
		getLogger().Warningf("unmarshal failed: %v", errUnmarshal)
	}

	//getLogger().Tracef("\n%s", getLogger().FormatStruct(lc))
	return &bom, errUnmarshal
}

func UnMarshalMetadata(data interface{}) (CDXMetadata, error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// we need to marshal the data to normalize it to a []byte
	jsonString, errMarshal := json.Marshal(data)

	if errMarshal != nil {
		return CDXMetadata{}, errMarshal
	}

	// optimistically, prepare the receiving structure and unmarshal
	metadata := CDXMetadata{}
	errUnmarshal := json.Unmarshal(jsonString, &metadata)

	if errUnmarshal != nil {
		getLogger().Warningf("unmarshal failed: %v", errUnmarshal)
	}

	//getLogger().Tracef("\n%s", getLogger().FormatStruct(lc))
	return metadata, errUnmarshal
}

func UnMarshalLicenseChoice(data interface{}) (CDXLicenseChoice, error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// we need to marshal the data to normalize it to a []byte
	jsonString, errMarshal := json.Marshal(data)

	if errMarshal != nil {
		return CDXLicenseChoice{}, errMarshal
	}

	// optimistically, prepare the receiving structure and unmarshal
	lc := CDXLicenseChoice{}
	errUnmarshal := json.Unmarshal(jsonString, &lc)

	if errUnmarshal != nil {
		getLogger().Warningf("unmarshal failed: %v", errUnmarshal)
	}

	//getLogger().Tracef("\n%s", getLogger().FormatStruct(lc))
	return lc, errUnmarshal
}

func UnMarshalComponent(data interface{}) (CDXComponent, error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// we need to marshal the data to normalize it to a []byte
	jsonString, errMarshal := json.Marshal(data)

	if errMarshal != nil {
		return CDXComponent{}, errMarshal
	}

	// optimistically, prepare the receiving structure
	// and unmarshal
	component := CDXComponent{}
	errUnmarshal := json.Unmarshal(jsonString, &component)

	if errUnmarshal != nil {
		getLogger().Warningf("unmarshal failed: %v", errUnmarshal)
	}

	//getLogger().Tracef("\n%s", getLogger().FormatStruct(component))
	return component, errUnmarshal
}

func UnMarshalComponents(data interface{}) ([]CDXComponent, error) {
	getLogger().Enter()
	defer getLogger().Exit()

	var components []CDXComponent

	// we need to marshal the data to normalize it to a []byte
	jsonString, errMarshal := json.Marshal(data)
	if errMarshal != nil {
		return components, errMarshal
	}

	// unmarshal into custom structure
	errUnmarshal := json.Unmarshal(jsonString, &components)
	if errUnmarshal != nil {
		getLogger().Warningf("unmarshal failed: %v", errUnmarshal)
	}

	return components, errUnmarshal
}

func UnMarshalProperties(data interface{}) (properties []CDXProperty, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// we need to marshal the data to normalize it to a []byte
	jsonString, err := json.Marshal(data)
	if err != nil {
		return
	}

	// unmarshal into custom structure
	err = json.Unmarshal(jsonString, &properties)
	if err != nil {
		getLogger().Warningf("unmarshal failed: %v", err)
	}

	return
}

func UnMarshalProperty(data interface{}) (property CDXProperty, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// we need to marshal the data to normalize it to a []byte
	jsonString, err := json.Marshal(data)
	if err != nil {
		return
	}

	// unmarshal into custom structure
	err = json.Unmarshal(jsonString, &property)
	if err != nil {
		getLogger().Warningf("unmarshal failed: %v", err)
	}

	return
}

// --------------------------------------
// Utils
// --------------------------------------

func (property *CDXProperty) Equals(testProperty CDXProperty) bool {
	return reflect.DeepEqual(*property, testProperty)
}
