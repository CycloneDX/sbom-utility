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
	Compositions []CDXCompositions `json:"compositions,omitempty"`
	// v1.4 added "vulnerabilities", "signature"
	Vulnerabilities []CDXVulnerability `json:"vulnerabilities,omitempty"`
	// TODO: Signature CDXSignature `json:"signature,omitempty"`
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
	BomRef             string                  `json:"bom-ref"`
	Provider           CDXOrganizationalEntity `json:"provider"`
	Group              string                  `json:"group"`
	Name               string                  `json:"name"`
	Version            string                  `json:"version"`
	Description        string                  `json:"description"`
	Endpoints          []string                `json:"endpoints"`
	Authenticated      bool                    `json:"authenticated"`
	XTrustBoundary     bool                    `json:"x-trust-boundary"`
	Data               []CDXDataClassification `json:"data"`
	Licenses           []CDXLicenseChoice      `json:"licenses"`
	ExternalReferences []CDXExternalReference  `json:"externalReferences"`
	Services           []CDXService            `json:"services"`
	Properties         []CDXProperty           `json:"properties"`   // v1.3: added
	ReleaseNotes       []CDXReleaseNotes       `json:"releaseNotes"` // v1.4: added
	Signature          CDXSignature            `json:"signature"`    // v1.4: added
}

// v1.2: existed as an anon. type in the "component" type defn.
// The "Notes" (plural) should likely be multiple strings or text annotations
// TODO: create top-level defn. for "pedigree" anon. type
type CDXPedigree struct {
	Ancestors   []CDXComponent `json:"ancestors"`
	Descendants []CDXComponent `json:"descendants"`
	Variants    []CDXComponent `json:"variants"`
	Commits     []CDXCommit    `json:"commits"`
	Patches     []CDXPatch     `json:"patches"`
	Notes       string         `json:"notes"`
}

// v1.2: existed
// v1.4: added "externalReferences"
type CDXTool struct {
	Vendor             string                 `json:"vendor"`
	Name               string                 `json:"name"`
	Version            string                 `json:"version"`
	Hashes             []CDXHash              `json:"hashes"`
	ExternalReferences []CDXExternalReference `json:"externalReferences"` // v1.4: added
}

// v1.2: existed
type CDXOrganizationalEntity struct {
	Name    string                     `json:"name"`
	Url     []string                   `json:"url"`
	Contact []CDXOrganizationalContact `json:"contact"`
}

// v1.2: existed
type CDXOrganizationalContact struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Phone string `json:"phone"`
}

// v1.2: existed
// v1.4: deprecated
type CDXSwid struct {
	TagId      string        `json:"tagId"`
	Name       string        `json:"name"`
	Version    string        `json:"version"`
	TagVersion int           `json:"tagVersion"`
	Patch      bool          `json:"patch"`
	Text       CDXAttachment `json:"attachment"`
	Url        string        `json:"url"`
}

// v1.2: existed
type CDXAttachment struct {
	ContentType string `json:"contentType"`
	Encoding    string `json:"encoding"`
	Content     string `json:"content"`
}

// v1.2: existed
// Note: "alg" is of type "hash-alg" which is a constrained `string` type
// Note: "content" is of type "hash-content" which is a constrained `string` type
type CDXHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// v1.2: was an anon. type
// v1.3: created
// Note: "oneOf": ["license", "expression"] is required
type CDXLicenseChoice struct {
	License    CDXLicense `json:"license"`
	Expression string     `json:"expression"`
}

// v1.2: was an anon. type
// v1.3: created
// Note: "oneOf": ["id", "name"] is required
type CDXLicense struct {
	Id   string        `json:"id"`
	Name string        `json:"name"`
	Text CDXAttachment `json:"text"`
	Url  string        `json:"url"`
}

// v1.2: existed
// TODO: GitHub PRs MAY have more than 1 commit (committer); CDX needs to account for this
type CDXCommit struct {
	Uid       string                `json:"uid"`
	Url       string                `json:"url"`
	Message   string                `json:"message"`
	Author    CDXIdentifiableAction `json:"author"`
	Committer CDXIdentifiableAction `json:"committer"`
}

// v1.2: existed
type CDXPatch struct {
	Type     string     `json:"type"`
	Diff     CDXDiff    `json:"diff"`
	Resolves []CDXIssue `json:"resolves"`
}

// v1.2: existed
// v1.3 "url" type changed from `string` (with constraints) to an "iri-reference"
type CDXDiff struct {
	Text CDXAttachment `json:"text"`
	Url  string        `json:"url"` // v1.3: type changed to "iri-reference"
}

// v1.2: existed
// Note: v1.2 Bug: there appears to be a bug in the 1.2 spec. where the type for
// "references" is declared an array of "no type" (it likely should be `string`)
// Not sure how a parser will treat this... perhaps as an `interface{}`?
// v1.3: fixed to be []string
type CDXIssue struct {
	Type        string    `json:"type"`
	Id          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Source      CDXSource `json:"source"`
	References  []string  `json:"references"` // v1.3: added missing `string` type
}

// v1.2: existed as anon. type
// Note: this is an anonymous type defined within "issue" defn. (i.e., "CDXIssue")
type CDXSource struct {
	Name string `json:"name"`
	Url  string `json:"url"`
}

// v1.2: existed
// TODO: We should suggest this be "deprecated" and instead add "timestamp" and
// other fields to OrganizationalContact (or similar)
// TODO: should have "signage" information (e.g., evidence, public key)
type CDXIdentifiableAction struct {
	Timestamp string `json:"timestamp"`
	Name      string `json:"name"`
	Email     string `json:"email"`
}

// v1.2: existed
// v1.3: added "hashes"
// v1.4: `Type` field: added value "release-notes" to enum.
type CDXExternalReference struct {
	Url     string    `json:"url"`
	Comment string    `json:"comment"`
	Type    string    `json:"type"`
	Hashes  []CDXHash `json:"hashes"` // v1.3: added
}

// v1.2: existed
// v1.4: "ref" and "dependsOn" became type "refType" which is a constrained `string`
type CDXDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

// v1.2: existed
// Note: "flow" is of type "dataFlow" which is a constrained `string` type
type CDXDataClassification struct {
	Flow           string `json:"flow"`
	Classification string `json:"classification"`
}

// v1.3: created "copyright" defn.
type CDXCopyright struct {
	Text string
}

// v1.3: created "componentEvidence" defn.
type CDXComponentEvidence struct {
	Licenses  []CDXLicense
	Copyright []CDXCopyright
}

// v1.3: created "compositions" defn.
// v1.4: added "signature"
// Note: "aggregate" is type `aggregateType` which is a constrained string
// TODO: Should not be plural
type CDXCompositions struct {
	Aggregate    string       `json:"aggregate"`
	Assemblies   []string     `json:"assemblies"`
	Dependencies []string     `json:"dependencies"`
	Signature    CDXSignature `json:"signature"` // v1.4: added
}

// v1.3: created "property" defn.
type CDXProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// v1.4: created "note" defn.
// Note: "locale" is of type "localeType" which is a constrained `string`
type CDXNote struct {
	Locale string        `json:"locale"`
	Text   CDXAttachment `json:"attachment"`
}

// v1.4: created "releaseNotes" defn.
// TODO: should be singular "releaseNote"
type CDXReleaseNotes struct {
	Type          string        `json:"type"`
	Title         string        `json:"title"`
	FeaturedImage string        `json:"featuredImage"`
	SocialImage   string        `json:"socialImage"`
	Description   string        `json:"description"`
	Timestamp     string        `json:"timestamp"`
	Aliases       []string      `json:"aliases"`
	Tags          []string      `json:"tags"`
	Resolves      []CDXIssue    `json:"resolves"`
	Notes         []CDXNote     `json:"notes"`
	Properties    []CDXProperty `json:"properties"`
}

// v1.4: created "releaseNotes" defn.
// Note: "url" is of type "iri-reference"
type CDXAdvisory struct {
	Title string `json:"title"`
	Url   string `json:"url"`
}

// v1.4: created "rating" defn.
// Note: "score" is of type "number" which should map to `float64`
// Note: "severity" is of type "severity" which is a constrained `string`
// Note: "method" is of type "scoreMethod" which is a constrained `string`
type CDXRating struct {
	// TODO: Source CDXVulnerabilitySource `json:"source"`
	Score         float64 `json:"score"`
	Severity      string  `json:"severity"`
	Method        string  `json:"method"`
	Vector        string  `json:"vector"`
	Justification string  `json:"justification"`
}

// v1.4: created "vulnerabilitySource" defn.
// Note: "url" is of type "string" (and not an "iri-reference")
// TODO: "url" SHOULD be an "iri-reference"
type CDXVulnerabilitySource struct {
	Url  string `json:"url"`
	Name string `json:"name"`
}

// v1.4: created "vulnerability" defn.
// Note: "bom-ref" is a "ref-type" which is a constrained `string`
// Note: "cwes" is a array of "cwe" which is a constrained `int`
type CDXVulnerability struct {
	BomRef string                 `json:"bom-ref"`
	Id     string                 `json:"id"`
	Source CDXVulnerabilitySource `json:"source"`
	// TODO: References []CDXReference `json:"references"` // an anon. type
	Ratings        []CDXRating   `json:"ratings"`
	Cwes           []int         `json:"cwes"`
	Description    string        `json:"description"`
	Detail         string        `json:"detail"`
	Recommendation string        `json:"recommendation"`
	Advisories     []CDXAdvisory `json:"advisories"`
	Created        string        `json:"created"`
	Published      string        `json:"published"`
	Updated        string        `json:"updated"`
	Credits        CDXCredit     `json:"credits"` // anon. type
	Tools          []CDXTool     `json:"tools"`
	Analysis       CDXAnalysis   `json:"analysis"` // anon. type
	Affects        []CDXAffect   `json:"affects"`  // anon. type
	Properties     []CDXProperty `json:"properties"`
	// v1.5 properties follow
	Rejected string `json:"rejected"` // v1.5: added
}

// v1.4: created "credit" defn. to represent the in-line, anon. type
// found in the "vulnerability" type defn.
// TODO: create top-level defn. for "credit" anon. type
type CDXCredit struct {
	Organizations []CDXOrganizationalEntity  `json:"organizations"`
	Individuals   []CDXOrganizationalContact `json:"individuals"`
}

// v1.4: created "analysis" def. to represent an in-line, anon. type
// defined in the "vulnerability" object defn.
// Note: "state" is an "impactAnalysisState" type which is a constrained enum. of type `string`
// Note: "justification" is an "impactAnalysisJustification" type which is a constrained enum. of type `string`
// TODO: create top-level defn. for "analysis" anon. type
// TODO: "response" is also "in-lined" as a constrained enum. of `string`, but SHOULD be declared at top-level
type CDXAnalysis struct {
	State         string   `json:"state"`
	Justification string   `json:"justification"`
	Response      []string `json:"response"` // anon. type
	Detail        string   `json:"detail"`
}

// v1.4: created "analysis" def. to represent an in-line, anon. type
// Note: This anon. "type" ONLY includes a single array of another in-line type
// TODO: create top-level defn. for "affect" anon. type
type CDXAffect struct {
	Versions []CDXVersionRange `json:"versions"` // anon. type
}

// v1.4: created "version" def. to represent an in-line, anon. type
// Note "version" is a top-level defn. that is a constrained `string` type
// Note "affectedStatus" is a top-level defn. that is an enum. of `string` type
// Note: Both "version" constrains strings to a min/mac (1, 1024) length
// this concept SHOULD APPLY to all free-form text entries (e.g., descriptive text)
// TODO: create top-level defn. for "versions" (a.k.a. "versionRange") anon. type (name TBD)
type CDXVersionRange struct {
	Version string `json:"version"`
	Range   string `json:"range"`
	Status  string `json:"status"`
}

// TODO: implement JSF schema
// https://github.com/CycloneDX/specification/blob/master/schema/jsf-0.82.schema.json
type CDXSignature struct {
	KeyType string `json:"keyType"`
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
