// SPDX-License-Identifier: Apache-2.0
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

import "golang.org/x/exp/slices"

// -------------------
// Resources
// -------------------

// resource types
const (
	RESOURCE_TYPE_DEFAULT   = "" // i.e., all resource types
	RESOURCE_TYPE_COMPONENT = "component"
	RESOURCE_TYPE_SERVICE   = "service"
)

var VALID_RESOURCE_TYPES = []string{RESOURCE_TYPE_DEFAULT, RESOURCE_TYPE_COMPONENT, RESOURCE_TYPE_SERVICE}

func IsValidResourceType(value string) bool {
	return slices.Contains(VALID_RESOURCE_TYPES, value)
}

// TODO: need to strip `-` from `bom-ref` for where filter
// To be clear, we need the "json:" annotations to enable "where" filter
// "key=value" matches when hashing resources since we apply it to a
// JSON map:
//
//	mapResourceInfo, _ := utils.ConvertStructToMap(resourceInfo)
//	match, _ = whereFilterMatch(mapResourceInfo, whereFilters)
//
// If we could normalize to lowercase and remove "-" chars we may not
// need to use any JSON annotations.
// Please note that the JSON annotations MUST match those declared by
// the CDX types CDXComponent and CDXService.
type CDXResourceInfo struct {
	IsRoot         bool
	ResourceType   string `json:"resource-type"`
	Group          string `json:"group"`
	Name           string `json:"name"`
	Version        string `json:"version"`
	Description    string `json:"description"`
	BOMRef         string `json:"bom-ref"`
	NumberLicenses int    `json:"number-licenses"`
	Properties     *[]CDXProperty
	Component      CDXComponent
	Service        CDXService
	HasLicense     bool
}

// -------------------
// Components
// -------------------
// TODO: Authors (*[]CDXOrganizationalContact)
// TODO: HasHashes, HasLicenses, HasPedigree, HasEvidence, HasComponents, HasReleaseNotes
// TODO: HasModelCard, HasData, HasTags, HasSignature (*JSFSignature)
// TODO: OmniborId (new), Swhid (new)
type CDXComponentInfo struct {
	CDXResourceInfo
	Type             string `json:"type"`
	SupplierName     string `json:"supplier-name"`
	SupplierUrl      string `json:"supplier-url"`
	ManufacturerName string `json:"manufacturer-name"`
	ManufacturerUrl  string `json:"manufacturer-url"`
	Publisher        string `json:"publisher"`
	Copyright        string `json:"copyright"`
	Cpe              string `json:"cpe"`
	Purl             string `json:"purl"`
	SwidTagId        string `json:"swid-tag-id"`
	NumberHashes     int    `json:"number-hashes"`
	HasHash          bool   `json:"has-hash"`
	HasPedigree      bool   `json:"has-pedigree"`
	//Scope            string `json:"scope"`
}

func NewComponentInfo(cdxComponent CDXComponent) (componentInfo *CDXComponentInfo) {
	componentInfo = new(CDXComponentInfo)
	componentInfo.MapCDXComponentData(cdxComponent)
	return
}

// TODO: flag any component w/o a license
func (componentInfo *CDXComponentInfo) MapCDXComponentData(cdxComponent CDXComponent) {
	componentInfo.ResourceType = RESOURCE_TYPE_COMPONENT
	componentInfo.Component = cdxComponent
	componentInfo.Name = cdxComponent.Name
	if cdxComponent.BOMRef != nil {
		ref := *cdxComponent.BOMRef
		componentInfo.BOMRef = ref.String()
	}
	componentInfo.Group = cdxComponent.Group
	componentInfo.Description = cdxComponent.Description
	componentInfo.Version = cdxComponent.Version
	componentInfo.Properties = cdxComponent.Properties

	if cdxComponent.Supplier != nil {
		componentInfo.SupplierName = cdxComponent.Supplier.Name
		// NOTE: if multiple URLs exist, we only display the first
		if len(cdxComponent.Supplier.Url) > 0 {
			componentInfo.SupplierUrl = cdxComponent.Supplier.Url[0]
		}
	}

	componentInfo.Publisher = cdxComponent.Publisher

	// Manufacturer field added v1.6
	if cdxComponent.Manufacturer != nil {
		componentInfo.ManufacturerName = cdxComponent.Manufacturer.Name
		// NOTE: if multiple URLs exist, we only display the first
		if len(cdxComponent.Manufacturer.Url) > 0 {
			componentInfo.ManufacturerUrl = cdxComponent.Manufacturer.Url[0]
		}
	}

	// Mark the component has having no licenses declared (at all)
	// TODO: Need to further mark ones that have licenses array, yet no valid (e.g., empty) license
	if cdxComponent.Licenses != nil {
		numLicenses := len(*cdxComponent.Licenses)
		if numLicenses > 0 {
			componentInfo.HasLicense = true
			componentInfo.NumberLicenses = numLicenses
		}
	}

	if cdxComponent.Hashes != nil {
		numHashes := len(*cdxComponent.Hashes)
		if numHashes > 0 {
			componentInfo.HasHash = true
			componentInfo.NumberHashes = numHashes
		}
	}

	// Component-specific fields/properties
	componentInfo.Type = cdxComponent.Type
	componentInfo.Copyright = cdxComponent.Copyright
	componentInfo.Purl = cdxComponent.Purl
	componentInfo.Cpe = cdxComponent.Cpe
	if cdxComponent.Swid != nil {
		componentInfo.SwidTagId = cdxComponent.Swid.TagId
	}
	if cdxComponent.Pedigree != nil && *cdxComponent.Pedigree != (CDXPedigree{}) {
		componentInfo.HasPedigree = true
	}
}

// -------------------
// Services
// -------------------
// TODO: HasServices, HasEndpoints
// TODO: HasLicenses, HasReleaseNotes, HasData, HasTags, HasSignature (*JSFSignature)
// TODO: HasProperties, HasExternalRefs
type CDXServiceInfo struct {
	CDXResourceInfo
	ProviderName   string `json:"provider-name"`
	ProviderUrl    string `json:"provider-url"`
	Authenticated  bool   `json:"authenticated,omitempty"`
	XTrustBoundary bool   `json:"x-trust-boundary,omitempty"`
	TrustZone      string `json:"trustZone,omitempty"`
}

func NewServiceInfo(cdxService CDXService) (serviceInfo *CDXServiceInfo) {
	serviceInfo = new(CDXServiceInfo)
	serviceInfo.MapCDXServiceData(cdxService)
	return
}

func (serviceInfo *CDXServiceInfo) MapCDXServiceData(cdxService CDXService) {
	serviceInfo.ResourceType = RESOURCE_TYPE_SERVICE
	serviceInfo.Service = cdxService
	serviceInfo.Name = cdxService.Name
	if cdxService.BOMRef != nil {
		serviceInfo.BOMRef = cdxService.BOMRef.String()
	}
	serviceInfo.Group = cdxService.Group
	serviceInfo.Description = cdxService.Description
	serviceInfo.Version = cdxService.Version
	if cdxService.Provider != nil {
		serviceInfo.ProviderName = cdxService.Provider.Name
		// NOTE: if multiple URLs exist, we only display the first
		if len(cdxService.Provider.Url) > 0 {
			serviceInfo.ProviderUrl = cdxService.Provider.Url[0]
		}
	}
	serviceInfo.Properties = cdxService.Properties
	// Mark the service has having no licenses declared (at all)
	// TODO: Need to further mark ones that have licenses array, yet no valid (e.g., empty) license
	if cdxService.Licenses != nil {
		numLicenses := len(*cdxService.Licenses)
		if numLicenses > 0 {
			serviceInfo.HasLicense = true
			serviceInfo.NumberLicenses = numLicenses
		}
	}
}

// -------------------
// Vulnerabilities
// -------------------

// default / "empty" values
const (
	VULN_DATE_EMPTY           = "none"
	VULN_ANALYSIS_STATE_EMPTY = "UNDEFINED"
	VULN_RATING_EMPTY         = "none"
)

// This data consolidates nested information into a flattened version more suitable for report listings
type VulnerabilityInfo struct {
	Id                    string                 `json:"id"`
	BOMRef                string                 `json:"bom-ref"`
	CvssSeverity          []string               `json:"cvss-severity"`
	Created               string                 `json:"created"`
	Published             string                 `json:"published"`
	Updated               string                 `json:"updated"`
	Rejected              string                 `json:"rejected"`
	Description           string                 `json:"description"`
	SourceUrl             string                 `json:"source-url"`
	SourceName            string                 `json:"source-name"`
	AnalysisState         string                 `json:"analysis-state"`
	AnalysisJustification string                 `json:"analysis-justification"`
	AnalysisResponse      []string               `json:"analysis-response"`
	CweIds                []string               `json:"cwe-ids"`
	Source                CDXVulnerabilitySource `json:"source"`
	Vulnerability         CDXVulnerability
}

// -------------------
// Licenses
// -------------------

// LicenseChoice - Choice type
const (
	LC_TYPE_INVALID = iota
	LC_TYPE_ID
	LC_TYPE_NAME
	LC_TYPE_EXPRESSION
)

// LicenseChoice - corresponding (name) values for license choice types
const (
	LC_VALUE_INVALID    = "invalid"
	LC_VALUE_ID         = "id"
	LC_VALUE_NAME       = "name"
	LC_VALUE_EXPRESSION = "expression"
)

// Declare a fixed-sized array for LC type name indexed lookup
// Note: this is a "Composite Literal" which forces an array of string that
// matches the size of the declaration
var arrayLicenseTypeNames = [...]string{LC_VALUE_INVALID, LC_VALUE_ID, LC_VALUE_NAME, LC_VALUE_EXPRESSION}

const (
	LC_LOC_UNKNOWN = iota
	LC_LOC_METADATA_COMPONENT
	LC_LOC_METADATA
	LC_LOC_COMPONENTS
	LC_LOC_SERVICES
)

var mapLicenseLocationNames = map[int]string{
	LC_LOC_UNKNOWN:            "unknown",
	LC_LOC_METADATA_COMPONENT: "metadata.component",
	LC_LOC_METADATA:           "metadata.licenses",
	LC_LOC_COMPONENTS:         "components",
	LC_LOC_SERVICES:           "services",
}

// Note: the "License" property is used as hashmap key
// NOTE: CDXRefType is a named `string` type as of v1.5
type LicenseInfo struct {
	UsagePolicy            string           `json:"usage-policy"`
	LicenseChoiceTypeValue int              `json:"license-type-value"`
	LicenseChoiceType      string           `json:"license-type"`
	License                string           `json:"license"`
	ResourceName           string           `json:"resource-name"`
	BOMRef                 CDXRefType       `json:"bom-ref"`
	BOMLocationValue       int              `json:"bom-location-value"`
	BOMLocation            string           `json:"bom-location"`
	LicenseChoice          CDXLicenseChoice // Do not marshal
	Policy                 LicensePolicy    // Do not marshal
	Component              CDXComponent     // Do not marshal
	Service                CDXService       // Do not marshal
	ExtendedLicenseInfo
}

type ExtendedLicenseInfo struct {
	LicenseId              string `json:"license-id"`
	LicenseName            string `json:"license-name"`
	LicenseExpression      string `json:"license-expression"`
	LicenseUrl             string `json:"license-url"`
	LicenseTextEncoding    string `json:"license-text-encoding"`
	LicenseTextContentType string `json:"license-text-content-type"`
	LicenseTextContent     string `json:"license-text-content"`
}

func NewLicenseInfoFromComponent(cdxComponent CDXComponent, licenseChoice CDXLicenseChoice, location int) (licenseInfo *LicenseInfo) {
	licenseInfo = new(LicenseInfo)
	licenseInfo.BOMLocationValue = location
	licenseInfo.MapCDXLicenseFromComponent(cdxComponent, licenseChoice)
	return
}

// TODO: flag any component or service w/o a license
func (licenseInfo *LicenseInfo) MapCDXLicenseFromComponent(cdxComponent CDXComponent, cdxLicenseChoice CDXLicenseChoice) {
	licenseInfo.Component = cdxComponent
	licenseInfo.ResourceName = cdxComponent.Name
	licenseInfo.LicenseChoice = cdxLicenseChoice
	if cdxComponent.BOMRef != nil {
		licenseInfo.BOMRef = *cdxComponent.BOMRef
	}
}

func NewLicenseInfoFromService(cdxService CDXService, licenseChoice CDXLicenseChoice, location int) (licenseInfo *LicenseInfo) {
	licenseInfo = new(LicenseInfo)
	licenseInfo.BOMLocationValue = location
	licenseInfo.MapCDXLicenseFromService(cdxService, licenseChoice)
	return
}

func (licenseInfo *LicenseInfo) MapCDXLicenseFromService(cdxService CDXService, cdxLicenseChoice CDXLicenseChoice) {
	licenseInfo.Service = cdxService
	licenseInfo.LicenseChoice = cdxLicenseChoice
	licenseInfo.ResourceName = cdxService.Name
	if cdxService.BOMRef != nil {
		licenseInfo.BOMRef = *cdxService.BOMRef
	}
}

func (licenseInfo *LicenseInfo) SetLicenseChoiceTypeValue(value int) {
	licenseInfo.LicenseChoiceTypeValue = value
	licenseInfo.LicenseChoiceType = GetLicenseChoiceTypeName(value)
}

// TODO: look to remove once we uniformly use get/set methods on structure fields
func GetLicenseChoiceLocationName(value int) (name string) {
	if _, ok := mapLicenseLocationNames[value]; ok {
		name = mapLicenseLocationNames[value]
	} else {
		name = mapLicenseLocationNames[LC_TYPE_INVALID]
		getLogger().Warningf("invalid license choice location value (out of range): %v", value)
	}
	return
}

// TODO: look to remove once we uniformly use get/set methods on structure fields
func GetLicenseChoiceTypeName(value int) (name string) {
	if value < len(arrayLicenseTypeNames) {
		name = arrayLicenseTypeNames[value]
	} else {
		name = arrayLicenseTypeNames[LC_TYPE_INVALID]
		getLogger().Warningf("invalid license choice type value (out of range): %v", value)
	}
	return
}
