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

import (
	"sort"
)

type Normalizer interface {
	Normalize()
}

// TODO: Would like to use type reflection to "walk" a CDXBom{} type hierarchy,
// and normalize each element by calling its "Normalizer" interface IFF it is supported.
// For example:
// > if normalizeSupported(bom.Element) {
// >	bom.Element.Normalize()
// >}

// **NOTE** this method is a generic means to test for ANY named interface
func interfaceSupported[T any](i T, itfc interface{}) bool {
	if itfc != nil {
		_, ok := itfc.(T)
		return ok
	}
	return false
}

// This is a wrapper to test specifically for the Normalize interface
func normalizeSupported(itfc interface{}) bool {
	return interfaceSupported(Normalizer(nil), itfc)
}

// named BOM slice types
type CDXAnnotationsSlice []CDXAnnotation
type CDXComponentDataSlice []CDXComponentData
type CDXComponentsSlice []CDXComponent
type CDXDependenciesSlice []CDXDependency
type CDXExternalReferencesSlice []CDXExternalReference
type CDXHashesSlice []CDXHash
type CDXLicenseChoiceSlice []CDXLicenseChoice
type CDXLicensesSlice []CDXLicense // TODO: used in CDXComponentEvidence
type CDXPropertiesSlice []CDXProperty
type CDXReleaseNotesSlice []CDXReleaseNotes
type CDXServicesSlice []CDXService
type CDXVulnerabilitiesSlice []CDXVulnerability
type CDXFormulaSlice []CDXFormula

// ====================================================================
// Sort by (normalization) rules:
// ====================================================================
// 1. Required fields if they exist
// 1. Use pseudo-required field "bom-ref" when available
// 1. Using optional local identifiers or
// 1. Using combinations of identifying field values (towards 100% normalization)
// ====================================================================
// "Punch" list of future items:
// - TODO: track/limit depth of recursion (in "component", "service")
// ====================================================================

func (bom *CDXBom) Normalize() {
	// Sort: BOM Metadata
	if bom.Metadata != nil {
		bom.Metadata.Normalize()
	}

	// Sort: Components
	if bom.Components != nil {
		CDXComponentsSlice(*bom.Components).Normalize()
	}

	// Sort: Services
	if bom.Services != nil {
		CDXServicesSlice(*bom.Services).Normalize()
	}

	// Sort: Dependencies
	if bom.Dependencies != nil {
		CDXDependenciesSlice(*bom.Dependencies).Normalize()
	}

	// Sort: Vulnerabilities
	if bom.Vulnerabilities != nil {
		CDXVulnerabilitiesSlice(*bom.Vulnerabilities).Normalize()
	}

	// TODO: sort Compositions

	// TODO: sort Formulation
	if bom.Formulation != nil {
		CDXFormulaSlice(*bom.Formulation).Normalize()
	}

	// Sort: Annotations
	if bom.Annotations != nil {
		CDXAnnotationsSlice(*bom.Annotations).Normalize()
	}

	// Sort: ExternalReferences
	if bom.ExternalReferences != nil {
		CDXExternalReferencesSlice(*bom.ExternalReferences).Normalize()
	}

	// Sort: Properties
	if bom.Properties != nil {
		CDXPropertiesSlice(*bom.Properties).Normalize()
	}

	// TODO: Sort: Declarations (v1.6)
	// TODO: Sort: Definitions (v1.6)
}

// TODO: Sort Metadata object fields that are slices:
// Tools        interface{}                 `json:"tools,omitempty"`                               // v1.2: added.v1.5: "tools" is now an interface{}
// Authors      *[]CDXOrganizationalContact `json:"authors,omitempty"`
// Component    *CDXComponent               `json:"component,omitempty"`
// Manufacturer *CDXOrganizationalEntity    `json:"manufacture,omitempty"` // NOTE: Typo is in spec.
// Supplier     *CDXOrganizationalEntity    `json:"supplier,omitempty"`
// Lifecycles   *[]CDXLifecycle             `json:"lifecycles,omitempty"` // v1.5 added
func (pMetadata *CDXMetadata) Normalize() {
	if pMetadata != nil {
		metadata := *pMetadata

		// Sort: Component
		if metadata.Component != nil {
			metadata.Component.Normalize()
		}

		// Sort: Licenses
		if metadata.Licenses != nil {
			CDXLicenseChoiceSlice(*metadata.Licenses).Normalize()
		}

		// Sort: Properties
		if metadata.Properties != nil {
			CDXPropertiesSlice(*metadata.Properties).Normalize()
		}

		// TODO: Sort: Lifecycles
	}
}

func (component *CDXComponent) Normalize() {
	// Sort: Components
	// Note: The following method is recursive
	if component.Components != nil {
		CDXComponentsSlice(*component.Components).Normalize()
	}

	// Sort: Licenses
	if component.Licenses != nil {
		//sortSliceLicenseChoices(component.Licenses)
		CDXLicenseChoiceSlice(*component.Licenses).Normalize()
	}

	// Sort: Hashes
	if component.Hashes != nil {
		CDXHashesSlice(*component.Hashes).Normalize()
	}

	// Sort: Data
	if component.Data != nil {
		CDXComponentDataSlice(*component.Data).Normalize()
	}

	// Sort: ReleaseNotes
	if component.ReleaseNotes != nil {
		CDXReleaseNotesSlice(*component.ReleaseNotes).Normalize()
	}

	// Sort: ExternalReferences
	if component.ExternalReferences != nil {
		CDXExternalReferencesSlice(*component.ExternalReferences).Normalize()
	}

	// Sort: Properties
	if component.Properties != nil {
		CDXPropertiesSlice(*component.Properties).Normalize()
	}

	// TODO: Sort: Authors

	// TODO: Sort: Evidence

	// TODO: Sort: ModelCard

	// TODO: Sort Pedigree (i.e., its Ancestors, Dependents, etc.)

	// TODO: Sort: CryptoProperties (v1.6)

	// TODO: Sort: Tags (v1.6)
}

func (service *CDXService) Normalize() {
	// Sort: Services
	// Note: The following method is recursive
	if service.Services != nil {
		CDXServicesSlice(*service.Services).Normalize()
	}

	// Sort: Licenses
	if service.Licenses != nil {
		CDXLicenseChoiceSlice(*service.Licenses).Normalize()
	}

	// Sort: ReleaseNotes
	if service.ReleaseNotes != nil {
		CDXReleaseNotesSlice(*service.ReleaseNotes).Normalize()
	}

	// Sort: ExternalReferences
	if service.ExternalReferences != nil {
		CDXExternalReferencesSlice(*service.ExternalReferences).Normalize()
	}

	// Sort: Properties
	if service.Properties != nil {
		CDXPropertiesSlice(*service.Properties).Normalize()
	}

	// TODO: Sort: Endpoints

	// TODO: Sort: (Service) Data

	// TODO: Sort: Tags
}

func (slice CDXComponentsSlice) Normalize() {
	sort.Slice(slice, func(i, j int) bool {
		element1 := slice[i]
		element2 := slice[j]
		return comparatorComponent(element1, element2)
	})

	// Normalize() each entry in the Components slice
	// Note: this causes recursion as each "Component" type has a "Components" slice.
	for _, component := range slice {
		component.Normalize()
	}
}

func (slice CDXServicesSlice) Normalize() {
	sort.Slice(slice, func(i, j int) bool {
		element1 := slice[i]
		element2 := slice[j]
		return comparatorService(element1, element2)
	})

	// Normalize() each entry in the Service slice
	// Note: this causes recursion as each "Service" type has a "Services" slice.
	for _, component := range slice {
		component.Normalize()
	}
}

func (slice CDXVulnerabilitiesSlice) Normalize() {
	sort.Slice(slice, func(i, j int) bool {
		element1 := slice[i]
		element2 := slice[j]
		return comparatorVulnerability(element1, element2)
	})
}

func (slice CDXDependenciesSlice) Normalize() {
	sort.Slice(slice, func(i, j int) bool {
		element1 := slice[i]
		element2 := slice[j]
		return comparatorDependency(element1, element2)
	})

	// Normalize() each entry in the Dependency slice
	for _, dependency := range slice {
		dependency.Normalize()
	}
}

// TODO: sort the slice of "dependsOn"
func (dependency CDXDependency) Normalize() {
	if pDependsOn := dependency.DependsOn; pDependsOn != nil {
		slice := *pDependsOn
		// Note: this is a "string" sort
		sort.Slice(slice, func(i, j int) bool {
			return slice[i] < slice[j]
		})
	}
}

// TODO: Sort: the slices within the CDXComponentData (e.g., Contents,
// SensitiveData, Graphics (collection), Governance, etc. )
func (slice CDXComponentDataSlice) Normalize() {
	sort.Slice(slice, func(i, j int) bool {
		element1 := slice[i]
		element2 := slice[j]
		return comparatorComponentData(element1, element2)
	})
}

func (slice CDXLicenseChoiceSlice) Normalize() {
	sort.Slice(slice, func(i, j int) bool {
		element1 := slice[i]
		element2 := slice[j]
		return comparatorLicenseChoice(element1, element2)
	})
}

func (slice CDXAnnotationsSlice) Normalize() {
	sort.Slice(slice, func(i, j int) bool {
		element1 := slice[i]
		element2 := slice[j]
		return comparatorAnnotation(element1, element2)
	})
}

func (slice CDXExternalReferencesSlice) Normalize() {
	sort.Slice(slice, func(i, j int) bool {
		element1 := slice[i]
		element2 := slice[j]
		return comparatorExternalReference(element1, element2)
	})
}

func (slice CDXPropertiesSlice) Normalize() {
	sort.Slice(slice, func(i, j int) bool {
		element1 := slice[i]
		element2 := slice[j]
		return comparatorProperty(element1, element2)
	})
}

func (slice CDXReleaseNotesSlice) Normalize() {
	sort.Slice(slice, func(i, j int) bool {
		element1 := slice[i]
		element2 := slice[j]
		return comparatorReleaseNotes(element1, element2)
	})
}

func (slice CDXHashesSlice) Normalize() {
	sort.Slice(slice, func(i, j int) bool {
		element1 := slice[i]
		element2 := slice[j]
		return comparatorHash(element1, element2)
	})
}

func (slice CDXFormulaSlice) Normalize() {
	sort.Slice(slice, func(i, j int) bool {
		element1 := slice[i]
		element2 := slice[j]
		return comparatorFormula(element1, element2)
	})

	// TODO: Sort: workflows (tasks), components, services, properties, etc.
	// Normalize() each entry in the Dependency slice
	for _, formula := range slice {
		formula.Normalize()
	}
}

func (formula *CDXFormula) Normalize() {
	// Sort: Components
	// Note: The following method is recursive
	if formula.Components != nil {
		CDXComponentsSlice(*formula.Components).Normalize()
	}

	// Sort: Services
	// Note: The following method is recursive
	if formula.Services != nil {
		CDXServicesSlice(*formula.Services).Normalize()
	}
}

// ====================================================================
// Struct comparators
// ====================================================================

// Use required fields: "type", "name"
// Use optional identity fields: "purl", "cpe", "swid.TagId"
// Sort by the optional field "bom-ref" as this is pseudo-required if
// slice elements contain duplicates with both "name" and "type".
func comparatorComponent(element1 CDXComponent, element2 CDXComponent) bool {
	// sort by required field(s)
	if element1.Type != element2.Type {
		return element1.Type < element2.Type
	}
	if element1.Name != element2.Name {
		return element1.Name < element2.Name
	}
	// sort by pseudo-required field "bom-ref"
	if element1.BOMRef != nil && element2.BOMRef != nil {
		return *element1.BOMRef < *element2.BOMRef
	}
	// Other optional identifiers
	if element1.Cpe != element2.Cpe {
		return element1.Cpe < element2.Cpe
	}
	if element1.Purl != element2.Purl {
		return element1.Purl < element2.Purl
	}
	if element1.Swid != nil && element2.Swid != nil {
		Swid1 := *element1.Swid
		Swid2 := *element2.Swid
		return Swid1.TagId < Swid2.TagId
	}
	// Other "tie breakers"
	if element1.Version != element2.Version {
		return element1.Version < element2.Version
	}
	// default: preserve existing order
	return true
}

func comparatorService(element1 CDXService, element2 CDXService) bool {
	// sort by required field(s): "name"
	if element1.Name != element2.Name {
		return element1.Name < element2.Name
	}
	// sort by pseudo-required field "bom-ref"
	if element1.BOMRef != nil && element2.BOMRef != nil {
		return *element1.BOMRef < *element2.BOMRef
	}
	// sort by other "tie breakers"
	if element1.Version != element2.Version {
		return element1.Version < element2.Version
	}
	// default: preserve existing order
	return true
}

// NOTE: there are NO required fields in the vulnerability object's data schema
// sort by we will sort using fields that may contain local, identifying values
// TODO sort "advisories", "cwes" and "ratings.source" and "affects.ref"
func comparatorVulnerability(element1 CDXVulnerability, element2 CDXVulnerability) bool {
	// sort by pseudo-required field "bom-ref"
	if element1.BOMRef != nil && element2.BOMRef != nil {
		return *element1.BOMRef < *element2.BOMRef
	}
	// optional identifiers: "id"
	if element1.Id != element2.Id {
		return element1.Id < element2.Id
	}
	// other optional "tie breakers": "Source.Name", "Source.Url"
	if element1.Source != nil && element2.Source != nil {
		source1 := *element1.Source
		source2 := *element2.Source
		if source1.Name != source2.Name {
			return source1.Name < source2.Name
		}
		if source1.Url != source2.Url {
			return source1.Url < source2.Url
		}
	}
	// default: preserve existing order
	return true
}

func comparatorDependency(element1 CDXDependency, element2 CDXDependency) bool {
	// guard against invalid pointers to (required) elements
	if element1.Ref != nil && element2.Ref != nil {
		// sort by required field: "ref"
		return *element1.Ref < *element2.Ref
	}
	// default: preserve existing order
	return true
}

func comparatorComponentData(element1 CDXComponentData, element2 CDXComponentData) bool {
	// sort by required fields: "type"
	if element1.Type != element2.Type {
		return element1.Type < element2.Type
	}
	// sort using combinations of identifying field values: "name"
	return element1.Name < element2.Name
}

// TODO: use "bom-ref" as pseudo-required (if present)
// TODO: use "text", "url" as "tie-breakers"
// Text       *CDXAttachment `json:"text,omitempty"`
// Url        string         `json:"url,omitempty"`
// BOMRef     *CDXRefType    `json:"bom-ref,omitempty"`    // v1.5: added
// Licensing  *CDXLicensing  `json:"licensing,omitempty"`  // v1.5: added
// Properties *[]CDXProperty `json:"properties,omitempty"` // v1.5: added
func comparatorLicenseChoice(element1 CDXLicenseChoice, element2 CDXLicenseChoice) bool {
	// Option 1: "CDXLicense" object is provided
	// guard against invalid pointers to (required) elements
	if element1.License != nil && element2.License != nil {
		license1 := *element1.License
		license2 := *element2.License
		// TODO: test for "id" vs. "name" and assure "id" entries appear first
		// "oneOf": ["id", "name"] is required
		if license1.Id != license2.Id {
			return license1.Id < license2.Id
		}
		return license1.Name < license2.Name
	}
	// Option 2: "CDXLicenseExpression" is provided
	// Expression      string      `json:"expression,omitempty"` REQUIRED
	// Acknowledgement string      `json:"acknowledgement,omitempty"` // v1.6: added
	// BOMRef          *CDXRefType `json:"bom-ref,omitempty"`
	return element1.Expression < element2.Expression
}

func comparatorHash(element1 CDXHash, element2 CDXHash) bool {
	// sort by required fields: "alg", "content"
	if element1.Alg != element2.Alg {
		return element1.Alg < element2.Alg
	}
	return element1.Content < element2.Content
}

// TODO sort "subjects", "annotator"
func comparatorAnnotation(element1 CDXAnnotation, element2 CDXAnnotation) bool {
	// sort by required fields: "timestamp", "text"
	if element1.Timestamp != element2.Timestamp {
		return element1.Timestamp < element2.Timestamp
	}
	return element1.Text < element2.Text
}

// NOTE: The name is plural to match the current struct name (and perhaps json schema name)
func comparatorReleaseNotes(element1 CDXReleaseNotes, element2 CDXReleaseNotes) bool {
	// sort by required fields: "type"
	if element1.Type != element2.Type {
		return element1.Type < element2.Type
	}
	// sort by using combinations of identifying field values: "title", "timestamp"
	if element1.Title != element2.Title {
		return element1.Title < element2.Title
	}
	return element1.Timestamp < element2.Timestamp
}

func comparatorExternalReference(element1 CDXExternalReference, element2 CDXExternalReference) bool {
	// sort by required fields: "type", "url"
	if element1.Type != element2.Type {
		return element1.Type < element2.Type
	}
	return element1.Url < element2.Url
}

func comparatorProperty(element1 CDXProperty, element2 CDXProperty) bool {
	// sort by required fields: "name", "value"
	if element1.Name != element2.Name {
		return element1.Name < element2.Name
	}
	return element1.Value < element2.Value
}

func comparatorFormula(element1 CDXFormula, element2 CDXFormula) bool {
	// sort by pseudo-required field "bom-ref"
	if element1.BOMRef != nil && element2.BOMRef != nil {
		return *element1.BOMRef < *element2.BOMRef
	}
	// default: preserve existing order
	return true
}

func comparatorWorkflow(element1 CDXWorkflow, element2 CDXWorkflow) bool {
	// sort by required field "bom-ref"
	if element1.BOMRef != nil && element2.BOMRef != nil {
		return *element1.BOMRef < *element2.BOMRef
	}
	// default: preserve existing order
	return true
}
