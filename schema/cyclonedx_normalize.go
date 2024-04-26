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

	"github.com/google/uuid"
)

// named BOM slice types
type CDXAnnotationSlice []CDXAnnotation
type CDXComponentDataSlice []CDXComponentData
type CDXComponentSlice []CDXComponent
type CDXCompositionSlice []CDXCompositions
type CDXDependencySlice []CDXDependency
type CDXExternalReferenceSlice []CDXExternalReference
type CDXHashSlice []CDXHash
type CDXLicenseChoiceSlice []CDXLicenseChoice
type CDXLicenseSlice []CDXLicense // TODO: used in CDXComponentEvidence
type CDXLifecycleSlice []CDXLifecycle
type CDXOrganizationalContactSlice []CDXOrganizationalContact
type CDXOrganizationalEntitySlice []CDXOrganizationalEntity
type CDXPropertySlice []CDXProperty
type CDXRefLinkTypeSlice []CDXRefLinkType
type CDXReleaseNotesSlice []CDXReleaseNotes
type CDXServiceSlice []CDXService
type CDXVersionRangeSlice []CDXVersionRange

// ====================================================================
// Normalizer Interface (and helpers)
// ====================================================================
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
func NormalizeSupported(itfc interface{}) bool {
	return interfaceSupported(Normalizer(nil), itfc)
}

func IsValidUUID(u string) bool {
	_, err := uuid.Parse(u)
	return err == nil
}

// ====================================================================
// Normalization (i.e., "sort by") rules:
// ====================================================================
// 1. Sort by: Required fields if they exist ("id" values, author order)
// >> WRONG: 1. Sort by: The pseudo-required field "bom-ref" when available (a BOM-unique ID)
// 1. Sort by: Using optional struct-local, or domain identifiers (e.g., SPDXID) or
// 1. Sort by: Using combinations of identifying field values (towards 100% normalization)
// ====================================================================
// "Punch" list of future items:
// - TODO: track/limit depth of recursion (in "component", "service")
// ====================================================================

// ====================================================================
// Struct Normalizers
// ====================================================================
func (bom *CDXBom) Normalize() {
	// Sort: BOM Metadata
	if bom.Metadata != nil {
		bom.Metadata.Normalize()
	}
	// Sort: Components
	if bom.Components != nil {
		CDXComponentSlice(*bom.Components).Normalize()
	}
	// Sort: Services
	if bom.Services != nil {
		CDXServiceSlice(*bom.Services).Normalize()
	}
	// Sort: Dependencies
	if bom.Dependencies != nil {
		CDXDependencySlice(*bom.Dependencies).Normalize()
	}
	// Sort: Vulnerabilities
	if bom.Vulnerabilities != nil {
		CDXVulnerabilitySlice(*bom.Vulnerabilities).Normalize()
	}
	// Sort Formulation
	if bom.Formulation != nil {
		CDXFormulaSlice(*bom.Formulation).Normalize()
	}
	// Sort: Annotations
	if bom.Annotations != nil {
		CDXAnnotationSlice(*bom.Annotations).Normalize()
	}
	// Sort: ExternalReferences
	if bom.ExternalReferences != nil {
		CDXExternalReferenceSlice(*bom.ExternalReferences).Normalize()
	}
	// Sort: Properties
	if bom.Properties != nil {
		CDXPropertySlice(*bom.Properties).Normalize()
	}
	// TODO: Sort Compositions
	// TODO: Sort: Declarations (v1.6)
	// TODO: Sort: Definitions (v1.6)
}

func (component *CDXComponent) Normalize() {
	// Sort: Components
	// Note: The following method is recursive
	if component.Components != nil {
		CDXComponentSlice(*component.Components).Normalize()
	}
	// Sort: Licenses
	if component.Licenses != nil {
		CDXLicenseChoiceSlice(*component.Licenses).Normalize()
	}
	// Sort: Hashes
	if component.Hashes != nil {
		CDXHashSlice(*component.Hashes).Normalize()
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
		CDXExternalReferenceSlice(*component.ExternalReferences).Normalize()
	}
	// Sort: Properties
	if component.Properties != nil {
		CDXPropertySlice(*component.Properties).Normalize()
	}
	// Sort: Authors (v1.6)
	if component.Authors != nil {
		CDXOrganizationalContactSlice(*component.Authors).Normalize()
	}
	// Sort: Tags (i.e., an array of "string") (v1.6)
	if component.Tags != nil {
		sort.Strings(*component.Tags)
	}
	// TODO: Sort: Evidence
	// TODO: Sort: ModelCard
	// TODO: Sort: Pedigree (i.e., its Ancestors, Dependents, etc.)
	// TODO: Sort: CryptoProperties (v1.6)
}

func (composition *CDXCompositions) Normalize() {
	// Sort: Assemblies
	if composition.Assemblies != nil {
		// Note: "Assembly" is really  OneOf: "refLinkType" or "bomLinkElementType"
		// BOTH of which map to "string" (thankfully for now)
		sort.Strings(*composition.Assemblies)
	}
	// Sort: Dependencies
	if composition.Dependencies != nil {
		sort.Strings(*composition.Dependencies)
	}
	// Sort: Vulnerabilities
	if composition.Vulnerabilities != nil {
		CDXVulnerabilitySlice(*composition.Vulnerabilities).Normalize()
	}
}

func (dependency CDXDependency) Normalize() {
	if dependency.DependsOn != nil {
		CDXRefLinkTypeSlice(*dependency.DependsOn).Normalize()
	}
}

func (license CDXLicense) Normalize() {
	// TODO: Sort: Licensing  *CDXLicensing
	// Sort: Properties
	if license.Properties != nil {
		CDXPropertySlice(*license.Properties).Normalize()
	}
	if license.Licensing != nil {
		license.Licensing.Normalize()
	}
}

func (licenseChoice CDXLicenseChoice) Normalize() {
	// Sort: License (slices within)
	if licenseChoice.License != nil {
		licenseChoice.License.Normalize()
	}
}

func (licensing CDXLicensing) Normalize() {
	// Sort: AltIds
	if licensing.AltIds != nil {
		sort.Strings(*licensing.AltIds)
	}
	// Sort: LicenseTypes
	if licensing.LicenseTypes != nil {
		sort.Strings(*licensing.LicenseTypes)
	}
}

// TODO: Sort Metadata object fields that are slices:
// Tools        interface{}                 `json:"tools,omitempty"`      // v1.2: added.v1.5: "tools" is now an interface{}
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
			CDXPropertySlice(*metadata.Properties).Normalize()
		}
		// Sort: Authors
		if metadata.Authors != nil {
			CDXOrganizationalContactSlice(*metadata.Authors).Normalize()
		}
		// Sort: Lifecycles
		if metadata.Lifecycles != nil {
			CDXLifecycleSlice(*metadata.Lifecycles).Normalize()
		}
	}
}

func (entity *CDXOrganizationalEntity) Normalize() {
	// Sort: Contact(s)
	if entity.Contact != nil {
		CDXOrganizationalContactSlice(*entity.Contact).Normalize()
	}
}

func (service *CDXService) Normalize() {
	// Sort: Services
	// Note: The following method is recursive
	if service.Services != nil {
		CDXServiceSlice(*service.Services).Normalize()
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
		CDXExternalReferenceSlice(*service.ExternalReferences).Normalize()
	}
	// Sort: Properties
	if service.Properties != nil {
		CDXPropertySlice(*service.Properties).Normalize()
	}
	// Sort: Endpoints (i.e., an array of "string")
	if service.Endpoints != nil {
		sort.Strings(*service.Endpoints)
	}
	// Sort: Tags (i.e., an array of "string") (v1.6)
	if service.Tags != nil {
		sort.Strings(*service.Tags)
	}
	// TODO: Sort: (Service) Data
}

// ====================================================================
// Slice Normalizers
// ====================================================================

func (slice CDXAnnotationSlice) Normalize() {
	sort.Slice(slice, func(i, j int) bool {
		element1 := slice[i]
		element2 := slice[j]
		return comparatorAnnotation(element1, element2)
	})
}

func (slice CDXComponentSlice) Normalize() {
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

// TODO: Sort: the slices within the CDXComponentData (e.g., Contents,
// SensitiveData, Graphics (collection), Governance, etc. )
func (slice CDXComponentDataSlice) Normalize() {
	sort.Slice(slice, func(i, j int) bool {
		element1 := slice[i]
		element2 := slice[j]
		return comparatorComponentData(element1, element2)
	})
}

func (slice CDXCompositionSlice) Normalize() {
	sort.Slice(slice, func(i, j int) bool {
		element1 := slice[i]
		element2 := slice[j]
		return comparatorComposition(element1, element2)
	})

	for _, composition := range slice {
		composition.Normalize()
	}
}

func (slice CDXDependencySlice) Normalize() {
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

func (slice CDXExternalReferenceSlice) Normalize() {
	sort.Slice(slice, func(i, j int) bool {
		element1 := slice[i]
		element2 := slice[j]
		return comparatorExternalReference(element1, element2)
	})
}

func (slice CDXLicenseChoiceSlice) Normalize() {
	sort.Slice(slice, func(i, j int) bool {
		element1 := slice[i]
		element2 := slice[j]
		return comparatorLicenseChoice(element1, element2)
	})

	// Sort LicenseChoice elements
	for _, licenseChoice := range slice {
		licenseChoice.Normalize()
	}
}

func (slice CDXLifecycleSlice) Normalize() {
	sort.Slice(slice, func(i, j int) bool {
		element1 := slice[i]
		element2 := slice[j]
		return comparatorLifecycle(element1, element2)
	})
}

func (slice CDXHashSlice) Normalize() {
	sort.Slice(slice, func(i, j int) bool {
		element1 := slice[i]
		element2 := slice[j]
		return comparatorHash(element1, element2)
	})
}

func (slice CDXOrganizationalContactSlice) Normalize() {
	sort.Slice(slice, func(i, j int) bool {
		element1 := slice[i]
		element2 := slice[j]
		return comparatorOrganizationalContact(element1, element2)
	})
}

func (slice CDXOrganizationalEntitySlice) Normalize() {
	sort.Slice(slice, func(i, j int) bool {
		element1 := slice[i]
		element2 := slice[j]
		return comparatorOrganizationalEntity(element1, element2)
	})

	// Sort the contents of the CDXOrganizationalEntity (i.e., Contact(s))
	for _, entity := range slice {
		entity.Normalize()
	}
}

func (slice CDXPropertySlice) Normalize() {
	sort.Slice(slice, func(i, j int) bool {
		element1 := slice[i]
		element2 := slice[j]
		return comparatorProperty(element1, element2)
	})
}

func (slice CDXRefLinkTypeSlice) Normalize() {
	sort.Slice(slice, func(i, j int) bool {
		element1 := slice[i]
		element2 := slice[j]
		return comparatorRefLinkType(element1, element2)
	})
}

func (slice CDXReleaseNotesSlice) Normalize() {
	sort.Slice(slice, func(i, j int) bool {
		element1 := slice[i]
		element2 := slice[j]
		return comparatorReleaseNotes(element1, element2)
	})
}

func (slice CDXServiceSlice) Normalize() {
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

func (slice CDXVersionRangeSlice) Normalize() {
	sort.Slice(slice, func(i, j int) bool {
		element1 := slice[i]
		element2 := slice[j]
		return comparatorVersionRange(element1, element2)
	})
}

// ====================================================================
// Struct comparators
// ====================================================================

// TODO sort "subjects", "annotator"
func comparatorAnnotation(element1 CDXAnnotation, element2 CDXAnnotation) bool {
	// sort by required fields: "timestamp", "text"
	if element1.Timestamp != element2.Timestamp {
		return element1.Timestamp < element2.Timestamp
	}
	return element1.Text < element2.Text
}

func comparatorBOMRefType(element1 CDXRefType, element2 CDXRefType) bool {
	// NOTE: we do not want to use "bom-def" if it is randomly generated UUID
	// Even if it is an ID like a Package URL (pURL), other IDs SHOULD
	// be used for "sort" prior to relying upon it in the "bom-ref" field.
	if IsValidUUID(element1.String()) || IsValidUUID(element2.String()) {
		return true
	}
	// Note: this is a basic "string" comparison
	return comparatorRefType(element1, element2)
}

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
	// sort by (sometimes an identifier): "bom-ref"
	if element1.BOMRef != nil && element2.BOMRef != nil {
		return comparatorBOMRefType(*element1.BOMRef, *element2.BOMRef)
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

func comparatorComposition(element1 CDXCompositions, element2 CDXCompositions) bool {
	// sort by required field "aggregate"
	if element1.Aggregate != element2.Aggregate {
		return element1.Aggregate < element2.Aggregate
	}
	// TODO: "tie-breakers": "signature"?
	// sort by (sometimes an identifier): "bom-ref"
	if element1.BOMRef != nil && element2.BOMRef != nil {
		return comparatorBOMRefType(*element1.BOMRef, *element2.BOMRef)
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

func comparatorExternalReference(element1 CDXExternalReference, element2 CDXExternalReference) bool {
	// sort by required fields: "type", "url"
	if element1.Type != element2.Type {
		return element1.Type < element2.Type
	}
	return element1.Url < element2.Url
}

func comparatorHash(element1 CDXHash, element2 CDXHash) bool {
	// sort by required fields: "alg", "content"
	if element1.Alg != element2.Alg {
		return element1.Alg < element2.Alg
	}
	return element1.Content < element2.Content
}

// TODO: use "text", "url" as "tie-breakers"
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
	if element1.Expression != element2.Expression {
		return element1.Expression < element2.Expression
	}
	// sort by (sometimes an identifier): "bom-ref"
	if element1.BOMRef != nil && element2.BOMRef != nil {
		return comparatorBOMRefType(*element1.BOMRef, *element2.BOMRef)
	}
	return true
}

func comparatorLifecycle(element1 CDXLifecycle, element2 CDXLifecycle) bool {
	if element1.Phase != element2.Phase {
		return element1.Phase < element2.Phase
	}
	// default: preserve existing order
	return true
}

func comparatorOrganizationalContact(element1 CDXOrganizationalContact, element2 CDXOrganizationalContact) bool {
	// sort by optional field(s): "name", "email", "phone"
	if element1.Name != element2.Name {
		return element1.Name < element2.Name
	}
	if element1.Email != element2.Email {
		return element1.Email < element2.Email
	}
	if element1.Phone != element2.Phone {
		return element1.Phone < element2.Phone
	}
	// sort by (sometimes an identifier): "bom-ref"
	if element1.BOMRef != nil && element2.BOMRef != nil {
		return comparatorBOMRefType(*element1.BOMRef, *element2.BOMRef)
	}
	return true
}

func comparatorOrganizationalEntity(element1 CDXOrganizationalEntity, element2 CDXOrganizationalEntity) bool {
	// sort by optional field(s): "name"
	if element1.Name != element2.Name {
		return element1.Name < element2.Name
	}
	// TODO: "tie-breakers": Url ([]string), Contact ([]string)
	// sort by (sometimes an identifier): "bom-ref"
	if element1.BOMRef != nil && element2.BOMRef != nil {
		return comparatorBOMRefType(*element1.BOMRef, *element2.BOMRef)
	}
	return true
}

func comparatorProperty(element1 CDXProperty, element2 CDXProperty) bool {
	// sort by required fields: "name", "value"
	if element1.Name != element2.Name {
		return element1.Name < element2.Name
	}
	return element1.Value < element2.Value
}

// Note: RefLinkType is of type CDXRefType which is of type "string" (for now)
func comparatorRefLinkType(element1 CDXRefLinkType, element2 CDXRefLinkType) bool {
	// Note: casting to actual data type
	return comparatorRefType(CDXRefType(element1), CDXRefType(element2))
}

func comparatorRefType(element1 CDXRefType, element2 CDXRefType) bool {
	// Note: this is a basic "string" comparison
	return element1 < element2
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

func comparatorService(element1 CDXService, element2 CDXService) bool {
	// sort by required field(s): "name"
	if element1.Name != element2.Name {
		return element1.Name < element2.Name
	}
	// sort by other "tie breakers"
	if element1.Version != element2.Version {
		return element1.Version < element2.Version
	}
	// sort by (sometimes an identifier): "bom-ref"
	if element1.BOMRef != nil && element2.BOMRef != nil {
		return comparatorBOMRefType(*element1.BOMRef, *element2.BOMRef)
	}
	// default: preserve existing order
	return true
}

func comparatorVersionRange(element1 CDXVersionRange, element2 CDXVersionRange) bool {
	if element1.Version != element2.Version {
		return element1.Version < element2.Version
	}
	if element1.Range != element2.Range {
		return element1.Range < element2.Range
	}
	if element1.Status != element2.Status {
		return element1.Status < element2.Status
	}
	// default: preserve existing order
	return true
}
