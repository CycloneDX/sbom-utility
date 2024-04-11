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

// ====================================================================
// Sort (normalization) by rules:
// ====================================================================
// 1. Required fields if they exist
// 1. Use pseudo-required field "bom-ref" when available
// 1. Using optional local identifiers or
// 1. Using combinations of identifying field values (towards 100% normalization)
// ====================================================================
// "Punch" list of future items:
// - TODO: track/limit depth of recursion (in "component", "service")
// ====================================================================

// TODO: Compositions, Formula
func (bom *CDXBom) Sort() {
	// Sort: Components
	if bom.Components != nil {
		sortSliceComponents(bom.Components)
	}

	// Sort: Services
	if bom.Services != nil {
		sortSliceServices(bom.Services)
	}

	// Sort: Dependencies
	if pSlice := bom.Dependencies; pSlice != nil {
		slice := *pSlice
		sort.Slice(slice, func(i, j int) bool {
			element1 := slice[i]
			element2 := slice[j]
			return comparatorDependency(element1, element2)
		})
	}

	// Sort: Vulnerabilities
	if pSlice := bom.Vulnerabilities; pSlice != nil {
		slice := *pSlice
		sort.Slice(slice, func(i, j int) bool {
			element1 := slice[i]
			element2 := slice[j]
			return comparatorVulnerability(element1, element2)
		})
	}

	// Sort: Annotations
	if pSlice := bom.Annotations; pSlice != nil {
		slice := *pSlice
		sort.Slice(slice, func(i, j int) bool {
			element1 := slice[i]
			element2 := slice[j]
			return comparatorAnnotation(element1, element2)
		})
	}

	// Sort: ExternalReferences
	if pSlice := bom.ExternalReferences; pSlice != nil {
		slice := *pSlice
		sort.Slice(slice, func(i, j int) bool {
			element1 := slice[i]
			element2 := slice[j]
			return comparatorExternalReference(element1, element2)
		})
	}

	// Sort: Properties
	if bom.Properties != nil {
		sortSliceProperties(bom.Properties)
	}

	// Sort: Metadata.Licenses
	if bom.Metadata != nil {
		bom.Metadata.Sort()
	}
}

// TODO: Sort Metadata object fields that are slices:
// Tools        interface{}                 `json:"tools,omitempty"`                               // v1.2: added.v1.5: "tools" is now an interface{}
// Authors      *[]CDXOrganizationalContact `json:"authors,omitempty"`
// Component    *CDXComponent               `json:"component,omitempty"`
// Manufacturer *CDXOrganizationalEntity    `json:"manufacture,omitempty"` // NOTE: Typo is in spec.
// Supplier     *CDXOrganizationalEntity    `json:"supplier,omitempty"`
// Lifecycles   *[]CDXLifecycle             `json:"lifecycles,omitempty"` // v1.5 added
func (pMetadata *CDXMetadata) Sort() {
	if pMetadata != nil {
		metadata := *pMetadata

		// Sort: Component
		if metadata.Component != nil {
			metadata.Component.Sort()
		}

		// Sort: Licenses
		if pSlice := metadata.Licenses; pSlice != nil {
			slice := *pSlice
			sort.Slice(slice, func(i, j int) bool {
				element1 := slice[i]
				element2 := slice[j]
				return comparatorLicense(element1, element2)
			})
		}

		// Sort: Properties
		if pSlice := metadata.Properties; pSlice != nil {
			slice := *pSlice
			sort.Slice(slice, func(i, j int) bool {
				element1 := slice[i]
				element2 := slice[j]
				return comparatorProperty(element1, element2)
			})
		}
	}
}

func (component *CDXComponent) Sort() {

	// Sort: Components
	// Note: The following method is recursive
	if component.Components != nil {
		sortSliceComponents(component.Components)
	}

	// Sort: Hashes
	if pSlice := component.Hashes; pSlice != nil {
		slice := *pSlice
		sort.Slice(slice, func(i, j int) bool {
			element1 := slice[i]
			element2 := slice[j]
			return comparatorHash(element1, element2)
		})
	}

	// Sort: Licenses
	if pSlice := component.Licenses; pSlice != nil {
		slice := *pSlice
		sort.Slice(slice, func(i, j int) bool {
			element1 := slice[i]
			element2 := slice[j]
			return comparatorLicense(element1, element2)
		})
	}

	// Sort: ReleaseNotes
	if pSlice := component.ReleaseNotes; pSlice != nil {
		slice := *pSlice
		sort.Slice(slice, func(i, j int) bool {
			element1 := slice[i]
			element2 := slice[j]
			// sort by required fields: "type"
			if element1.Type != element2.Type {
				return element1.Type < element2.Type
			}
			// sort by using combinations of identifying field values: "title", "timestamp"
			if element1.Title != element2.Title {
				return element1.Title < element2.Title
			}
			return element1.Timestamp < element2.Timestamp
		})
	}

	// Sort: Data
	if pSlice := component.Data; pSlice != nil {
		slice := *pSlice
		sort.Slice(slice, func(i, j int) bool {
			element1 := slice[i]
			element2 := slice[j]
			// sort by required fields: "type"
			if element1.Type != element2.Type {
				return element1.Type < element2.Type
			}
			// sort using combinations of identifying field values: "name"
			return element1.Name < element2.Name
		})
	}

	// Sort: External References
	if pSlice := component.ExternalReferences; pSlice != nil {
		slice := *pSlice
		sort.Slice(slice, func(i, j int) bool {
			element1 := slice[i]
			element2 := slice[j]
			return comparatorExternalReference(element1, element2)
		})
	}

	// Sort: Properties
	if pSlice := component.Properties; pSlice != nil {
		slice := *pSlice
		sort.Slice(slice, func(i, j int) bool {
			element1 := slice[i]
			element2 := slice[j]
			return comparatorProperty(element1, element2)
		})
	}
}

func (service *CDXService) Sort() {

	// Sort: Services
	// Note: The following method is recursive
	if service.Services != nil {
		sortSliceServices(service.Services)
	}

	// Sort: Licenses
	if pSlice := service.Licenses; pSlice != nil {
		slice := *pSlice
		sort.Slice(slice, func(i, j int) bool {
			element1 := slice[i]
			element2 := slice[j]
			return comparatorLicense(element1, element2)
		})
	}

	// Sort: ExternalReferences
	if pSlice := service.ExternalReferences; pSlice != nil {
		slice := *pSlice
		sort.Slice(slice, func(i, j int) bool {
			element1 := slice[i]
			element2 := slice[j]
			return comparatorExternalReference(element1, element2)
		})
	}
}

// ====================================================================
// Slice sort methods
// ====================================================================

// Note: recursively sorts slice of CycloneDX Components
func sortSliceComponents(pSlice *[]CDXComponent) {
	if pSlice != nil {
		slice := *pSlice
		sort.Slice(slice, func(i, j int) bool {
			element1 := slice[i]
			element2 := slice[j]
			return comparatorComponent(element1, element2)
		})

		// !!!RECURSIVELY sort each entry in the Components slice
		for _, component := range slice {
			component.Sort()
		}
	}
}

// Note: recursively sorts slice of CycloneDX Services
func sortSliceServices(pSlice *[]CDXService) {
	if pSlice != nil {
		slice := *pSlice
		sort.Slice(slice, func(i, j int) bool {
			element1 := slice[i]
			element2 := slice[j]
			return comparatorService(element1, element2)
		})

		// !!!RECURSIVELY sort each entry in the Services slice
		for _, service := range slice {
			service.Sort()
		}
	}
}

// Note: recursively sorts slice of CycloneDX Services
func sortSliceProperties(pSlice *[]CDXProperty) {
	if pSlice != nil {
		slice := *pSlice
		sort.Slice(slice, func(i, j int) bool {
			element1 := slice[i]
			element2 := slice[j]
			return comparatorProperty(element1, element2)
		})
	}
}

// ====================================================================
// Slice comparators
// ====================================================================

// Use required fields: "type", "name"
// Use optional identity fields: "purl", "cpe", "swid.TagId"
// Sort by the optional field "bom-ref" as this is pseudo-required if
// slice elements contain duplicates with both "name" and "type".
// TODO: Sort licenses, hashes, etc.
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

// TODO: Sort licenses, endpoints, etc.
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

// TODO: sort "DependsOn" array values AND
// TODO: use sorted "DependsOn" array values (as a whole) as a "tie-breaker"
func comparatorDependency(element1 CDXDependency, element2 CDXDependency) bool {
	// guard against invalid pointers to (required) elements
	if element1.Ref != nil && element2.Ref != nil {
		// sort by required field: "ref"
		return *element1.Ref < *element2.Ref
	}
	// default: preserve existing order
	return true
}

// TODO: use "bom-ref" as pseudo-required (if present)
// TODO: use "text", "url" as "tie-breakers"
// Text       *CDXAttachment `json:"text,omitempty"`
// Url        string         `json:"url,omitempty"`
// BOMRef     *CDXRefType    `json:"bom-ref,omitempty"`    // v1.5: added
// Licensing  *CDXLicensing  `json:"licensing,omitempty"`  // v1.5: added
// Properties *[]CDXProperty `json:"properties,omitempty"` // v1.5: added
func comparatorLicense(element1 CDXLicenseChoice, element2 CDXLicenseChoice) bool {
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
