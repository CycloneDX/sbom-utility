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

import "sort"

// Sort by rules:
// 1. Required fields if they exist
// 1. Use pseudo-required field "bom-ref" when available
// 1. Using optional local identifiers or
// 1. Using combinations of identifying field values
// TODO: Compositions, Formula
func (bom *CDXBom) Sort() {
	// ====================================================================
	// Components
	// ====================================================================
	if pSlice := bom.Components; pSlice != nil {
		slice := *pSlice
		sort.Slice(slice, func(i, j int) bool {
			element1 := slice[i]
			element2 := slice[j]
			return comparatorComponents(element1, element2)
		})
	}

	// ====================================================================
	// Services
	// ====================================================================
	// Use required fields: "name"
	// Sort by the optional field "bom-ref" as this is pseudo-required if
	// slice elements contain duplicates with both "name" and "type".
	// TODO: Sort licenses, endpoints, etc.
	if pSlice := bom.Services; pSlice != nil {
		slice := *pSlice
		sort.Slice(slice, func(i, j int) bool {
			element1 := slice[i]
			element2 := slice[j]
			// sort by required field(s)
			if element1.Name != element2.Name {
				return element1.Name < element2.Name
			}
			// sort by pseudo-required field "bom-ref"
			if element1.BOMRef != nil && element2.BOMRef != nil {
				return *element1.BOMRef < *element2.BOMRef
			}
			// Other "tie breakers"
			if element1.Version != element2.Version {
				return element1.Version < element2.Version
			}
			// default: preserve existing order
			return true
		})
	}

	// ====================================================================
	// Dependencies
	// ====================================================================
	// Use required fields: "ref"
	// TODO sort child slice "dependsOn"
	if pSlice := bom.Dependencies; pSlice != nil {
		slice := *pSlice
		sort.Slice(slice, func(i, j int) bool {
			element1 := slice[i]
			element2 := slice[j]
			// guard against invalid pointers to (required) elements
			if element1.Ref != nil && element2.Ref != nil {
				return *element1.Ref < *element2.Ref
			}
			// default: preserve existing order
			return true
		})
	}

	// ====================================================================
	// Vulnerabilities
	// ====================================================================
	// The vulnerability object has no required field; sort by fields
	// that may contain local identifiers or identifying values
	// Optional sort fields: "id"
	// TODO source.url, source.name (optional)
	// TODO sort "advisories", "cwes" and "ratings.source" and "affects.ref"
	if pSlice := bom.Vulnerabilities; pSlice != nil {
		slice := *pSlice
		sort.Slice(slice, func(i, j int) bool {
			element1 := slice[i]
			element2 := slice[j]
			// sort by pseudo-required field "bom-ref"
			if element1.BOMRef != nil && element2.BOMRef != nil {
				return *element1.BOMRef < *element2.BOMRef
			}
			// optional identifiers
			if element1.Id != element2.Id {
				return element1.Id < element2.Id
			}
			// other optional "tie breakers"
			if element1.Source != nil && element2.Source != nil {
				Source1 := *element1.Source
				Source2 := *element2.Source
				if Source1.Name != Source2.Name {
					return Source1.Name < Source2.Name
				}
				if Source1.Url != Source2.Url {
					return Source1.Url < Source2.Url
				}
			}
			// default: preserve existing order
			return true
		})
	}

	// ====================================================================
	// Annotations
	// ====================================================================
	// Use required fields: "timestamp", "text"
	// TODO sort "subjects", "annotator"
	if pSlice := bom.Annotations; pSlice != nil {
		slice := *pSlice
		sort.Slice(slice, func(i, j int) bool {
			element1 := slice[i]
			element2 := slice[j]
			// sort by primary field
			if element1.Timestamp != element2.Timestamp {
				return element1.Timestamp < element2.Timestamp
			}
			// sort by secondary field
			return element1.Text < element2.Text
		})
	}

	// ====================================================================
	// External References
	// ====================================================================
	if pSlice := bom.ExternalReferences; pSlice != nil {
		slice := *pSlice
		sort.Slice(slice, func(i, j int) bool {
			element1 := slice[i]
			element2 := slice[j]
			return comparatorExternalReferences(element1, element2)
		})
	}

	// ====================================================================
	// Properties
	// ====================================================================
	if pSlice := bom.Properties; pSlice != nil {
		slice := *pSlice
		sort.Slice(slice, func(i, j int) bool {
			element1 := slice[i]
			element2 := slice[j]
			return comparatorProperties(element1, element2)
		})
	}
}

func (bom *CDXComponent) Sort() {
	// ====================================================================
	// Hashes
	// ====================================================================
	// Use required fields: "alg", "content"
	if pSlice := bom.Hashes; pSlice != nil {
		slice := *pSlice
		sort.Slice(slice, func(i, j int) bool {
			element1 := slice[i]
			element2 := slice[j]
			// sort by primary field
			if element1.Alg != element2.Alg {
				return element1.Alg < element2.Alg
			}
			// sort by secondary field
			return element1.Content < element2.Content
		})
	}

	// ====================================================================
	// Licenses - TODO
	// ====================================================================

	// ====================================================================
	// Components
	// ====================================================================
	// !!!IMPORTANT: This call is recursive !!!
	// TODO: perhaps track/limit depth of recursion
	if pSlice := bom.Components; pSlice != nil {
		slice := *pSlice
		sort.Slice(slice, func(i, j int) bool {
			element1 := slice[i]
			element2 := slice[j]
			return comparatorComponents(element1, element2)
		})
	}

	// ====================================================================
	// ReleaseNotes
	// ====================================================================
	// Use required fields: "type"
	// Using combinations of identifying field values: "title", "timestamp"
	if pSlice := bom.ReleaseNotes; pSlice != nil {
		slice := *pSlice
		sort.Slice(slice, func(i, j int) bool {
			element1 := slice[i]
			element2 := slice[j]
			// sort by primary field
			if element1.Type != element2.Type {
				return element1.Type < element2.Type
			}
			// sort by optional field values
			if element1.Title != element2.Title {
				return element1.Title < element2.Title
			}
			return element1.Timestamp < element2.Timestamp
		})
	}

	// ====================================================================
	// Data
	// ====================================================================
	// Use required fields: "type"
	// Using combinations of identifying field values: "name"
	if pSlice := bom.Data; pSlice != nil {
		slice := *pSlice
		sort.Slice(slice, func(i, j int) bool {
			element1 := slice[i]
			element2 := slice[j]
			// sort by primary field
			if element1.Type != element2.Type {
				return element1.Type < element2.Type
			}
			// sort by optional field values
			return element1.Name < element2.Name
		})
	}

	// ====================================================================
	// External References
	// ====================================================================
	if pSlice := bom.ExternalReferences; pSlice != nil {
		slice := *pSlice
		sort.Slice(slice, func(i, j int) bool {
			element1 := slice[i]
			element2 := slice[j]
			return comparatorExternalReferences(element1, element2)
		})
	}

	// ====================================================================
	// Properties
	// ====================================================================
	if pSlice := bom.Properties; pSlice != nil {
		slice := *pSlice
		sort.Slice(slice, func(i, j int) bool {
			element1 := slice[i]
			element2 := slice[j]
			return comparatorProperties(element1, element2)
		})
	}
}

// Use required fields: "type", "name"
// Use optional identity fields: "purl", "cpe", "swid.TagId"
// Sort by the optional field "bom-ref" as this is pseudo-required if
// slice elements contain duplicates with both "name" and "type".
// TODO: Sort licenses, hashes, etc.
func comparatorComponents(element1 CDXComponent, element2 CDXComponent) bool {
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

// Use required fields: "type", "url"
func comparatorExternalReferences(element1 CDXExternalReference, element2 CDXExternalReference) bool {
	// sort by primary field
	if element1.Type != element2.Type {
		return element1.Type < element2.Type
	}
	// sort by secondary field
	return element1.Url < element2.Url
}

// Use required fields: "name", "value"
func comparatorProperties(element1 CDXProperty, element2 CDXProperty) bool {
	// sort by primary field
	if element1.Name != element2.Name {
		return element1.Name < element2.Name
	}
	// sort by secondary field
	return element1.Value < element2.Value
}
