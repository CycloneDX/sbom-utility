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

// CycloneDX v2.0 tests.
//
// All tests in this file exercise functionality specific to CycloneDX v2.0 BOMs
// (specFormat rename, parties[], identifiers[], etc.) and require the
// SCHEMA_VARIANT_DEVELOPMENT schema variant to be selected.

package cmd

import (
	"errors"
	"testing"

	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/CycloneDX/sbom-utility/utils"
)

// -------------------------------------------
// validate
// -------------------------------------------

// TestValidateCdx20ValidComponent verifies that a CycloneDX v2.0 BOM containing a single
// component with v2.0-only fields (identifiers, parties, implementationPlatform as []string)
// is correctly validated and unmarshalled into the CDXComponent struct.
func TestValidateCdx20ValidComponent(t *testing.T) {
	vti := NewValidateTestInfo(TEST_CDX_2_0_VALID_COMPONENT, FORMAT_TEXT, SCHEMA_VARIANT_DEVELOPMENT, nil)
	document, _, err := innerTestValidate(t, *vti)
	if err != nil {
		return
	}

	if err = document.UnmarshalCycloneDXBOM(); err != nil {
		t.Errorf("UnmarshalCycloneDXBOM() failed: %v", err)
		return
	}

	// v2.0: component is in metadata, not components array
	comp := document.GetCdxMetadataComponent()
	if comp == nil {
		t.Errorf("expected metadata.component to be populated for v2.0 fixture")
		return
	}

	// v2.0: identifiers field should be populated
	if comp.Identifiers == nil || len(*comp.Identifiers) == 0 {
		t.Errorf("expected component.identifiers to be populated for v2.0 fixture")
	}

	// v2.0: parties field should be populated
	if comp.Parties == nil || len(*comp.Parties) == 0 {
		t.Errorf("expected component.parties to be populated for v2.0 fixture")
	}
}

// -------------------------------------------
// resource list
// -------------------------------------------

// TestResourceListCdx20ValidComponentPurl verifies that resource list with --variant development
// on a CycloneDX v2.0 BOM correctly surfaces the purl extracted from identifiers[].identities[].
func TestResourceListCdx20ValidComponentPurl(t *testing.T) {
	utils.GlobalFlags.ValidateFlags.SchemaVariant = SCHEMA_VARIANT_DEVELOPMENT
	defer func() { utils.GlobalFlags.ValidateFlags.SchemaVariant = SCHEMA_VARIANT_NONE }()

	rti := NewResourceTestInfoBasic(
		TEST_CDX_2_0_VALID_COMPONENT,
		FORMAT_CSV,
		nil,
		schema.RESOURCE_TYPE_COMPONENT,
	)
	rti.ResultExpectedLineCount = 3 // title + 1 data row + EOF LF
	rti.ResultLineContainsValuesAtLineNum = 1
	rti.ResultLineContainsValues = []string{"pkg:npm/acme-corp/acme-lib@2.3.1"}
	innerTestResourceList(t, rti)
}

// -------------------------------------------
// component list
// -------------------------------------------

// TestComponentListCdx20ValidComponentPartiesCsv verifies that "component list" for a CycloneDX
// v2.0 BOM correctly reads supplier, manufacturer, and publisher from the component's v2.0
// "parties" array (not the legacy metadata.supplier / metadata.manufacturer direct fields).
func TestComponentListCdx20ValidComponentPartiesCsv(t *testing.T) {
	utils.GlobalFlags.ValidateFlags.SchemaVariant = SCHEMA_VARIANT_DEVELOPMENT
	defer func() { utils.GlobalFlags.ValidateFlags.SchemaVariant = SCHEMA_VARIANT_NONE }()

	ti := NewComponentTestInfoBasic(TEST_COMPONENT_LIST_CDX_2_0_VALID_COMPONENT, FORMAT_CSV, nil)
	ti.ResultExpectedLineCount = 3 // title + 1 data row + EOF LF
	ti.ResultLineContainsValuesAtLineNum = 1
	// All three party roles must be sourced from parties[], not legacy direct fields
	ti.ResultLineContainsValues = []string{"Acme Supplier Ltd", "Acme Manufacturing Inc", "Acme Corp"}
	innerTestComponentList(t, ti, COMPONENT_TEST_DEFAULT_FLAGS)
}

// TestComponentListCdx20WhereManufacturerNameMatchCsv verifies that the --where filter on
// "manufacturer-name" correctly matches the value resolved from a v2.0 "parties" array entry
// with role "manufacturer" (positive case: one component must be returned).
func TestComponentListCdx20WhereManufacturerNameMatchCsv(t *testing.T) {
	utils.GlobalFlags.ValidateFlags.SchemaVariant = SCHEMA_VARIANT_DEVELOPMENT
	defer func() { utils.GlobalFlags.ValidateFlags.SchemaVariant = SCHEMA_VARIANT_NONE }()

	ti := NewComponentTestInfoBasic(TEST_COMPONENT_LIST_CDX_2_0_VALID_COMPONENT, FORMAT_CSV, nil)
	ti.WhereClause = "manufacturer-name=Acme Manufacturing Inc"
	ti.ResultExpectedLineCount = 3 // title + 1 data row + EOF LF
	ti.ResultLineContainsValuesAtLineNum = 1
	ti.ResultLineContainsValues = []string{"Acme Manufacturing Inc"}
	innerTestComponentList(t, ti, COMPONENT_TEST_DEFAULT_FLAGS)
}

// TestComponentListCdx20WhereManufacturerNameNoMatchCsv verifies that the --where filter on
// "manufacturer-name" correctly returns no results when the value does not match any component
// party with role "manufacturer" in a v2.0 BOM (negative case).
func TestComponentListCdx20WhereManufacturerNameNoMatchCsv(t *testing.T) {
	utils.GlobalFlags.ValidateFlags.SchemaVariant = SCHEMA_VARIANT_DEVELOPMENT
	defer func() { utils.GlobalFlags.ValidateFlags.SchemaVariant = SCHEMA_VARIANT_NONE }()

	ti := NewComponentTestInfoBasic(TEST_COMPONENT_LIST_CDX_2_0_VALID_COMPONENT, FORMAT_CSV, errors.New(""))
	ti.WhereClause = "manufacturer-name=NonExistentManufacturer"
	innerTestComponentList(t, ti, COMPONENT_TEST_DEFAULT_FLAGS)
}
