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

package cmd

import (
	"testing"
)

// Custom IBM configuration files
const (
	CONFIG_IBM_SCHEMA         = "test/ibm/config/config-ibm.json"
	CONFIG_IBM_LICENSE_POLICY = "test/ibm/config/license-ibm.json"
	CONFIG_IBM_VALIDATION     = "test/ibm/config/custom-ibm.json"
)

// Custom IBM CycloneDX JSON schemas
// TODO: incorporate into build-specific testing
const (
	SCHEMA_VARIANT_IBM_DEV = "ibm-dev"
	SCHEMA_VARIANT_IBM_REL = "ibm-rel"
)

// Custom-specific test files
const (
	// Min. Req. - Test versioned documents meet min. schema (variant) requirements
	TEST_CDX_1_3_IBM_MIN_REQUIRED = "test/custom/ibm/cdx-1-3-ibm-min-required.json"
	TEST_CDX_1_4_IBM_MIN_REQUIRED = "test/custom/ibm/cdx-1-4-ibm-min-required.json"

	// Composition
	TEST_CUSTOM_IBM_CDX_1_3_INVALID_COMPOSITION_METADATA_COMPONENT = "test/custom/ibm/cdx-1-3-ibm-invalid-composition-metadata-component.json"
	TEST_CUSTOM_IBM_CDX_1_3_INVALID_COMPOSITION_COMPONENTS         = "test/custom/ibm/cdx-1-3-ibm-invalid-composition-components.json"

	// Metadata tests
	// TODO: reference new "ibm-custom.json" file (i.e., not used the default "custom.json")
	//TEST_CUSTOM_IBM_CDX_1_4_MISSING_DISCLAIMER = "test/custom/ibm/cdx-1-4-test-ibm-invalid-disclaimer-missing.json"

	// Merge tests
	TEST_CUSTOM_IBM_CDX_1_3_MERGE_PRODUCT_DATA = "test/custom/ibm/cdx-1-3-ibm-manual-data-example.json"
)

// -----------------------------------------------------------
// Min. req. tests
// -----------------------------------------------------------

func TestValidateCustomIBMCdx13MinRequiredBasic(t *testing.T) {
	innerValidateError(t,
		TEST_CDX_1_3_IBM_MIN_REQUIRED,
		SCHEMA_VARIANT_IBM_DEV,
		nil)
}

func TestValidateCustomIBMCdx14MinRequiredBasic(t *testing.T) {
	innerValidateError(t,
		TEST_CDX_1_4_IBM_MIN_REQUIRED,
		SCHEMA_VARIANT_IBM_DEV,
		nil)
}

// -------------------------------------------
// Schema: root tests
// -------------------------------------------

// -------------------------------------------
// Schema: metadata tests
// -------------------------------------------

// TODO: test to assure we do not allow version to be > 1

// -------------------------------------------
// Composition tests
// -------------------------------------------

// Error if hierarchical components found in top-level "metadata.component" object
func TestValidateCustomIBMErrorCdx13InvalidCompositionMetadataComponent(t *testing.T) {
	innerCustomValidateInvalidSBOMInnerError(t,
		TEST_CUSTOM_IBM_CDX_1_3_INVALID_COMPOSITION_METADATA_COMPONENT,
		SCHEMA_VARIANT_IBM_DEV,
		&SBOMCompositionError{})
}

// Error if hierarchical components in top-level "components" array
func TestValidateCustomIBMErrorCdx13InvalidCompositionComponents(t *testing.T) {
	innerCustomValidateInvalidSBOMInnerError(t,
		TEST_CUSTOM_IBM_CDX_1_3_INVALID_COMPOSITION_METADATA_COMPONENT,
		SCHEMA_VARIANT_IBM_DEV,
		&SBOMCompositionError{})
}

// -----------------------------------------------------------
// CycloneDX - merge tests
// ----------------------------------------------------------

// NOTE: the "merge" document SHOULD be a valid CDX SBOM, but with
// only a subset of fields (i.e., do NOT validate against an IBM schema)
// TODO": Once "merge" command is completed, also verify not just the merge data,
// but also the resultant merged SBOM
func TestValidateCustomIBMCdx13MergeProductData(t *testing.T) {
	innerValidateError(t,
		TEST_CUSTOM_IBM_CDX_1_3_MERGE_PRODUCT_DATA,
		SCHEMA_VARIANT_NONE,
		nil)
}
