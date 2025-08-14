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

package cmd

import (
	"testing"

	"github.com/CycloneDX/sbom-utility/log"
	"github.com/CycloneDX/sbom-utility/schema"
)

// -------------------------------------------
// Custom CycloneDX JSON schema
// -------------------------------------------

// v1.3, 1.4 - custom json schema tests
const (
	TEST_SCHEMA_CDX_1_3_CUSTOM = "resources/schema/test/bom-1.3-custom.schema.json"
	TEST_SCHEMA_CDX_1_4_CUSTOM = "resources/schema/test/bom-1.4-custom.schema.json"
)

// -------------------------------------------
// BOM test files
// -------------------------------------------

// CycloneDX v1.6
const (
	TEST_CUSTOM_CDX_1_6_BEST_PRACTICES        = "test/custom/cdx-1-6-test-best-practices.json"
	TEST_CUSTOM_CDX_1_6_BOM_PROPERTIES        = "test/custom/cdx-1-6-test-bom-properties.json"
	TEST_CUSTOM_CDX_1_6_METADATA_HAS_ELEMENTS = "test/custom/cdx-1-6-test-metadata-has-elements.json"

	TEST_CUSTOM_CDX_1_6_METADATA_PROPS_CLASSIFICATION_MULTIPLE = "test/custom/cdx-1-6-test-metedata-properties-classification-multiple.json"
	TEST_CUSTOM_CDX_1_6_METADATA_PROPS_DISCLAIMER_MISMATCH     = "test/custom/cdx-1-6-test-metedata-properties-disclaimer-mismatch.json"
	TEST_CUSTOM_CDX_1_6_METADATA_PROPS_DISCLAIMER_MISSING      = "test/custom/cdx-1-6-test-metedata-properties-disclaimer-missing.json"
	TEST_CUSTOM_CDX_1_6_METADATA_PROPS_DISCLAIMER_UNIQUE       = "test/custom/cdx-1-6-test-metedata-properties-disclaimer-unique.json"
)

// -------------------------------------------
// Custom validation - test configuration files
// -------------------------------------------

// SPDX
const (
	CUSTOM_CONFIG_SPDX_2_X_STRUCTURE = "test/custom/spdx-custom-bom-properties.json"
)

// CycloneDX
const (
	CUSTOM_CONFIG_BOM_STRUCTURE_BEST_PRACTICE       = "test/custom/custom-bom-structure-best-practice.json"
	CUSTOM_CONFIG_BOM_PROPS_UNIQUE                  = "test/custom/custom-bom-properties-unique.json"
	CUSTOM_CONFIG_BOM_PROPS_NOT_UNIQUE              = "test/custom/custom-bom-properties-not-unique.json"
	CUSTOM_CONFIG_METADATA_HAS_ELEMENTS_FAIL        = "test/custom/custom-metadata-element-not-found.json"
	CUSTOM_CONFIG_METADATA_HAS_ELEMENTS_SUCCESS     = "test/custom/custom-metadata-has-elements.json"
	CUSTOM_CONFIG_METADATA_PROPS_DISCLAIMER_MATCH   = "test/custom/custom-metadata-properties-disclaimer-match.json"
	CUSTOM_CONFIG_METADATA_PROPS_DISCLAIMER_UNIQUE  = "test/custom/custom-metadata-properties-disclaimer-unique.json"
	CUSTOM_CONFIG_METADATA_PROPS_DISCLAIMER_MISSING = "test/custom/custom-metadata-properties-disclaimer-missing.json"
)

// License tests
const (
	// Note: The "invalid" tests below is also used in "list" command tests
	// which tests for a "none found" warning messages being displayed to stdout
	TEST_CUSTOM_CDX_1_4_INVALID_LICENSES_NOT_FOUND = TEST_LICENSE_LIST_CDX_1_4_NONE_FOUND
)

// -------------------------------------------
// SPDX Tests
// -------------------------------------------

// Test format unsupported (SPDX) for "--custom" flag
// TODO - The latest code SHOULD be able to support SPDX 2.2, 2.3 using custom validation!
// Currently, we just throw an "UnsupportedFormatError" once SPDX is detected
func TestValidateCustomFormatUnsupportedSPDX_2_2(t *testing.T) {
	// getLogger().SetLevel(log.TRACE)
	vti := NewValidateTestInfo(TEST_SPDX_2_2_MIN_REQUIRED,
		FORMAT_ANY,
		SCHEMA_VARIANT_NONE,
		&schema.UnsupportedFormatError{})
	vti.CustomConfig = CUSTOM_CONFIG_SPDX_2_X_STRUCTURE
	innerTestValidate(t, *vti)
}

func TestValidateCustomFormatUnsupportedSPDX_2_3(t *testing.T) {
	// getLogger().SetLevel(log.TRACE)
	vti := NewValidateTestInfo(TEST_SPDX_2_3_EXAMPLE_PACKAGE_BOM,
		FORMAT_ANY,
		SCHEMA_VARIANT_NONE,
		&schema.UnsupportedFormatError{})
	vti.CustomConfig = CUSTOM_CONFIG_SPDX_2_X_STRUCTURE
	innerTestValidate(t, *vti)
}

// -------------------------------------------
// CycloneDX - valid license tests
// -------------------------------------------

// Error if no licenses found in entirety of SBOM (variant none)
func TestValidateCustomErrorCdx14NoLicensesFound(t *testing.T) {
	// getLogger().SetLevel(log.TRACE)
	vti := NewValidateTestInfo(TEST_CUSTOM_CDX_1_4_INVALID_LICENSES_NOT_FOUND,
		FORMAT_ANY,
		SCHEMA_VARIANT_NONE,
		&InvalidSBOMError{})
	vti.CustomConfig = DEFAULT_CUSTOM_VALIDATION_CONFIG
	document, results, _ := innerTestValidate(t, *vti)
	getLogger().Tracef("filename: '%s', results:\n%v", document.GetFilename(), results)
}

// -------------------------------------------
// CycloneDX - isUnique tests
// -------------------------------------------

// isUnique(): Success - BOM "metadata.properties" has a unique "disclaimer" property
func TestValidateCustomCdx16_MetadataPropsUniqueDisclaimer(t *testing.T) {
	// getLogger().SetLevel(log.TRACE)
	getLogger().SetLevel(log.TRACE)
	vti := NewValidateTestInfoMinimum(TEST_CUSTOM_CDX_1_6_METADATA_PROPS_DISCLAIMER_UNIQUE)
	vti.CustomConfig = CUSTOM_CONFIG_METADATA_PROPS_DISCLAIMER_UNIQUE
	document, results, _ := innerTestValidate(t, *vti)
	getLogger().Tracef("filename: '%s', results:\n%v", document.GetFilename(), results)
}

func TestValidateCustomCdx16_BOMPropsUnique(t *testing.T) {
	// getLogger().SetLevel(log.TRACE)
	vti := NewValidateTestInfoMinimum(TEST_CUSTOM_CDX_1_6_BOM_PROPERTIES)
	vti.CustomConfig = CUSTOM_CONFIG_BOM_PROPS_UNIQUE
	document, _, err := innerTestValidate(t, *vti)
	getLogger().Tracef("filename: '%s', error: '%s'", document.GetFilename(), err)
}

// isUnique(): Fail - BOM "properties" does not have a unique "name" property (i.e., "foo" appears twice)
func TestValidateCustomCdx16_BOMPropsNotUnique(t *testing.T) {
	// getLogger().SetLevel(log.TRACE)
	vti := NewValidateTestInfoMinimum(TEST_CUSTOM_CDX_1_6_BOM_PROPERTIES)
	vti.CustomConfig = CUSTOM_CONFIG_BOM_PROPS_NOT_UNIQUE
	vti.ResultExpectedError = &InvalidSBOMError{}
	vti.ResultExpectedInnerError = &ItemIsUniqueError{}
	document, _, err := innerValidateInvalidSBOMInnerError(t, *vti)
	getLogger().Tracef("filename: '%s', error: '%s'", document.GetFilename(), err)
}

// -------------------------------------------
// CycloneDX - hasProperties tests
// -------------------------------------------

// hasProperties(): Success - has a top-level "metadata", "components" and "dependencies"
func TestValidateCustomCdx16_BOMStructureBestPractice(t *testing.T) {
	// getLogger().SetLevel(log.TRACE)
	vti := NewValidateTestInfoMinimum(TEST_CUSTOM_CDX_1_6_BEST_PRACTICES)
	vti.CustomConfig = CUSTOM_CONFIG_BOM_STRUCTURE_BEST_PRACTICE
	document, results, _ := innerTestValidate(t, *vti)
	getLogger().Tracef("filename: '%s', results:\n%v", document.GetFilename(), results)
}

// hasProperties(): Success - Has elements in BOM "metadata"
func TestValidateCustomCdx16_MetadataHasElements(t *testing.T) {
	// getLogger().SetLevel(log.TRACE)
	vti := NewValidateTestInfoMinimum(TEST_CUSTOM_CDX_1_6_BEST_PRACTICES)
	vti.CustomConfig = CUSTOM_CONFIG_METADATA_HAS_ELEMENTS_SUCCESS
	document, results, _ := innerTestValidate(t, *vti)
	getLogger().Tracef("filename: '%s', results:\n%v", document.GetFilename(), results)
}

// hasProperties(): Fail - missing element in BOM "metadata"
func TestValidateCustomCdx16_MetadataElementNotFound(t *testing.T) {
	// getLogger().SetLevel(log.TRACE)
	vti := NewValidateTestInfoMinimum(TEST_CUSTOM_CDX_1_6_BEST_PRACTICES)
	vti.CustomConfig = CUSTOM_CONFIG_METADATA_HAS_ELEMENTS_FAIL
	vti.ResultExpectedError = &InvalidSBOMError{}
	vti.ResultExpectedInnerError = &ItemHasPropertiesError{}
	document, _, err := innerValidateInvalidSBOMInnerError(t, *vti)
	getLogger().Tracef("filename: '%s', error: '%s'", document.GetFilename(), err)
}

// -------------------------------------------
// FAIL - Uniqueness tests
// -------------------------------------------

func TestValidateCustomCdx14MetadataPropertyDisclaimerUnique(t *testing.T) {
	// getLogger().SetLevel(log.TRACE)
	vti := NewValidateTestInfoMinimum(TEST_CUSTOM_CDX_1_6_METADATA_PROPS_DISCLAIMER_UNIQUE)
	vti.CustomConfig = CUSTOM_CONFIG_METADATA_PROPS_DISCLAIMER_UNIQUE
	vti.ResultExpectedError = &InvalidSBOMError{}
	vti.ResultExpectedInnerError = &ItemIsUniqueError{}
	document, _, err := innerValidateInvalidSBOMInnerError(t, *vti)
	getLogger().Tracef("filename: '%s', error: '%s'", document.GetFilename(), err)
}

func TestValidateCustomCdx14MetadataPropertyDisclaimerMismatch(t *testing.T) {
	// getLogger().SetLevel(log.TRACE)
	vti := NewValidateTestInfoMinimum(TEST_CUSTOM_CDX_1_6_METADATA_PROPS_DISCLAIMER_MISMATCH)
	vti.CustomConfig = CUSTOM_CONFIG_METADATA_PROPS_DISCLAIMER_MATCH
	vti.ResultExpectedError = &InvalidSBOMError{}
	vti.ResultExpectedInnerError = &ItemHasPropertiesError{}
	document, _, err := innerValidateInvalidSBOMInnerError(t, *vti)
	getLogger().Tracef("filename: '%s', error: '%s'", document.GetFilename(), err)
}

func TestValidateCustomCdx14MetadataPropertyDisclaimerMissing(t *testing.T) {
	// getLogger().SetLevel(log.TRACE)
	vti := NewValidateTestInfoMinimum(TEST_CUSTOM_CDX_1_6_METADATA_PROPS_DISCLAIMER_MISSING)
	vti.CustomConfig = CUSTOM_CONFIG_METADATA_PROPS_DISCLAIMER_MISSING
	vti.ResultExpectedError = &InvalidSBOMError{}
	vti.ResultExpectedInnerError = &JSONElementNotFoundError{}
	document, _, err := innerValidateInvalidSBOMInnerError(t, *vti)
	getLogger().Tracef("filename: '%s', error: '%s'", document.GetFilename(), err)
}
