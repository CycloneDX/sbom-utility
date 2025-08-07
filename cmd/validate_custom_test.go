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
// "custom.json" test variants
// -------------------------------------------

// v1.6
const (
	TEST_CUSTOM_BOM_STRUCTURE_BEST_PRACTICE      = "test/custom/custom-bom-structure-best-practice.json"
	TEST_CUSTOM_BOM_PROPS_NOT_UNIQUE             = "test/custom/custom-bom-properties-not-unique.json"
	TEST_CUSTOM_METADATA_HAS_ELEMENTS_FAIL       = "test/custom/custom-metadata-element-not-found.json"
	TEST_CUSTOM_METADATA_HAS_ELEMENTS_SUCCESS    = "test/custom/custom-metadata-has-elements.json"
	TEST_CUSTOM_METADATA_PROPS_DISCLAIMER_MATCH  = "test/custom/custom-metadata-properties-disclaimer-match.json"
	TEST_CUSTOM_METADATA_PROPS_DISCLAIMER_UNIQUE = "test/custom/custom-metadata-properties-disclaimer-unique.json"
)

// v1.3, 1.4 - custom json schema tests
const (
	TEST_SCHEMA_CDX_1_3_CUSTOM = "resources/schema/test/bom-1.3-custom.schema.json"
	TEST_SCHEMA_CDX_1_4_CUSTOM = "resources/schema/test/bom-1.4-custom.schema.json"
)

// -------------------------------------------
// CycloneDX BOM test files
// -------------------------------------------

// v1.6
const TEST_CUSTOM_CDX_1_6_CUSTOM = "test/custom/cdx-1-6-test-custom-metadata-property-disclaimer-classification.json"

// v1.4, v1.3
const (
	// Metadata tests
	TEST_CUSTOM_CDX_1_4_METADATA_PROPS_DISCLAIMER_INVALID = "test/custom/cdx-1-4-test-custom-metadata-property-disclaimer-invalid.json"
	TEST_CUSTOM_CDX_1_4_METADATA_PROPS_DISCLAIMER_MISSING = "test/custom/cdx-1-4-test-custom-metadata-property-disclaimer-missing.json"
	TEST_CUSTOM_CDX_1_4_METADATA_PROPS_DISCLAIMER_UNIQUE  = "test/custom/cdx-1-4-test-custom-metadata-property-disclaimer-unique.json"
	// License tests
	// Note: The "invalid" tests below is also used in "list" command tests
	// which tests for a "none found" warning messages being displayed to stdout
	TEST_CUSTOM_CDX_1_4_INVALID_LICENSES_NOT_FOUND = TEST_LICENSE_LIST_CDX_1_4_NONE_FOUND
)

// -------------------------------------------
// SPDX Tests
// -------------------------------------------

// Test format unsupported (SPDX) for "--custom" flag
func TestValidateCustomFormatUnsupportedSPDX(t *testing.T) {
	// getLogger().SetLevel(log.TRACE)
	vti := NewValidateTestInfo(TEST_SPDX_2_2_MIN_REQUIRED,
		FORMAT_ANY,
		SCHEMA_VARIANT_NONE,
		&schema.UnsupportedFormatError{})
	vti.CustomConfig = TEST_CUSTOM_BOM_STRUCTURE_BEST_PRACTICE
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
// CycloneDX - BOM structure
// -------------------------------------------

// hasProperties(): Success - has a top-level "metadata", "components" and "dependencies"
func TestValidateCustomCdx16_BOMStructureBestPractice(t *testing.T) {
	// getLogger().SetLevel(log.TRACE)
	vti := NewValidateTestInfoMinimum(TEST_CUSTOM_CDX_1_6_CUSTOM)
	vti.CustomConfig = TEST_CUSTOM_BOM_STRUCTURE_BEST_PRACTICE
	document, results, _ := innerTestValidate(t, *vti)
	getLogger().Tracef("filename: '%s', results:\n%v", document.GetFilename(), results)
}

// hasProperties(): Success - Has required elements in BOM "metadata"
func TestValidateCustomCdx16_MetadataHasElements(t *testing.T) {
	// getLogger().SetLevel(log.TRACE)
	vti := NewValidateTestInfoMinimum(TEST_CUSTOM_CDX_1_6_CUSTOM)
	vti.CustomConfig = TEST_CUSTOM_METADATA_HAS_ELEMENTS_SUCCESS
	document, results, _ := innerTestValidate(t, *vti)
	getLogger().Tracef("filename: '%s', results:\n%v", document.GetFilename(), results)
}

// hasProperties(): Fail - missing element in BOM "metadata"
func TestValidateCustomCdx16_MetadataElementNotFound(t *testing.T) {
	// getLogger().SetLevel(log.TRACE)
	vti := NewValidateTestInfoMinimum(TEST_CUSTOM_CDX_1_6_CUSTOM)
	vti.CustomConfig = TEST_CUSTOM_METADATA_HAS_ELEMENTS_FAIL
	vti.ResultExpectedError = &InvalidSBOMError{}
	vti.ResultExpectedInnerError = &ItemHasPropertiesError{}
	document, _, err := innerValidateInvalidSBOMInnerError(t, *vti)
	getLogger().Tracef("filename: '%s', error: '%s'", document.GetFilename(), err)
}

// isUnique(): Success - BOM "metadata.properties" has a unique "disclaimer" property
func TestValidateCustomCdx16_MetadataPropsUniqueDisclaimer(t *testing.T) {
	// getLogger().SetLevel(log.TRACE)
	getLogger().SetLevel(log.TRACE)
	vti := NewValidateTestInfoMinimum(TEST_CUSTOM_CDX_1_6_CUSTOM)
	vti.CustomConfig = TEST_CUSTOM_METADATA_PROPS_DISCLAIMER_UNIQUE
	document, results, _ := innerTestValidate(t, *vti)
	getLogger().Tracef("filename: '%s', results:\n%v", document.GetFilename(), results)
}

// isUnique(): Fail - BOM "properties" has a unique "disclaimer" property
func TestValidateCustomCdx16_MetadataPropsNotUnique(t *testing.T) {
	// getLogger().SetLevel(log.TRACE)
	vti := NewValidateTestInfoMinimum(TEST_CUSTOM_CDX_1_6_CUSTOM)
	vti.CustomConfig = TEST_CUSTOM_BOM_PROPS_NOT_UNIQUE
	vti.ResultExpectedError = &InvalidSBOMError{}
	vti.ResultExpectedInnerError = &ItemIsUniqueError{}
	document, _, err := innerValidateInvalidSBOMInnerError(t, *vti)
	getLogger().Tracef("filename: '%s', error: '%s'", document.GetFilename(), err)
}

// invalid tests
func TestValidateCustomCdx16_BOMPropertiesNotUnique(t *testing.T) {
	// getLogger().SetLevel(log.TRACE)
	vti := NewValidateTestInfoMinimum(TEST_CUSTOM_CDX_1_6_CUSTOM)
	vti.CustomConfig = TEST_CUSTOM_BOM_PROPS_NOT_UNIQUE
	vti.ResultExpectedError = &InvalidSBOMError{}
	vti.ResultExpectedInnerError = &ItemIsUniqueError{}
	document, _, err := innerValidateInvalidSBOMInnerError(t, *vti)
	getLogger().Tracef("filename: '%s', error: '%s'", document.GetFilename(), err)
}

// -------------------------------------------
// FAIL - Uniqueness tests
// -------------------------------------------
// Note: The "uniqueness" constraint for objects is not supported in JSON schema v7

func TestValidateCustomCdx14MetadataPropertyDisclaimerUnique(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CUSTOM_CDX_1_4_METADATA_PROPS_DISCLAIMER_UNIQUE)
	vti.CustomConfig = TEST_CUSTOM_METADATA_PROPS_DISCLAIMER_UNIQUE
	vti.ResultExpectedError = &InvalidSBOMError{}
	vti.ResultExpectedInnerError = &ItemIsUniqueError{}
	document, _, err := innerValidateInvalidSBOMInnerError(t, *vti)
	getLogger().Tracef("filename: '%s', error: '%s'", document.GetFilename(), err)
}

func TestValidateCustomCdx14MetadataPropertyDisclaimerMatch(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CUSTOM_CDX_1_4_METADATA_PROPS_DISCLAIMER_INVALID)
	vti.CustomConfig = TEST_CUSTOM_METADATA_PROPS_DISCLAIMER_MATCH
	vti.ResultExpectedError = &InvalidSBOMError{}
	vti.ResultExpectedInnerError = &ItemHasPropertiesError{}
	document, _, err := innerValidateInvalidSBOMInnerError(t, *vti)
	getLogger().Tracef("filename: '%s', error: '%s'", document.GetFilename(), err)
}

func TestValidateCustomCdx14MetadataPropsMissingDisclaimer(t *testing.T) {
	vti := NewValidateTestInfo(TEST_CUSTOM_CDX_1_4_METADATA_PROPS_DISCLAIMER_MISSING,
		FORMAT_TEXT,
		SCHEMA_VARIANT_CUSTOM,
		&InvalidSBOMError{})
	vti.CustomBOMSchema = DEFAULT_CUSTOM_VALIDATION_CONFIG
	vti.ResultExpectedError = &InvalidSBOMError{}
	vti.ResultExpectedInnerError = &ItemIsUniqueError{}
	document, results, _ := innerTestValidate(t, *vti)
	getLogger().Debugf("filename: '%s', results:\n%v", document.GetFilename(), results)
}

// func TestValidateCustomCdx14MetadataPropsInvalidDisclaimer(t *testing.T) {
// 	// disclaimer property
// 	SCHEMA_ERROR_TYPE := "contains"
// 	SCHEMA_ERROR_FIELD := "metadata.properties"
// 	SCHEMA_ERROR_VALUE := ""
// 	innerTestSchemaErrorAndErrorResults(t,
// 		TEST_CUSTOM_CDX_1_4_METADATA_PROPS_DISCLAIMER_INVALID,
// 		SCHEMA_VARIANT_CUSTOM,
// 		SCHEMA_ERROR_TYPE,
// 		SCHEMA_ERROR_FIELD,
// 		SCHEMA_ERROR_VALUE)
// 	SCHEMA_ERROR_TYPE = "const"
// 	SCHEMA_ERROR_FIELD = "metadata.properties.0.value"
// 	SCHEMA_ERROR_VALUE = ""
// 	innerTestSchemaErrorAndErrorResults(t,
// 		TEST_CUSTOM_CDX_1_4_METADATA_PROPS_DISCLAIMER_INVALID,
// 		SCHEMA_VARIANT_CUSTOM,
// 		SCHEMA_ERROR_TYPE,
// 		SCHEMA_ERROR_FIELD,
// 		SCHEMA_ERROR_VALUE)
// }

// func TestValidateCustomCdx14MetadataPropsInvalidClassification(t *testing.T) {
// 	SCHEMA_ERROR_TYPE := "contains"
// 	SCHEMA_ERROR_FIELD := "metadata.properties"
// 	SCHEMA_ERROR_VALUE := ""
// 	innerTestSchemaErrorAndErrorResults(t,
// 		TEST_CUSTOM_CDX_1_4_METADATA_PROPS_CLASSIFICATION_INVALID,
// 		SCHEMA_VARIANT_CUSTOM,
// 		SCHEMA_ERROR_TYPE,
// 		SCHEMA_ERROR_FIELD,
// 		SCHEMA_ERROR_VALUE)
// 	SCHEMA_ERROR_TYPE = "const"
// 	SCHEMA_ERROR_FIELD = "metadata.properties.1.value"
// 	SCHEMA_ERROR_VALUE = ""
// 	innerTestSchemaErrorAndErrorResults(t,
// 		TEST_CUSTOM_CDX_1_4_METADATA_PROPS_CLASSIFICATION_INVALID,
// 		SCHEMA_VARIANT_CUSTOM,
// 		SCHEMA_ERROR_TYPE,
// 		SCHEMA_ERROR_FIELD,
// 		SCHEMA_ERROR_VALUE)
// }
