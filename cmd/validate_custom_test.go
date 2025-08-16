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
	TEST_CUSTOM_CDX_1_6_BOM_BEST_PRACTICES_EXAMPLE = "test/custom/cdx-1-6-test-bom-best-practices.json"
	TEST_CUSTOM_CDX_1_6_BOM_PROPERTIES             = "test/custom/cdx-1-6-test-bom-properties.json"
	TEST_CUSTOM_CDX_1_6_BOM_METADATA               = "test/custom/cdx-1-6-test-bom-metadata.json"

	// TEST_CUSTOM_CDX_1_6_METADATA_PROPS_CLASSIFICATION_MULTIPLE = "test/custom/cdx-1-6-test-metedata-properties-classification-multiple.json"
	TEST_CUSTOM_CDX_1_6_METADATA_PROPS_DISCLAIMER_MISMATCH = "test/custom/cdx-1-6-test-metedata-properties-disclaimer-mismatch.json"
	TEST_CUSTOM_CDX_1_6_METADATA_PROPS_DISCLAIMER_MISSING  = "test/custom/cdx-1-6-test-metedata-properties-disclaimer-missing.json"
	TEST_CUSTOM_CDX_1_6_METADATA_PROPS_DISCLAIMER_UNIQUE   = "test/custom/cdx-1-6-test-metedata-properties-disclaimer.json"
)

// -------------------------------------------
// Custom Configuration test files
// -------------------------------------------

// SPDX
const (
	CONFIG_SPDX_2_X_STRUCTURE = "test/custom/config-spdx-bom-properties.json"
)

// CycloneDX
const (
	CONFIG_CDX_BOM_BEST_PRACTICE_PROFILE         = "test/custom/config-cdx-best-practices-profile.json"
	CONFIG_CDX_BOM_PROPS_NOT_UNIQUE              = "test/custom/config-cdx-bom-properties-not-unique.json"
	CONFIG_CDX_BOM_PROPS_PK_MISSING              = "test/custom/config-cdx-bom-properties-primary-key-missing.json"
	CONFIG_CDX_BOM_PROPS_UNIQUE                  = "test/custom/config-cdx-bom-properties-unique.json"
	CONFIG_CDX_BOM_STRUCTURE                     = "test/custom/config-cdx-bom-structure.json"
	CONFIG_CDX_METADATA_ELEMENTS_FOUND           = "test/custom/config-cdx-metadata-elements-found.json"
	CONFIG_CDX_METADATA_ELEMENTS_NOT_FOUND       = "test/custom/config-cdx-metadata-elements-not-found.json"
	CONFIG_CDX_METADATA_PROPS_DISCLAIMER_MATCH   = "test/custom/config-cdx-metadata-properties-disclaimer-match.json"
	CONFIG_CDX_METADATA_PROPS_DISCLAIMER_MISSING = "test/custom/config-cdx-metadata-properties-disclaimer-missing.json"
	// TODO
	CONFIG_CDX_METADATA_PROPS_DISCLAIMER_UNIQUE       = "test/custom/config-cdx-metadata-properties-disclaimer-unique.json"
	CONFIG_CDX_METADATA_PROPS_DISCLAIMER_UNIQUE_MATCH = "test/custom/config-cdx-metadata-properties-disclaimer-unique-match.json"
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
	vti.CustomConfig = CONFIG_SPDX_2_X_STRUCTURE
	innerTestValidate(t, *vti)
}

func TestValidateCustomFormatUnsupportedSPDX_2_3(t *testing.T) {
	// getLogger().SetLevel(log.TRACE)
	vti := NewValidateTestInfo(TEST_SPDX_2_3_EXAMPLE_PACKAGE_BOM,
		FORMAT_ANY,
		SCHEMA_VARIANT_NONE,
		&schema.UnsupportedFormatError{})
	vti.CustomConfig = CONFIG_SPDX_2_X_STRUCTURE
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

// isUnique(): Success - BOM "properties" has a unique property with key-value: "name": "yyz"
func TestValidateCustomCdx16_BOMPropsUnique(t *testing.T) {
	// getLogger().SetLevel(log.TRACE)
	vti := NewValidateTestInfoMinimum(TEST_CUSTOM_CDX_1_6_BOM_PROPERTIES)
	vti.CustomConfig = CONFIG_CDX_BOM_PROPS_UNIQUE
	document, _, err := innerTestValidate(t, *vti)
	getLogger().Tracef("filename: '%s', error: '%s'", document.GetFilename(), err)
}

// isUnique(): Failure - BOM "properties" does not have a unique property with key-value: "name": "foo" (i.e., "foo" appears twice)
func TestValidateCustomCdx16_BOMPropsNotUnique(t *testing.T) {
	// getLogger().SetLevel(log.TRACE)
	vti := NewValidateTestInfoMinimum(TEST_CUSTOM_CDX_1_6_BOM_PROPERTIES)
	vti.CustomConfig = CONFIG_CDX_BOM_PROPS_NOT_UNIQUE
	vti.ResultExpectedError = &InvalidSBOMError{}
	vti.ResultExpectedInnerError = &ItemIsUniqueError{}
	document, _, err := innerValidateInvalidSBOMInnerError(t, *vti)
	getLogger().Tracef("filename: '%s', error: '%s'", document.GetFilename(), err)
}

// -------------------------------------------
// CycloneDX - hasProperties tests
// -------------------------------------------

// hasProperties(): Success - BOM has a representative set of "best practice" elements or "profile"
func TestValidateCustomCdx16_BOMBestPracticeExample(t *testing.T) {
	// getLogger().SetLevel(log.TRACE)
	vti := NewValidateTestInfoMinimum(TEST_CUSTOM_CDX_1_6_BOM_BEST_PRACTICES_EXAMPLE)
	vti.CustomConfig = CONFIG_CDX_BOM_BEST_PRACTICE_PROFILE
	document, results, _ := innerTestValidate(t, *vti)
	getLogger().Tracef("filename: '%s', results:\n%v", document.GetFilename(), results)
}

// hasProperties(): Success - BOM elements are structured against a "best practice" profile
func TestValidateCustomCdx16_BOMStructure(t *testing.T) {
	// getLogger().SetLevel(log.TRACE)
	vti := NewValidateTestInfoMinimum(TEST_CUSTOM_CDX_1_6_BOM_BEST_PRACTICES_EXAMPLE)
	vti.CustomConfig = CONFIG_CDX_BOM_STRUCTURE
	document, results, _ := innerTestValidate(t, *vti)
	getLogger().Tracef("filename: '%s', results:\n%v", document.GetFilename(), results)
}

// hasProperties(): Success - Has elements in BOM "metadata"
func TestValidateCustomCdx16_MetadataElementsFound(t *testing.T) {
	// getLogger().SetLevel(log.TRACE)
	vti := NewValidateTestInfoMinimum(TEST_CUSTOM_CDX_1_6_BOM_METADATA)
	vti.CustomConfig = CONFIG_CDX_METADATA_ELEMENTS_FOUND
	document, results, _ := innerTestValidate(t, *vti)
	getLogger().Tracef("filename: '%s', results:\n%v", document.GetFilename(), results)
}

// hasProperties(): Failure - missing element in BOM "metadata"
func TestValidateCustomCdx16_MetadataElementsNotFound(t *testing.T) {
	// getLogger().SetLevel(log.TRACE)
	vti := NewValidateTestInfoMinimum(TEST_CUSTOM_CDX_1_6_BOM_METADATA)
	vti.CustomConfig = CONFIG_CDX_METADATA_ELEMENTS_NOT_FOUND
	vti.ResultExpectedError = &InvalidSBOMError{}
	vti.ResultExpectedInnerError = &ItemHasPropertiesError{}
	document, _, err := innerValidateInvalidSBOMInnerError(t, *vti)
	getLogger().Tracef("filename: '%s', error: '%s'", document.GetFilename(), err)
}

// -------------------------------------------
// Disclaimer variant tests
// -------------------------------------------

// isUnique(): Success - BOM "metadata.properties" has a unique "disclaimer" property
func TestValidateCustomCdx16_MetadataPropsDisclaimerUnique(t *testing.T) {
	// getLogger().SetLevel(log.TRACE)
	getLogger().SetLevel(log.TRACE)
	vti := NewValidateTestInfoMinimum(TEST_CUSTOM_CDX_1_6_METADATA_PROPS_DISCLAIMER_UNIQUE)
	vti.CustomConfig = CONFIG_CDX_METADATA_PROPS_DISCLAIMER_UNIQUE
	document, results, _ := innerTestValidate(t, *vti)
	getLogger().Tracef("filename: '%s', results:\n%v", document.GetFilename(), results)
}

// hasProperties(): Failure
func TestValidateCustomCdx16MetadataPropertyDisclaimerMismatch(t *testing.T) {
	// getLogger().SetLevel(log.TRACE)
	vti := NewValidateTestInfoMinimum(TEST_CUSTOM_CDX_1_6_METADATA_PROPS_DISCLAIMER_MISMATCH)
	vti.CustomConfig = CONFIG_CDX_METADATA_PROPS_DISCLAIMER_MATCH
	vti.ResultExpectedError = &InvalidSBOMError{}
	vti.ResultExpectedInnerError = &ItemHasPropertiesError{}
	document, _, err := innerValidateInvalidSBOMInnerError(t, *vti)
	getLogger().Tracef("filename: '%s', error: '%s'", document.GetFilename(), err)
}

// hasProperties(): Failure
func TestValidateCustomCdx16MetadataPropertyDisclaimerMissing(t *testing.T) {
	// getLogger().SetLevel(log.TRACE)
	vti := NewValidateTestInfoMinimum(TEST_CUSTOM_CDX_1_6_METADATA_PROPS_DISCLAIMER_MISSING)
	vti.CustomConfig = CONFIG_CDX_METADATA_PROPS_DISCLAIMER_MISSING
	vti.ResultExpectedError = &InvalidSBOMError{}
	vti.ResultExpectedInnerError = &JSONElementNotFoundError{}
	document, _, err := innerValidateInvalidSBOMInnerError(t, *vti)
	getLogger().Tracef("filename: '%s', error: '%s'", document.GetFilename(), err)
}
