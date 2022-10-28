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

	"github.com/scs/sbom-utility/schema"
	"github.com/scs/sbom-utility/utils"
	"github.com/xeipuuv/gojsonschema"
)

// Custom-specific test files
const (

	// Root-level tests
	TEST_CUSTOM_CDX_1_3_INVALID_COMPOSITION_METADATA_COMPONENT = "test/custom/cdx-1-3-ibm-invalid-composition-metadata-component.json"

	// Metadata tests
	TEST_CUSTOM_CDX_1_4_METADATA_PROPS_DISCLAIMER_INVALID = "test/custom/cdx-1-4-test-custom-metadata-property-disclaimer-invalid.json"
	TEST_CUSTOM_CDX_1_4_METADATA_PROPS_DISCLAIMER_MISSING = "test/custom/cdx-1-4-test-custom-metadata-property-disclaimer-missing.json"
	TEST_CUSTOM_CDX_1_4_METADATA_PROPS_DISCLAIMER_UNIQUE  = "test/custom/cdx-1-4-test-custom-metadata-property-disclaimer-unique.json"
	TEST_CUSTOM_CDX_1_4_METADATA_PROPS_COVERAGE_INVALID   = "test/custom/cdx-1-4-test-custom-metadata-property-coverage-invalid.json"
	TEST_CUSTOM_CDX_1_4_METADATA_PROPS_COVERAGE_MISSING   = "test/custom/cdx-1-4-test-custom-metadata-property-coverage-missing.json"
	TEST_CUSTOM_CDX_1_4_METADATA_PROPS_COVERAGE_UNIQUE    = "test/custom/cdx-1-4-test-custom-metadata-property-coverage-unique.json"

	// License tests
	// Note: The "invalid" tests below is also used in "list" command tests
	// which tests for a "none found" warning messages being displayed to stdout
	TEST_CUSTOM_CDX_1_4_INVALID_LICENSES_NOT_FOUND = "test/custom/cdx-1-4-invalid-licenses-not-found.json"

	// Composition tests
	TEST_CUSTOM_CDX_1_4_COMPOSITION_HIERARCHICAL_COMPONENTS = "test/custom/cdx-1-4-hierarchical-component-list.json"
)

// -------------------------------------------
// Test wrappers
// -------------------------------------------

func innerCustomValidateError(t *testing.T, filename string, variant string, innerError error) (document *schema.Sbom, schemaErrors []gojsonschema.ResultError, actualError error) {
	utils.GlobalFlags.CustomValidation = true
	document, schemaErrors, actualError = innerValidateError(t, filename, variant, innerError)
	utils.GlobalFlags.CustomValidation = false
	return
}

func innerCustomValidateInvalidSBOMInnerError(t *testing.T, filename string, variant string, innerError error) (document *schema.Sbom, schemaErrors []gojsonschema.ResultError, actualError error) {
	utils.GlobalFlags.CustomValidation = true
	document, schemaErrors, actualError = innerValidateInvalidSBOMInnerError(t, filename, variant, innerError)
	utils.GlobalFlags.CustomValidation = false
	return
}

// -------------------------------------------
// Command & flag tests
// -------------------------------------------

// Test format unsupported (SPDX) for "--custom" flag
func TestValidateCustomFormatUnsupportedSPDX(t *testing.T) {
	innerCustomValidateError(t,
		TEST_SPDX_2_2_MIN_REQUIRED,
		SCHEMA_VARIANT_NONE,
		&schema.UnsupportedFormatError{})
}

// -------------------------------------------
// Schema: root tests
// -------------------------------------------

// Error if no licenses found in entirety of SBOM (variant none)
func TestValidateCustomErrorCdx14NoLicensesFound(t *testing.T) {
	innerCustomValidateError(t,
		TEST_CUSTOM_CDX_1_4_INVALID_LICENSES_NOT_FOUND,
		SCHEMA_VARIANT_NONE,
		&InvalidSBOMError{})
}

// -------------------------------------------
// Schema: metadata tests
// -------------------------------------------

func TestValidateCustomCdx14MetadataPropsMissingDisclaimer(t *testing.T) {
	document, results, _ := innerValidateError(t,
		TEST_CUSTOM_CDX_1_4_METADATA_PROPS_DISCLAIMER_MISSING,
		SCHEMA_VARIANT_IBM_DEV,
		&InvalidSBOMError{})
	getLogger().Debugf("filename: `%s`, results:\n%v", document.GetFilename(), results)
}

func TestValidateCustomCdx14MetadataPropsMissingCoverage(t *testing.T) {
	document, results, _ := innerValidateError(t,
		TEST_CUSTOM_CDX_1_4_METADATA_PROPS_COVERAGE_MISSING,
		SCHEMA_VARIANT_IBM_DEV,
		&InvalidSBOMError{})
	getLogger().Debugf("filename: `%s`, results:\n%v", document.GetFilename(), results)
}

func TestValidateCustomCdx14MetadataPropsInvalidDisclaimer(t *testing.T) {
	// disclaimer property
	SCHEMA_ERROR_TYPE := "contains"
	SCHEMA_ERROR_FIELD := "metadata.properties"
	SCHEMA_ERROR_VALUE := ""

	innerTestSchemaErrorAndErrorResults(t,
		TEST_CUSTOM_CDX_1_4_METADATA_PROPS_DISCLAIMER_INVALID,
		SCHEMA_VARIANT_IBM_DEV,
		SCHEMA_ERROR_TYPE,
		SCHEMA_ERROR_FIELD,
		SCHEMA_ERROR_VALUE)

	SCHEMA_ERROR_TYPE = "const"
	SCHEMA_ERROR_FIELD = "metadata.properties.0.value"
	SCHEMA_ERROR_VALUE = ""

	innerTestSchemaErrorAndErrorResults(t,
		TEST_CUSTOM_CDX_1_4_METADATA_PROPS_DISCLAIMER_INVALID,
		SCHEMA_VARIANT_IBM_DEV,
		SCHEMA_ERROR_TYPE,
		SCHEMA_ERROR_FIELD,
		SCHEMA_ERROR_VALUE)
}

func TestValidateCustomCdx14MetadataPropsInvalidCoverage(t *testing.T) {
	// coverage property
	SCHEMA_ERROR_TYPE := "contains"
	SCHEMA_ERROR_FIELD := "metadata.properties"
	SCHEMA_ERROR_VALUE := ""

	innerTestSchemaErrorAndErrorResults(t,
		TEST_CUSTOM_CDX_1_4_METADATA_PROPS_COVERAGE_INVALID,
		SCHEMA_VARIANT_IBM_DEV,
		SCHEMA_ERROR_TYPE,
		SCHEMA_ERROR_FIELD,
		SCHEMA_ERROR_VALUE)

	SCHEMA_ERROR_TYPE = "const"
	SCHEMA_ERROR_FIELD = "metadata.properties.1.value"
	SCHEMA_ERROR_VALUE = ""

	innerTestSchemaErrorAndErrorResults(t,
		TEST_CUSTOM_CDX_1_4_METADATA_PROPS_COVERAGE_INVALID,
		SCHEMA_VARIANT_IBM_DEV,
		SCHEMA_ERROR_TYPE,
		SCHEMA_ERROR_FIELD,
		SCHEMA_ERROR_VALUE)
}

// -------------------------------------------
// Property uniqueness tests
// -------------------------------------------
// Note: The "uniqueness" constraint for objects is not supported in JSON schema v7
func TestValidateCustomCdx14MetadataPropertyUniqueDisclaimer(t *testing.T) {
	document, results, _ := innerCustomValidateInvalidSBOMInnerError(t,
		TEST_CUSTOM_CDX_1_4_METADATA_PROPS_DISCLAIMER_UNIQUE,
		SCHEMA_VARIANT_IBM_DEV,
		&SBOMMetadataPropertyError{})
	getLogger().Debugf("filename: `%s`, results:\n%v", document.GetFilename(), results)
}

func TestValidateCustomCdx14MetadataPropertyUniqueCoverage(t *testing.T) {
	document, results, _ := innerCustomValidateInvalidSBOMInnerError(t,
		TEST_CUSTOM_CDX_1_4_METADATA_PROPS_DISCLAIMER_UNIQUE,
		SCHEMA_VARIANT_IBM_DEV,
		&SBOMMetadataPropertyError{})
	getLogger().Debugf("filename: `%s`, results:\n%v", document.GetFilename(), results)
}

// -------------------------------------------
// Composition tests
// -------------------------------------------

// Error if hierarchical components found in top-level "metadata.component" object
func TestValidateCustomErrorCdx13InvalidCompositionMetadataComponent(t *testing.T) {
	innerCustomValidateInvalidSBOMInnerError(t,
		TEST_CUSTOM_CDX_1_3_INVALID_COMPOSITION_METADATA_COMPONENT,
		SCHEMA_VARIANT_IBM_DEV,
		&SBOMCompositionError{})
}

// Make sure we can List all components in an SBOM, including those in hierarchical compositions
// TODO: should actually test for component count
func TestValidateCustomCompositionHierarchicalComponentList(t *testing.T) {
	innerValidateError(t,
		TEST_CUSTOM_CDX_1_4_COMPOSITION_HIERARCHICAL_COMPONENTS,
		SCHEMA_VARIANT_NONE,
		nil)
}
