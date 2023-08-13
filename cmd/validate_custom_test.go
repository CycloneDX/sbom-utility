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

	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/CycloneDX/sbom-utility/utils"
	"github.com/xeipuuv/gojsonschema"
)

// Custom JSON schema files for testing
const (
	SCHEMA_VARIANT_CUSTOM      = "custom"
	TEST_SCHEMA_CDX_1_3_CUSTOM = "resources/schema/test/bom-1.3-custom.schema.json"
	TEST_SCHEMA_CDX_1_4_CUSTOM = "resources/schema/test/bom-1.4-custom.schema.json"
)

// Custom-specific test files
const (
	// Metadata tests
	TEST_CUSTOM_CDX_1_4_METADATA_PROPS_DISCLAIMER_INVALID     = "test/custom/cdx-1-4-test-custom-metadata-property-disclaimer-invalid.json"
	TEST_CUSTOM_CDX_1_4_METADATA_PROPS_DISCLAIMER_MISSING     = "test/custom/cdx-1-4-test-custom-metadata-property-disclaimer-missing.json"
	TEST_CUSTOM_CDX_1_4_METADATA_PROPS_DISCLAIMER_UNIQUE      = "test/custom/cdx-1-4-test-custom-metadata-property-disclaimer-unique.json"
	TEST_CUSTOM_CDX_1_4_METADATA_PROPS_CLASSIFICATION_INVALID = "test/custom/cdx-1-4-test-custom-metadata-property-classification-invalid.json"
	TEST_CUSTOM_CDX_1_4_METADATA_PROPS_CLASSIFICATION_MISSING = "test/custom/cdx-1-4-test-custom-metadata-property-classification-missing.json"
	TEST_CUSTOM_CDX_1_4_METADATA_PROPS_CLASSIFICATION_UNIQUE  = "test/custom/cdx-1-4-test-custom-metadata-property-classification-unique.json"

	// License tests
	// Note: The "invalid" tests below is also used in "list" command tests
	// which tests for a "none found" warning messages being displayed to stdout
	TEST_CUSTOM_CDX_1_4_INVALID_LICENSES_NOT_FOUND = TEST_LICENSE_LIST_CDX_1_4_NONE_FOUND

	// Composition
	TEST_CUSTOM_CDX_1_3_INVALID_COMPOSITION_COMPONENTS         = "test/custom/cdx-1-3-test-custom-invalid-composition-components.json"
	TEST_CUSTOM_CDX_1_3_INVALID_COMPOSITION_METADATA_COMPONENT = "test/custom/cdx-1-3-test-custom-invalid-composition-metadata-component.json"
)

// -------------------------------------------
// Test wrappers
// -------------------------------------------

func innerTestValidateCustom(t *testing.T, vti ValidateTestInfo) (document *schema.BOM, schemaErrors []gojsonschema.ResultError, actualError error) {
	utils.GlobalFlags.ValidateFlags.CustomValidation = true
	document, schemaErrors, actualError = innerTestValidate(t, vti)
	utils.GlobalFlags.ValidateFlags.CustomValidation = false
	return
}

func innerTestValidateCustomInvalidSBOMInnerError(t *testing.T, filename string, variant string, innerError error) (document *schema.BOM, schemaErrors []gojsonschema.ResultError, actualError error) {
	utils.GlobalFlags.ValidateFlags.CustomValidation = true
	document, schemaErrors, actualError = innerValidateInvalidSBOMInnerError(t, filename, variant, innerError)
	utils.GlobalFlags.ValidateFlags.CustomValidation = false
	return
}

// -------------------------------------------
// Command & flag tests
// -------------------------------------------

// Test format unsupported (SPDX) for "--custom" flag
func TestValidateCustomFormatUnsupportedSPDX(t *testing.T) {
	vti := NewValidateTestInfo(TEST_SPDX_2_2_MIN_REQUIRED, FORMAT_ANY, SCHEMA_VARIANT_NONE, &schema.UnsupportedFormatError{})
	innerTestValidateCustom(t, *vti)
}

// -------------------------------------------
// Schema: cross-document tests
// -------------------------------------------

// Error if no licenses found in entirety of SBOM (variant none)
func TestValidateCustomErrorCdx14NoLicensesFound(t *testing.T) {
	vti := NewValidateTestInfo(TEST_CUSTOM_CDX_1_4_INVALID_LICENSES_NOT_FOUND, FORMAT_ANY, SCHEMA_VARIANT_NONE, &InvalidSBOMError{})
	document, results, _ := innerTestValidateCustom(t, *vti)
	getLogger().Debugf("filename: `%s`, results:\n%v", document.GetFilename(), results)
}

// -------------------------------------------
// Schema: metadata tests
// -------------------------------------------

func TestValidateCustomCdx14MetadataPropsMissingDisclaimer(t *testing.T) {
	vti := NewValidateTestInfo(TEST_CUSTOM_CDX_1_4_METADATA_PROPS_DISCLAIMER_MISSING, FORMAT_TEXT, SCHEMA_VARIANT_CUSTOM, &InvalidSBOMError{})
	document, results, _ := innerTestValidate(t, *vti)
	getLogger().Debugf("filename: `%s`, results:\n%v", document.GetFilename(), results)
}

func TestValidateCustomCdx14MetadataPropsMissingClassification(t *testing.T) {
	vti := NewValidateTestInfo(TEST_CUSTOM_CDX_1_4_METADATA_PROPS_CLASSIFICATION_MISSING, FORMAT_TEXT, SCHEMA_VARIANT_CUSTOM, &InvalidSBOMError{})
	document, results, _ := innerTestValidate(t, *vti)
	getLogger().Debugf("filename: `%s`, results:\n%v", document.GetFilename(), results)
}

func TestValidateCustomCdx14MetadataPropsInvalidDisclaimer(t *testing.T) {
	// disclaimer property
	SCHEMA_ERROR_TYPE := "contains"
	SCHEMA_ERROR_FIELD := "metadata.properties"
	SCHEMA_ERROR_VALUE := ""

	innerTestSchemaErrorAndErrorResults(t,
		TEST_CUSTOM_CDX_1_4_METADATA_PROPS_DISCLAIMER_INVALID,
		SCHEMA_VARIANT_CUSTOM,
		SCHEMA_ERROR_TYPE,
		SCHEMA_ERROR_FIELD,
		SCHEMA_ERROR_VALUE)

	SCHEMA_ERROR_TYPE = "const"
	SCHEMA_ERROR_FIELD = "metadata.properties.0.value"
	SCHEMA_ERROR_VALUE = ""

	innerTestSchemaErrorAndErrorResults(t,
		TEST_CUSTOM_CDX_1_4_METADATA_PROPS_DISCLAIMER_INVALID,
		SCHEMA_VARIANT_CUSTOM,
		SCHEMA_ERROR_TYPE,
		SCHEMA_ERROR_FIELD,
		SCHEMA_ERROR_VALUE)
}

func TestValidateCustomCdx14MetadataPropsInvalidClassification(t *testing.T) {

	SCHEMA_ERROR_TYPE := "contains"
	SCHEMA_ERROR_FIELD := "metadata.properties"
	SCHEMA_ERROR_VALUE := ""

	innerTestSchemaErrorAndErrorResults(t,
		TEST_CUSTOM_CDX_1_4_METADATA_PROPS_CLASSIFICATION_INVALID,
		SCHEMA_VARIANT_CUSTOM,
		SCHEMA_ERROR_TYPE,
		SCHEMA_ERROR_FIELD,
		SCHEMA_ERROR_VALUE)

	SCHEMA_ERROR_TYPE = "const"
	SCHEMA_ERROR_FIELD = "metadata.properties.1.value"
	SCHEMA_ERROR_VALUE = ""

	innerTestSchemaErrorAndErrorResults(t,
		TEST_CUSTOM_CDX_1_4_METADATA_PROPS_CLASSIFICATION_INVALID,
		SCHEMA_VARIANT_CUSTOM,
		SCHEMA_ERROR_TYPE,
		SCHEMA_ERROR_FIELD,
		SCHEMA_ERROR_VALUE)
}

// -------------------------------------------
// Property uniqueness tests
// -------------------------------------------
// Note: The "uniqueness" constraint for objects is not supported in JSON schema v7

func TestValidateCustomCdx14MetadataPropertyUniqueDisclaimer(t *testing.T) {
	document, results, _ := innerTestValidateCustomInvalidSBOMInnerError(t,
		TEST_CUSTOM_CDX_1_4_METADATA_PROPS_DISCLAIMER_UNIQUE,
		SCHEMA_VARIANT_NONE,
		&SBOMMetadataPropertyError{})
	getLogger().Debugf("filename: `%s`, results:\n%v", document.GetFilename(), results)
}

func TestValidateCustomCdx14MetadataPropertyUniqueClassification(t *testing.T) {
	document, results, _ := innerTestValidateCustomInvalidSBOMInnerError(t,
		TEST_CUSTOM_CDX_1_4_METADATA_PROPS_DISCLAIMER_UNIQUE,
		SCHEMA_VARIANT_NONE,
		&SBOMMetadataPropertyError{})
	getLogger().Debugf("filename: `%s`, results:\n%v", document.GetFilename(), results)
}

// -------------------------------------------
// Composition tests
// -------------------------------------------

// Error if hierarchical components found in top-level "metadata.component" object
func TestValidateCustomErrorCdx13InvalidCompositionMetadataComponent(t *testing.T) {
	innerTestValidateCustomInvalidSBOMInnerError(t,
		TEST_CUSTOM_CDX_1_3_INVALID_COMPOSITION_METADATA_COMPONENT,
		SCHEMA_VARIANT_NONE,
		&SBOMCompositionError{})
}

// Error if hierarchical components in top-level "components" array
func TestValidateCustomErrorCdx13InvalidCompositionComponents(t *testing.T) {
	innerTestValidateCustomInvalidSBOMInnerError(t,
		TEST_CUSTOM_CDX_1_3_INVALID_COMPOSITION_METADATA_COMPONENT,
		SCHEMA_VARIANT_NONE,
		&SBOMCompositionError{})
}

// Make sure we can List all components in an SBOM, including those in hierarchical compositions
// TODO: Actually verify one or more of the hierarchical comps. appear in list results
// func TestValidateCustomCompositionHierarchicalComponentList(t *testing.T) {
// 	innerCustomValidateError(t,
// 		TEST_CUSTOM_CDX_1_4_COMPOSITION_HIERARCHICAL_COMPONENTS,
// 		SCHEMA_VARIANT_NONE,
// 		nil)
// }
