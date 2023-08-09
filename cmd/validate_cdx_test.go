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

import "testing"

// Consolidate test file name declarations
const (
	// CycloneDX - Test versioned documents meet min. schema requirements
	TEST_CDX_1_3_MIN_REQUIRED = "test/cyclonedx/cdx-1-3-min-required.json"
	TEST_CDX_1_4_MIN_REQUIRED = "test/cyclonedx/cdx-1-4-min-required.json"
	TEST_CDX_1_5_MIN_REQUIRED = "test/cyclonedx/cdx-1-5-min-required.json"
)

// Mature SBOMs used to test various schemas and queries
const (
	TEST_CDX_1_3_MATURITY_EXAMPLE_1_BASE = "test/cyclonedx/cdx-1-3-mature-example-1.json"
	TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE = "test/cyclonedx/cdx-1-4-mature-example-1.json"
	TEST_CDX_1_5_MATURITY_EXAMPLE_1_BASE = "test/cyclonedx/cdx-1-5-mature-example-1.json"
)

const (
	// (invalid) schema tests
	TEST_SCHEMA_CDX_1_3_INVALID_LICENSE_CHOICE = "test/cyclonedx/cdx-1-3-invalid-license-choice-oneof.json"
	TEST_SCHEMA_CDX_1_3_INVALID_LICENSE_ID     = "test/cyclonedx/cdx-1-3-invalid-spdx-license-id.json"
	TEST_SCHEMA_CDX_1_4_INVALID_LICENSE_ID     = "test/cyclonedx/cdx-1-3-invalid-spdx-license-id.json"
	TEST_SCHEMA_CDX_1_4_INVALID_EMAIL_FORMAT   = "test/cyclonedx/cdx-1-4-invalid-email-format.json"
)

// -----------------------------------------------------------
// CycloneDX - Min. requirement & Mature tests
// -----------------------------------------------------------

func TestValidateCdx13MinRequiredBasic(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_3_MIN_REQUIRED)
	innerValidateTest(t, *vti)
}

func TestValidateCdx14MinRequiredBasic(t *testing.T) {
	innerValidateError(t, TEST_CDX_1_4_MIN_REQUIRED, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
}

func TestValidateCdx15MinRequiredBasic(t *testing.T) {
	innerValidateError(t, TEST_CDX_1_5_MIN_REQUIRED, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
}

func TestValidateCdx13Mature(t *testing.T) {
	innerValidateError(t, TEST_CDX_1_3_MATURITY_EXAMPLE_1_BASE, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
}

func TestValidateCdx14MMature(t *testing.T) {
	innerValidateError(t, TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
}

func TestValidateCdx15Mature(t *testing.T) {
	innerValidateError(t, TEST_CDX_1_5_MATURITY_EXAMPLE_1_BASE, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
}

// -----------------------------------------------------------
// CycloneDX - (invalid) schema tests
// -----------------------------------------------------------
// NOTE: Schema errors do not have an "inner error", but return "[]gojsonschema.ResultError"
// This means that these "errors" ARE NOT surfaced in the error return from Validate(); instead,
// a `[]gojsonschema.ResultError` (custom error) is returned in the "results" array
// -----------------------------------------------------------

// Ensure invalid "id" in a License object is caught (i.e., "UNKNOWN" is not a valid SPDX ID value)
func TestValidateSchemaCdx13InvalidSPDXLicenseId(t *testing.T) {
	SCHEMA_ERROR_TYPE := "enum"
	SCHEMA_ERROR_FIELD := "components.1.licenses.0.license.id"
	SCHEMA_ERROR_VALUE := "UNKNOWN"

	innerTestSchemaErrorAndErrorResults(t,
		TEST_SCHEMA_CDX_1_3_INVALID_LICENSE_ID,
		SCHEMA_VARIANT_NONE,
		SCHEMA_ERROR_TYPE,
		SCHEMA_ERROR_FIELD,
		SCHEMA_ERROR_VALUE)
}

// (v1.4+) Ensure invalid email value (format) is caught (i.e., type not "idn-email")
func TestValidateSchemaCdx14InvalidEmailFormat(t *testing.T) {
	SCHEMA_ERROR_TYPE := "format"
	SCHEMA_ERROR_FIELD := "metadata.supplier.contact.0.email"
	SCHEMA_ERROR_VALUE := "https://acme.com"

	innerTestSchemaErrorAndErrorResults(t,
		TEST_SCHEMA_CDX_1_4_INVALID_EMAIL_FORMAT,
		SCHEMA_VARIANT_NONE,
		SCHEMA_ERROR_TYPE,
		SCHEMA_ERROR_FIELD,
		SCHEMA_ERROR_VALUE)
}

// (v1.2+) Ensure invalid LicenseChoice object is caught (i.e., has BOTH an "id" and "name")
func TestValidateSchemaCdx13InvalidLicenseChoice(t *testing.T) {
	SCHEMA_ERROR_TYPE := "number_one_of"
	SCHEMA_ERROR_FIELD := "metadata.component.licenses.0.license"
	// Note: the value returned is not a simple string so do not test this
	// field of the error results.
	SCHEMA_ERROR_VALUE := ""

	innerTestSchemaErrorAndErrorResults(t,
		TEST_SCHEMA_CDX_1_3_INVALID_LICENSE_CHOICE,
		SCHEMA_VARIANT_NONE,
		SCHEMA_ERROR_TYPE,
		SCHEMA_ERROR_FIELD,
		SCHEMA_ERROR_VALUE)
}
