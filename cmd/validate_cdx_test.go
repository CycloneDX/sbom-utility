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

import "testing"

// Consolidate test file name declarations
const (
	// CycloneDX - Test versioned documents meet min. schema requirements
	TEST_CDX_1_3_MIN_REQUIRED = "test/cyclonedx/cdx-1-3-min-required.json"
	TEST_CDX_1_4_MIN_REQUIRED = "test/cyclonedx/cdx-1-4-min-required.json"
	TEST_CDX_1_5_MIN_REQUIRED = "test/cyclonedx/cdx-1-5-min-required.json"
	TEST_CDX_1_6_MIN_REQUIRED = "test/cyclonedx/1.6/cdx-1-6-min-required.json"
	TEST_CDX_1_7_MIN_REQUIRED = "test/cyclonedx/1.7/cdx-1-7-min-required.json"
)

// Tests for MLBOM subtypes
const (
	TEST_CDX_1_6_MACHINE_LEARNING_BOM = "test/cyclonedx/1.6/cdx-1-6-valid-mlbom-environmental-considerations.json"
)

// Tests for CBOM subtypes
const (
	TEST_CDX_1_6_CRYPTO_BOM = "test/cyclonedx/1.6/cdx-1-6-valid-cbom-full-1.6.json"
)

// Mature SBOMs used to test various schemas and queries
const (
	TEST_CDX_1_3_MATURE_EXAMPLE_1_BASE = "test/cyclonedx/cdx-1-3-mature-example-1.json"
	TEST_CDX_1_4_MATURE_EXAMPLE_1_BASE = "test/cyclonedx/cdx-1-4-mature-example-1.json"
	TEST_CDX_1_5_MATURE_EXAMPLE_1_BASE = "test/cyclonedx/cdx-1-5-mature-example-1.json"
)

const (
	// (invalid) schema tests
	TEST_SCHEMA_CDX_1_3_INVALID_LICENSE_CHOICE = "test/cyclonedx/cdx-1-3-invalid-license-choice-oneof.json"
	TEST_SCHEMA_CDX_1_3_INVALID_LICENSE_ID     = "test/cyclonedx/cdx-1-3-invalid-spdx-license-id.json"
	TEST_SCHEMA_CDX_1_4_INVALID_LICENSE_ID     = "test/cyclonedx/cdx-1-3-invalid-spdx-license-id.json"
	TEST_SCHEMA_CDX_1_4_INVALID_EMAIL_FORMAT   = "test/cyclonedx/cdx-1-4-invalid-email-format.json"
)

// Copied from CycloneDX spec. repo.
// See: https://github.com/CycloneDX/specification/tree/master/tools/src/test/resources/1.6
const (
	TEST_CDX_SPEC_1_6_VALID_BOM             = "test/cyclonedx/1.6/specification/valid-bom-1.6.json"
	TEST_CDX_SPEC_1_6_VALID_ANNOTATION      = "test/cyclonedx/1.6/specification/valid-annotation-1.6.json"
	TEST_CDX_SPEC_1_6_VALID_ATTESTATION     = "test/cyclonedx/1.6/specification/valid-attestation-1.6.json"
	TEST_CDX_SPEC_1_6_VALID_COMPONENT_HASH  = "test/cyclonedx/1.6/specification/valid-component-hashes-1.6.json"
	TEST_CDX_SPEC_1_6_VALID_COMPONENT_IDS   = "test/cyclonedx/1.6/specification/valid-component-identifiers-1.6.json"
	TEST_CDX_SPEC_1_6_VALID_SWID            = "test/cyclonedx/1.6/specification/valid-component-swid-1.6.json"
	TEST_CDX_SPEC_1_6_VALID_SWID_FULL       = "test/cyclonedx/1.6/specification/valid-component-swid-full-1.6.json"
	TEST_CDX_SPEC_1_6_VALID_COMPONENT_TYPES = "test/cyclonedx/1.6/specification/valid-component-types-1.6.json"
	TEST_CDX_SPEC_1_6_VALID_CRYPTO_IMPL     = "test/cyclonedx/1.6/specification/valid-cryptography-implementation-1.6.json"
	TEST_CDX_SPEC_1_6_VALID_EVIDENCE        = "test/cyclonedx/1.6/specification/valid-evidence-1.6.json"
	TEST_CDX_SPEC_1_6_VALID_LICENSE_EXP     = "test/cyclonedx/1.6/specification/valid-license-expression-1.6.json"
	TEST_CDX_SPEC_1_6_VALID_LICENSING       = "test/cyclonedx/1.6/specification/valid-license-licensing-1.6.json"
	TEST_CDX_SPEC_1_6_VALID_ML              = "test/cyclonedx/1.6/specification/valid-machine-learning-1.6.json"
	TEST_CDX_SPEC_1_6_VALID_ML_ENV          = "test/cyclonedx/1.6/specification/valid-machine-learning-considerations-env-1.6.json"
	TEST_CDX_SPEC_1_6_VALID_METADATA_TOOL   = "test/cyclonedx/1.6/specification/valid-metadata-tool-1.6.json"
	TEST_CDX_SPEC_1_6_VALID_SAASBOM         = "test/cyclonedx/1.6/specification/valid-saasbom-1.6.json"
	TEST_CDX_SPEC_1_6_VALID_VULNERABILITY   = "test/cyclonedx/1.6/specification/valid-vulnerability-1.6.json"
	TEST_CDX_SPEC_1_6_VALID_EXT_REF_IRI     = "test/validation/cdx-1-6-validate-component-ext-ref-iri-reference.json"
	TEST_CDX_SPEC_1_6_1_VALID_SPDX_LICENSE  = "test/cyclonedx/1.6/specification/valid-license-spdx-licenses-1.6.1.json"
)

const (
	TEST_CDX_SPEC_1_7_VALID_CRYPTO_CITATION = "test/cyclonedx/1.7/cdx-1-7-valid-crypto-citation.json"
	TEST_CDX_SPEC_1_7_COMP_VERSION_RANGE    = "test/cyclonedx/1.7/cdx-1-7-comp-version-range.json"

	TEST_CDX_SPEC_1_7_VALID_CITATIONS                   = "test/cyclonedx/1.7/specification/valid-citations-1.7.json"
	TEST_CDX_SPEC_1_7_VALID_COMPONENT_DATA              = "test/cyclonedx/1.7/specification/valid-component-data-1.7.json"
	TEST_CDX_SPEC_1_7_VALID_COMPONENT_EXT_VERSION_RANGE = "test/cyclonedx/1.7/specification/valid-component-external-with-versionRange.json"
	TEST_CDX_SPEC_1_7_VALID_CRYPTO_CERTIFICATE          = "test/cyclonedx/1.7/specification/valid-cryptography-certificate-1.7.json"
	TEST_CDX_SPEC_1_7_VALID_CRYPTO_CERTIFICATE_ADVANCED = "test/cyclonedx/1.7/specification/valid-cryptography-certificate-advanced-1.7.json"
	TEST_CDX_SPEC_1_7_VALID_CRYPTO_FULL                 = "test/cyclonedx/1.7/specification/valid-cryptography-full-1.7.json"
	TEST_CDX_SPEC_1_7_VALID_CRYPTO_IMPL                 = "test/cyclonedx/1.7/specification/valid-cryptography-implementation-1.7.json"
	TEST_CDX_SPEC_1_7_VALID_EVIDENCE                    = "test/cyclonedx/1.7/specification/valid-evidence-1.7.json"
	TEST_CDX_SPEC_1_7_VALID_EXT_REF_PROPS               = "test/cyclonedx/1.7/specification/valid-external-reference-properties-1.7.json"
	TEST_CDX_SPEC_1_7_VALID_LICENSE_EXP_LICENSING       = "test/cyclonedx/1.7/specification/valid-license-expression-with-licensing-1.7.json"
	TEST_CDX_SPEC_1_7_VALID_LICENSE_NAME_LICENSING      = "test/cyclonedx/1.7/specification/valid-license-name-with-licensing-1.7.json"
	TEST_CDX_SPEC_1_7_VALID_PATENT                      = "test/cyclonedx/1.7/specification/valid-patent-1.7.json"
	TEST_CDX_SPEC_1_7_VALID_RELEASE_NOTES               = "test/cyclonedx/1.7/specification/valid-release-notes-1.7.json"
	TEST_CDX_SPEC_1_7_VALID_SERVICE                     = "test/cyclonedx/1.7/specification/valid-service-1.7.json"
	TEST_CDX_SPEC_1_7_VALID_SIGNATURES                  = "test/cyclonedx/1.7/specification/valid-signatures-1.7.json"
	TEST_CDX_SPEC_1_7_VALID_STANDARD                    = "test/cyclonedx/1.7/specification/valid-standard-1.7.json"
)

// -----------------------------------------------------------
// CycloneDX - Min. requirement & Mature tests
// -----------------------------------------------------------

func TestValidateCdx13MinRequiredBasic(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_3_MIN_REQUIRED)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14MinRequiredBasic(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_MIN_REQUIRED)
	innerTestValidate(t, *vti)
}

func TestValidateCdx15MinRequiredBasic(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_5_MIN_REQUIRED)
	innerTestValidate(t, *vti)
}

func TestValidateCdx16MinRequiredBasic(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_6_MIN_REQUIRED)
	innerTestValidate(t, *vti)
}

func TestValidateCdx17MinRequiredBasic(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_7_MIN_REQUIRED)
	innerTestValidate(t, *vti)
}

func TestValidateCdx13Mature(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_3_MATURE_EXAMPLE_1_BASE)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14MMature(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_MATURE_EXAMPLE_1_BASE)
	innerTestValidate(t, *vti)
}

func TestValidateCdx15Mature(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_5_MATURE_EXAMPLE_1_BASE)
	innerTestValidate(t, *vti)
}

// Test BOM variants (e.g., MLBOM, CBOM, etc.)
func TestValidateCdx16MachineLearningBOM(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_6_MACHINE_LEARNING_BOM)
	innerTestValidate(t, *vti)
}

func TestValidateCdx16CryptographicBOM(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_6_CRYPTO_BOM)
	innerTestValidate(t, *vti)
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

// 1.6 Tests
func TestValidateCdx16ExtRefIRI(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_SPEC_1_6_VALID_EXT_REF_IRI)
	innerTestValidate(t, *vti)
}

func TestValidateCdx16Licensing(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_SPEC_1_6_VALID_LICENSING)
	innerTestValidate(t, *vti)
}

func TestValidateCdx16SpdxLicense(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_SPEC_1_6_1_VALID_SPDX_LICENSE)
	innerTestValidate(t, *vti)
}

// 1.7 Tests
func TestValidateCdx17CryptoCitation(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_SPEC_1_7_VALID_CRYPTO_CITATION)
	innerTestValidate(t, *vti)
}

func TestValidateCdx17ComponentVersionRange(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_SPEC_1_7_COMP_VERSION_RANGE)
	innerTestValidate(t, *vti)
}

// v1.7 Specification schema tests
func TestValidateCdx17ValidCitations(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_SPEC_1_7_VALID_CITATIONS)
	innerTestValidate(t, *vti)
}

func TestValidateCdx17ValidComponentData(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_SPEC_1_7_VALID_COMPONENT_DATA)
	innerTestValidate(t, *vti)
}

func TestValidateCdx17ValidComponentExternalVersionRange(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_SPEC_1_7_VALID_COMPONENT_EXT_VERSION_RANGE)
	innerTestValidate(t, *vti)
}

func TestValidateCdx17ValidCryptoCertificate(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_SPEC_1_7_VALID_CRYPTO_CERTIFICATE)
	innerTestValidate(t, *vti)
}

func TestValidateCdx17ValidCryptoCertificateAdvanced(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_SPEC_1_7_VALID_CRYPTO_CERTIFICATE_ADVANCED)
	innerTestValidate(t, *vti)
}

func TestValidateCdx17ValidCryptoFull(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_SPEC_1_7_VALID_CRYPTO_FULL)
	innerTestValidate(t, *vti)
}

func TestValidateCdx17ValidCryptoImpl(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_SPEC_1_7_VALID_CRYPTO_IMPL)
	innerTestValidate(t, *vti)
}

func TestValidateCdx17ValidEvidence(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_SPEC_1_7_VALID_EVIDENCE)
	innerTestValidate(t, *vti)
}

func TestValidateCdx17ValidExternalReferenceProperties(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_SPEC_1_7_VALID_EXT_REF_PROPS)
	innerTestValidate(t, *vti)
}

func TestValidateCdx17ValidLicenseExpressionLicensing(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_SPEC_1_7_VALID_LICENSE_EXP_LICENSING)
	innerTestValidate(t, *vti)
}

func TestValidateCdx17ValidLicenseNameLicensing(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_SPEC_1_7_VALID_LICENSE_NAME_LICENSING)
	innerTestValidate(t, *vti)
}

func TestValidateCdx17ValidPatent(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_SPEC_1_7_VALID_PATENT)
	innerTestValidate(t, *vti)
}

func TestValidateCdx17ValidReleaseNotes(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_SPEC_1_7_VALID_RELEASE_NOTES)
	innerTestValidate(t, *vti)
}

func TestValidateCdx17ValidService(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_SPEC_1_7_VALID_SERVICE)
	innerTestValidate(t, *vti)
}

func TestValidateCdx17ValidSignatures(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_SPEC_1_7_VALID_SIGNATURES)
	innerTestValidate(t, *vti)
}

func TestValidateCdx17ValidStandard(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_SPEC_1_7_VALID_STANDARD)
	innerTestValidate(t, *vti)
}
