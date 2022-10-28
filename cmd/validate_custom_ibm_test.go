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

const (
	SCHEMA_VARIANT_IBM_DEV = "ibm-dev"
	SCHEMA_VARIANT_IBM_REL = "ibm-rel"
)

// Custom-specific test files
const (

	// Min. Req. - Test versioned documents meet min. schema (variant) requirements
	TEST_CDX_1_3_IBM_MIN_REQUIRED = "test/custom/cdx-1-3-ibm-min-required.json"
	TEST_CDX_1_4_IBM_MIN_REQUIRED = "test/custom/cdx-1-4-ibm-min-required.json"

	// Metadata tests
	TEST_CDX_1_4_IBM_MISSING_DISCLAIMER = "test/custom/cdx-1-4-test-ibm-invalid-disclaimer-missing.json"

	// Merge tests
	TEST_CUSTOM_CDX_1_3_IBM_MANUAL_DATA = "test/custom/cdx-1-3-ibm-manual-data-example.json"
)

// -----------------------------------------------------------
// Min. req. tests
// -----------------------------------------------------------

func TestValidateCdx13IbmMinRequiredBasic(t *testing.T) {
	innerValidateError(t, TEST_CDX_1_3_IBM_MIN_REQUIRED, SCHEMA_VARIANT_IBM_DEV, nil)
}

func TestValidateCdx14IbmMinRequiredBasic(t *testing.T) {
	innerValidateError(t, TEST_CDX_1_4_IBM_MIN_REQUIRED, SCHEMA_VARIANT_IBM_DEV, nil)
}

// TODO - remove once product id, del. id, legal disclaimer, legal coverage
// can validate using only "contains" schema
func TestValidateCustomCdx13MinIBMRequiredBasicCustomProperties(t *testing.T) {
	innerCustomValidateError(t,
		TEST_CDX_1_3_IBM_MIN_REQUIRED,
		SCHEMA_VARIANT_IBM_DEV,
		nil)
}

func TestValidateCustomCdx14MinIBMRequiredBasicCustomProperties(t *testing.T) {
	innerCustomValidateError(t,
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

// -------------------------------------------
// Property uniqueness tests
// -------------------------------------------

// -------------------------------------------
// Composition tests
// -------------------------------------------

// -----------------------------------------------------------
// CycloneDX - merge tests
// ----------------------------------------------------------

func TestValidateCustomCdx13IbmManualData(t *testing.T) {
	innerValidateError(t, TEST_CUSTOM_CDX_1_3_IBM_MANUAL_DATA,
		SCHEMA_VARIANT_NONE,
		nil)
}
