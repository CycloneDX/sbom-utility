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
)

// Consolidate test file name declarations
const (
	// SPDX - Test versioned documents meet min. schema requirements
	TEST_SPDX_2_2_MIN_REQUIRED        = "test/spdx/spdx-2-2-min-required.json"
	TEST_SPDX_2_3_MIN_REQUIRED        = "test/spdx/spdx-2-3-min-required.json"
	TEST_SPDX_2_3_EXAMPLE_PACKAGE_BOM = "test/spdx/spdx-2-3-example-package-bom.json"

	// SPDX - (invalid) Schema tests
	TEST_SPDX_2_2_INVALID_CREATION_INFO_MISSING = "test/spdx/spdx-2-2-missing-creationinfo.json"

	// SPDX - Tool samples
	//TEST_SPDX_SAMPLE_MEND_PACKAGE_NPM_ASYNC_WS = "test/spdx/samples/whitesource.json"
)

// -----------------------------------------------------------
// SPDX - Min. req. tests
// -----------------------------------------------------------

// TODO: Need an SPDX 2.1 variant
// TODO: Need an SPDX 2.2.1 variant
// TODO: Need an SPDX 2.2 "custom" variant
func TestValidateSpdx22MinRequiredBasic(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_SPDX_2_2_MIN_REQUIRED)
	innerTestValidate(t, *vti)
}

// -----------------------------------------------------------
// SPDX - (invalid) Schema tests
// -----------------------------------------------------------
// NOTE: Schema errors do not have an "inner error", but return "[]gojsonschema.ResultError"
// This means that these "errors" ARE NOT surfaced in the error return from Validate(); instead,
// a `[]gojsonschema.ResultError` (custom error) is returned in the "results" array
// -----------------------------------------------------------

func TestValidateSchemaSpdx22CreationInfoMissing(t *testing.T) {
	// Note: actual error "value" is a structure which we cannot easily recreate here; so do not test that field
	SCHEMA_ERROR_TYPE := "required"
	SCHEMA_ERROR_FIELD := "(root)"
	SCHEMA_ERROR_VALUE := ""

	innerTestSchemaErrorAndErrorResults(t,
		TEST_SPDX_2_2_INVALID_CREATION_INFO_MISSING,
		SCHEMA_VARIANT_NONE,
		SCHEMA_ERROR_TYPE,
		SCHEMA_ERROR_FIELD,
		SCHEMA_ERROR_VALUE)
}
