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

// CycloneDX v2.0 tests.
//
// All tests in this file exercise functionality specific to CycloneDX v2.0 BOMs
// (specFormat rename, parties[], identifiers[], etc.) and require the
// SCHEMA_VARIANT_DEVELOPMENT schema variant to be selected.

package cmd

import (
	"testing"
)

// -------------------------------------------
// validate
// -------------------------------------------

// TestValidateCdx20MinRequiredBasic verifies that a CycloneDX v2.0 BOM using the
// renamed "specFormat" key (replacing "bomFormat") is correctly identified, validated,
// and unmarshalled into the CDXBom struct with SpecFormat populated.
func TestValidateCdx20MinRequiredBasic(t *testing.T) {
	const EXPECTED_SPEC_FORMAT = "CycloneDX"
	const EXPECTED_SPEC_VERSION = "2.0"

	vti := NewValidateTestInfo(TEST_CDX_2_0_MIN_REQUIRED, FORMAT_TEXT, SCHEMA_VARIANT_DEVELOPMENT, nil)
	document, _, err := innerTestValidate(t, *vti)
	if err != nil {
		// innerTestValidate already calls t.Errorf; just return to avoid nil-deref below
		return
	}

	// Unmarshal into CDX structs so we can inspect the Go model.
	if err = document.UnmarshalCycloneDXBOM(); err != nil {
		t.Errorf("UnmarshalCycloneDXBOM() failed: %v", err)
		return
	}

	// Assert the v2.0 specFormat key was decoded into SpecFormat (not BOMFormat).
	if got := document.GetCdxSpecFormat(); got != EXPECTED_SPEC_FORMAT {
		t.Errorf("SpecFormat: expected %q, got %q", EXPECTED_SPEC_FORMAT, got)
	}

	// Assert specVersion is preserved correctly.
	if cdxBom := document.GetCdxBom(); cdxBom == nil || cdxBom.SpecVersion != EXPECTED_SPEC_VERSION {
		var got string
		if cdxBom != nil {
			got = cdxBom.SpecVersion
		}
		t.Errorf("SpecVersion: expected %q, got %q", EXPECTED_SPEC_VERSION, got)
	}

	// Assert BOMFormat is empty (not set by a v2.0 document).
	if cdxBom := document.GetCdxBom(); cdxBom != nil && cdxBom.BOMFormat != "" {
		t.Errorf("BOMFormat: expected empty string for v2.0 document, got %q", cdxBom.BOMFormat)
	}
}
