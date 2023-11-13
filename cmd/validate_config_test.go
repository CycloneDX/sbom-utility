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

	"github.com/CycloneDX/sbom-utility/schema"
)

// -----------------------------------------------------------
// Configuration tests
// -----------------------------------------------------------

const (
	// Configuration tests
	TEST_INVALID_FORMAT_KEY_FOO    = "test/config/test-base-invalid-format-key-foo.json"
	TEST_CDX_SPEC_VERSION_INVALID  = "test/config/test-cdx-spec-version-invalid.json"
	TEST_CDX_BOM_FORMAT_INVALID    = "test/config/test-cdx-bom-format-invalid.json"
	TEST_CDX_BOM_FORMAT_MISSING    = "test/config/test-cdx-bom-format-missing.json"
	TEST_CDX_SPEC_VERSION_MISSING  = "test/config/test-cdx-spec-version-missing.json"
	TEST_SPDX_SPDX_ID_INVALID      = "test/config/test-spdx-spdx-id-invalid.json"
	TEST_SPDX_SPDX_VERSION_MISSING = "test/config/test-spdx-spdx-version-missing.json"
)

// Test values
const (
	TEST_INVALID_VARIANT_FOO = "foo"
)

func TestValidateConfigInvalidFormatKey(t *testing.T) {
	vti := NewValidateTestInfoBasic(TEST_INVALID_FORMAT_KEY_FOO, FORMAT_TEXT, &schema.UnsupportedFormatError{})
	innerTestValidate(t, *vti)
}

func TestValidateConfigInvalidVersion(t *testing.T) {
	vti := NewValidateTestInfoBasic(TEST_CDX_SPEC_VERSION_INVALID, FORMAT_TEXT, &schema.UnsupportedSchemaError{})
	innerTestValidate(t, *vti)
}

func TestValidateConfigInvalidVariant(t *testing.T) {
	vti := NewValidateTestInfo(TEST_CDX_1_4_MIN_REQUIRED, FORMAT_TEXT, TEST_INVALID_VARIANT_FOO, &schema.UnsupportedSchemaError{})
	innerTestValidate(t, *vti)
}

func TestValidateConfigCDXBomFormatInvalid(t *testing.T) {
	vti := NewValidateTestInfoBasic(TEST_CDX_BOM_FORMAT_INVALID, FORMAT_TEXT, &schema.UnsupportedFormatError{})
	innerTestValidate(t, *vti)
}

func TestValidateConfigCDXBomFormatMissing(t *testing.T) {
	vti := NewValidateTestInfoBasic(TEST_CDX_BOM_FORMAT_MISSING, FORMAT_TEXT, &schema.UnsupportedFormatError{})
	innerTestValidate(t, *vti)
}

func TestValidateConfigCDXSpecVersionMissing(t *testing.T) {
	vti := NewValidateTestInfoBasic(TEST_CDX_SPEC_VERSION_MISSING, FORMAT_TEXT, &schema.UnsupportedSchemaError{})
	innerTestValidate(t, *vti)
}

func TestValidateConfigSPDXSpdxIdInvalid(t *testing.T) {
	vti := NewValidateTestInfoBasic(TEST_SPDX_SPDX_ID_INVALID, FORMAT_TEXT, &schema.UnsupportedFormatError{})
	innerTestValidate(t, *vti)
}

func TestValidateConfigSPDXSpdxVersionInvalid(t *testing.T) {
	vti := NewValidateTestInfoBasic(TEST_SPDX_SPDX_VERSION_MISSING, FORMAT_TEXT, &schema.UnsupportedSchemaError{})
	innerTestValidate(t, *vti)
}
