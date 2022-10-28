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

func TestValidateConfigInvalidFormatKey(t *testing.T) {
	innerValidateError(t,
		TEST_INVALID_FORMAT_KEY_FOO,
		SCHEMA_VARIANT_NONE,
		&schema.UnsupportedFormatError{})
}

func TestValidateConfigInvalidVersion(t *testing.T) {
	innerValidateError(t,
		TEST_CDX_SPEC_VERSION_INVALID,
		SCHEMA_VARIANT_NONE,
		&schema.UnsupportedSchemaError{})
}

func TestValidateConfigInvalidVariant(t *testing.T) {
	innerValidateError(t,
		TEST_CDX_1_4_MIN_REQUIRED,
		"foo",
		&schema.UnsupportedSchemaError{})
}

func TestValidateConfigCDXBomFormatInvalid(t *testing.T) {
	innerValidateError(t,
		TEST_CDX_BOM_FORMAT_INVALID,
		SCHEMA_VARIANT_NONE,
		&schema.UnsupportedFormatError{})
}

func TestValidateConfigCDXBomFormatMissing(t *testing.T) {
	innerValidateError(t,
		TEST_CDX_BOM_FORMAT_MISSING,
		SCHEMA_VARIANT_NONE,
		&schema.UnsupportedFormatError{})
}

func TestValidateConfigCDXSpecVersionMissing(t *testing.T) {
	innerValidateError(t,
		TEST_CDX_SPEC_VERSION_MISSING,
		SCHEMA_VARIANT_NONE,
		&schema.UnsupportedSchemaError{})
}

func TestValidateConfigSPDXSpdxIdInvalid(t *testing.T) {
	innerValidateError(t,
		TEST_SPDX_SPDX_ID_INVALID,
		SCHEMA_VARIANT_NONE,
		&schema.UnsupportedFormatError{})
}

func TestValidateConfigSPDXSpdxVersionInvalid(t *testing.T) {
	innerValidateError(t,
		TEST_SPDX_SPDX_VERSION_MISSING,
		SCHEMA_VARIANT_NONE,
		&schema.UnsupportedSchemaError{})
}
