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
	"encoding/json"
	"fmt"
	"io/fs"
	"testing"

	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/CycloneDX/sbom-utility/utils"
	"github.com/xeipuuv/gojsonschema"
)

const (
	SCHEMA_VARIANT_NONE = ""
)

// JSON SBOM files containing syntax errors for testing
const (
	TEST_CDX_1_3_SYNTAX_ERR_1 = "test/cyclonedx/cdx-1-3-syntax-err-1.json"
	TEST_CDX_1_3_SYNTAX_ERR_2 = "test/cyclonedx/cdx-1-3-syntax-err-2.json"
)

// Mature SBOMs used to test various schemas and queries
const (
	TEST_CDX_1_3_MATURITY_BASE = "test/cyclonedx/cdx-1-3-mature-example-1.json"
	TEST_CDX_1_4_MATURITY_BASE = "test/cyclonedx/cdx-1-4-mature-example-1.json"
)

// Tests basic validation and expected errors
func innerValidateError(t *testing.T, filename string, variant string, expectedError error) (document *schema.Sbom, schemaErrors []gojsonschema.ResultError, actualError error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Copy the test filename to the command line flags where the code looks for it
	utils.GlobalFlags.InputFile = filename
	// Set the schema variant where the command line flag would
	utils.GlobalFlags.Variant = variant

	// Invoke the actual validate function
	var isValid bool
	isValid, document, schemaErrors, actualError = Validate()

	getLogger().Tracef("document: `%s`, isValid=`%t`, actualError=`%T`", document.GetFilename(), isValid, actualError)

	// Always compare actual against expected error (even if it is `nil`)
	if !ErrorTypesMatch(actualError, expectedError) {
		if len(schemaErrors) > 0 {
			getLogger().Debugf("schemaErrors=`%s`", schemaErrors)
		}

		switch t := actualError.(type) {
		default:
			fmt.Printf("unhandled error type: `%v`\n", t)
			fmt.Printf(">> value: `%v`\n", t)
			getLogger().Error(actualError)
		}
		t.Errorf("expected error type: `%T`, actual type: `%T`", expectedError, actualError)
	}

	// ANY error returned from Validate() SHOULD mark the input file as "invalid"
	if actualError != nil && isValid {
		t.Errorf("Validate() returned error (`%T`); however, input file still valid (%t)", actualError, isValid)
	}

	// ALWAYS make sure the if error was NOT expected that input file is marked "valid"
	if expectedError == nil && !isValid {
		t.Errorf("Input file invalid (%t); expected valid (no error)", isValid)
	}

	return
}

// Tests *ErrorInvalidSBOM error types and any (lower-level) errors they "wrapped"
func innerValidateInvalidSBOMInnerError(t *testing.T, filename string, variant string, innerError error) (document *schema.Sbom, schemaErrors []gojsonschema.ResultError, actualError error) {
	getLogger().Enter()
	defer getLogger().Exit()

	document, schemaErrors, actualError = innerValidateError(t, filename, variant, &InvalidSBOMError{})

	invalidSBOMError, ok := actualError.(*InvalidSBOMError)

	if !ok {
		t.Errorf("Unable to cast actual error type (%T) to `InvalidSBOMError`: (%T)", actualError, &InvalidSBOMError{})
	} else if !ErrorTypesMatch(invalidSBOMError.InnerError, innerError) {
		t.Errorf("expected wrapped error type: `%T`, actual type: `%T`", innerError, invalidSBOMError.InnerError)
	}
	return
}

// Tests for *json.SyntaxErrors "wrapped" in *ErrorInvalidSBOM error types
// It also tests that the syntax error occurred at the expected line number and character offset
func innerValidateSyntaxError(t *testing.T, filename string, variant string, expectedLineNum int, expectedCharNum int) (document *schema.Sbom, actualError error) {

	document, _, actualError = innerValidateError(t, filename, variant, &json.SyntaxError{})
	syntaxError, ok := actualError.(*json.SyntaxError)

	if !ok {
		t.Errorf("Unable to cast inner error type (%T) to *json.SyntaxError: (%T)", actualError, syntaxError)
		return
	}

	// Now make sure we correctly report the line/char offsets of the actual syntax error
	// within the (test) input file
	// Note: Uses the offset from JSON syntax errors return "encoding/json.SyntaxError"
	rawBytes := document.GetRawBytes()
	actualLineNum, actualCharNum := schema.CalcLineAndCharacterPos(rawBytes, syntaxError.Offset)
	if actualLineNum != expectedLineNum || actualCharNum != expectedCharNum {
		t.Errorf("syntax error found at line,char=[%d,%d], expected=[%d,%d]", actualLineNum, actualCharNum, expectedLineNum, expectedCharNum)
	}

	return
}

func innerTestSchemaErrorAndErrorResults(t *testing.T,
	filename string, variant string,
	schemaErrorType string, schemaErrorField string, schemaErrorValue string) {

	document, results, _ := innerValidateError(t,
		filename,
		variant,
		&InvalidSBOMError{})
	getLogger().Debugf("filename: `%s`, results:\n%v", document.GetFilename(), results)

	// See ResultType struct fields (and values) in the `gojsonschema` package
	exists := schemaErrorExists(results, schemaErrorType, schemaErrorField, schemaErrorValue)

	if !exists {
		t.Errorf("expected schema error: Type=`%s`, Field=`%s`, Value=`%s`",
			schemaErrorType,
			schemaErrorField,
			schemaErrorValue)
	}
}

// -----------------------------------------------------------
// Command tests
// -----------------------------------------------------------

// Test for invalid input file provided on the `-i` flag
func TestValidateInvalidInputFileLoad(t *testing.T) {
	// Assure we return path error
	innerValidateError(t,
		TEST_INPUT_FILE_NON_EXISTENT,
		SCHEMA_VARIANT_NONE,
		&fs.PathError{})
}

// -----------------------------------------------------------
// JSON Syntax error tests
// -----------------------------------------------------------
// Syntax error tests SHOULD return error type `encoding/json.SyntaxError`
// -----------------------------------------------------------

// "invalid character": Missing closing `}` bracket on `metadata` property
func TestValidateSyntaxErrorCdx13Test1(t *testing.T) {
	filename := TEST_CDX_1_3_SYNTAX_ERR_1
	LINE_NUM := 6
	OFFSET := 18
	innerValidateSyntaxError(t, filename, SCHEMA_VARIANT_NONE, LINE_NUM, OFFSET)
}

// "invalid character": Missing `:` separating `"properties"` key from array value `[`
func TestValidateSyntaxErrorCdx13Test2(t *testing.T) {
	filename := TEST_CDX_1_3_SYNTAX_ERR_2
	LINE_NUM := 123
	OFFSET := 28
	innerValidateSyntaxError(t, filename, SCHEMA_VARIANT_NONE, LINE_NUM, OFFSET)
}

// -----------------------------------------------------------
// Custom schema tests (i.e., `--force` flag) tests
// -----------------------------------------------------------
// NOTE: None of these tests actually test an SBOM against custom schema;
// those tests are instead run in "validate_custom_test.go"

// Force validation against a "custom" schema with compatible format (CDX) and version (1.3)
func TestValidateForceCustomSchemaCdx13(t *testing.T) {
	utils.GlobalFlags.ForcedJsonSchemaFile = TEST_SCHEMA_CDX_1_3_CUSTOM
	innerValidateError(t,
		TEST_CDX_1_3_MATURITY_BASE,
		SCHEMA_VARIANT_NONE,
		nil)
}

// Force validation against a "custom" schema with compatible format (CDX) and version (1.4)
func TestValidateForceCustomSchemaCdx14(t *testing.T) {
	utils.GlobalFlags.ForcedJsonSchemaFile = TEST_SCHEMA_CDX_1_4_CUSTOM
	innerValidateError(t,
		TEST_CDX_1_4_MATURITY_BASE,
		SCHEMA_VARIANT_NONE,
		nil)
}

// Force validation using schema with compatible format, but older version than the SBOM version
func TestValidateForceCustomSchemaCdxSchemaOlder(t *testing.T) {
	utils.GlobalFlags.ForcedJsonSchemaFile = TEST_SCHEMA_CDX_1_3_CUSTOM
	innerValidateError(t,
		TEST_CDX_1_4_MATURITY_BASE,
		SCHEMA_VARIANT_NONE,
		nil)
}

// func TestValidateSyntaxErrorCdx14AdHoc2(t *testing.T) {
// 	innerValidateError(t,
// 		"sample_co_May16.json",
// 		SCHEMA_VARIANT_NONE,
// 		nil)
// }
