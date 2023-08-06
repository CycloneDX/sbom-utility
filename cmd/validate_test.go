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
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
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

const (
	TEST_CDX_1_4_VALIDATE_ERR_COMPONENTS_UNIQUE    = "test/validation/cdx-1-4-validate-err-components-unique-items-1.json"
	TEST_CDX_1_4_VALIDATE_ERR_FORMAT_IRI_REFERENCE = "test/validation/cdx-1-4-validate-err-components-format-iri-reference.json"
)

// Tests basic validation and expected errors
func innerValidateError(t *testing.T, filename string, variant string, format string, expectedError error) (document *schema.BOM, schemaErrors []gojsonschema.ResultError, actualError error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Copy the test filename to the command line flags where the code looks for it
	utils.GlobalFlags.PersistentFlags.InputFile = filename
	// Set the err result format
	utils.GlobalFlags.PersistentFlags.OutputFormat = format
	// Set the schema variant where the command line flag would
	utils.GlobalFlags.ValidateFlags.SchemaVariant = variant

	// Invoke the actual validate function
	var isValid bool
	var outputBuffer bytes.Buffer

	// TODO: support additional tests on output buffer (e.g., format==valid JSON)
	isValid, document, schemaErrors, outputBuffer, actualError = innerValidateErrorBuffered(
		t,
		utils.GlobalFlags.PersistentFlags,
		utils.GlobalFlags.ValidateFlags,
	)

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

	// Assure it is valid JSON output
	if format == FORMAT_JSON {
		if outputBuffer.Len() == 0 {
			if expectedError == nil {
				getLogger().Tracef("output data empty as expected (nil).")
			} else {
				t.Error(fmt.Errorf("output data empty; expected error text: %s", expectedError.Error()))
				t.Logf("%s", outputBuffer.String())
			}

		} else if !utils.IsValidJsonRaw(outputBuffer.Bytes()) {
			err := getLogger().Errorf("output did not contain valid format data; expected: `%s`", FORMAT_JSON)
			t.Error(err.Error())
			t.Logf("%s", outputBuffer.String())
			return
		}
	}
	return
}

func innerValidateErrorBuffered(t *testing.T, persistentFlags utils.PersistentCommandFlags, validationFlags utils.ValidateCommandFlags) (isValid bool, document *schema.BOM, schemaErrors []gojsonschema.ResultError, outputBuffer bytes.Buffer, err error) {
	// Declare an output outputBuffer/outputWriter to use used during tests
	var outputWriter = bufio.NewWriter(&outputBuffer)
	// ensure all data is written to buffer before further validation
	defer outputWriter.Flush()

	// Invoke the actual command (API)
	isValid, document, schemaErrors, err = Validate(outputWriter, persistentFlags, utils.GlobalFlags.ValidateFlags)
	getLogger().Tracef("document: `%s`, isValid=`%t`, err=`%T`", document.GetFilename(), isValid, err)

	return
}

func innerValidateForcedSchema(t *testing.T, filename string, forcedSchema string, format string, expectedError error) (document *schema.BOM, schemaErrors []gojsonschema.ResultError, actualError error) {
	getLogger().Enter()
	defer getLogger().Exit()

	utils.GlobalFlags.ValidateFlags.ForcedJsonSchemaFile = forcedSchema
	innerValidateError(t, filename, SCHEMA_VARIANT_NONE, format, expectedError)
	// !!!Important!!! Must reset this global flag
	utils.GlobalFlags.ValidateFlags.ForcedJsonSchemaFile = ""

	return
}

// Tests *ErrorInvalidSBOM error types and any (lower-level) errors they "wrapped"
func innerValidateInvalidSBOMInnerError(t *testing.T, filename string, variant string, innerError error) (document *schema.BOM, schemaErrors []gojsonschema.ResultError, actualError error) {
	getLogger().Enter()
	defer getLogger().Exit()

	document, schemaErrors, actualError = innerValidateError(t, filename, variant, FORMAT_TEXT, &InvalidSBOMError{})

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
func innerValidateSyntaxError(t *testing.T, filename string, variant string, expectedLineNum int, expectedCharNum int) (document *schema.BOM, actualError error) {

	document, _, actualError = innerValidateError(t, filename, variant, FORMAT_TEXT, &json.SyntaxError{})
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
		FORMAT_TEXT,
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

func schemaErrorExists(schemaErrors []gojsonschema.ResultError,
	expectedType string, expectedField string, expectedValue interface{}) bool {

	for i, resultError := range schemaErrors {
		// Some descriptions include very long enums; in those cases,
		// truncate to a reasonable length using an intelligent separator
		getLogger().Tracef(">> %d. Type: [%s], Field: [%s], Value: [%v]",
			i+1,
			resultError.Type(),
			resultError.Field(),
			resultError.Value())

		actualType := resultError.Type()
		actualField := resultError.Field()
		actualValue := resultError.Value()

		if actualType == expectedType {
			// we have matched on the type (key) field, continue to match other fields
			if expectedField != "" &&
				actualField != expectedField {
				getLogger().Tracef("expected Field: `%s`; actual Field: `%s`", expectedField, actualField)
				return false
			}

			if expectedValue != "" &&
				actualValue != expectedValue {
				getLogger().Tracef("expected Value: `%s`; actual Value: `%s`", actualValue, expectedValue)
				return false
			}
			return true
		} else {
			getLogger().Debugf("Skipping result[%d]: expected Type: `%s`; actual Type: `%s`", i, expectedType, actualType)
		}
	}
	return false
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
		FORMAT_TEXT,
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
	innerValidateForcedSchema(t,
		TEST_CDX_1_3_MATURITY_EXAMPLE_1_BASE,
		TEST_SCHEMA_CDX_1_3_CUSTOM,
		FORMAT_TEXT,
		nil)
}

// Force validation against a "custom" schema with compatible format (CDX) and version (1.4)
func TestValidateForceCustomSchemaCdx14(t *testing.T) {
	innerValidateForcedSchema(t,
		TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE,
		TEST_SCHEMA_CDX_1_4_CUSTOM,
		FORMAT_TEXT,
		nil)
}

// Force validation using schema with compatible format, but older version than the SBOM version
func TestValidateForceCustomSchemaCdxSchemaOlder(t *testing.T) {
	innerValidateForcedSchema(t,
		TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE,
		TEST_SCHEMA_CDX_1_3_CUSTOM,
		FORMAT_TEXT,
		nil)
}

// TODO: add additional checks on the buffered output
func TestValidateCdx14ErrorResultsUniqueComponentsText(t *testing.T) {
	innerValidateError(t,
		TEST_CDX_1_4_VALIDATE_ERR_COMPONENTS_UNIQUE,
		SCHEMA_VARIANT_NONE,
		FORMAT_TEXT,
		&InvalidSBOMError{})
}

// TODO: add additional checks on the buffered output
func TestValidateCdx14ErrorResultsFormatIriReferencesText(t *testing.T) {
	innerValidateError(t,
		TEST_CDX_1_4_VALIDATE_ERR_FORMAT_IRI_REFERENCE,
		SCHEMA_VARIANT_NONE,
		FORMAT_TEXT,
		&InvalidSBOMError{})
}

func TestValidateCdx14ErrorResultsUniqueComponentsCsv(t *testing.T) {
	innerValidateError(t,
		TEST_CDX_1_4_VALIDATE_ERR_COMPONENTS_UNIQUE,
		SCHEMA_VARIANT_NONE,
		FORMAT_CSV,
		&InvalidSBOMError{})
}

// TODO: add additional checks on the buffered output
func TestValidateCdx14ErrorResultsFormatIriReferencesCsv(t *testing.T) {
	innerValidateError(t,
		TEST_CDX_1_4_VALIDATE_ERR_FORMAT_IRI_REFERENCE,
		SCHEMA_VARIANT_NONE,
		FORMAT_CSV,
		&InvalidSBOMError{})
}

func TestValidateCdx14ErrorResultsUniqueComponentsJson(t *testing.T) {
	var EXPECTED_ERROR_NUM = 2
	var EXPECTED_ERROR_CONTEXT = "(root).components"
	_, schemaErrors, _ := innerValidateError(t,
		TEST_CDX_1_4_VALIDATE_ERR_COMPONENTS_UNIQUE,
		SCHEMA_VARIANT_NONE,
		FORMAT_JSON,
		&InvalidSBOMError{})

	if len(schemaErrors) != EXPECTED_ERROR_NUM {
		t.Errorf("invalid schema error count: expected `%v`; actual: `%v`)", EXPECTED_ERROR_NUM, len(schemaErrors))
	}

	if schemaErrors[0].Context().String() != EXPECTED_ERROR_CONTEXT {
		t.Errorf("invalid schema error context: expected `%v`; actual: `%v`)", EXPECTED_ERROR_CONTEXT, schemaErrors[0].Context().String())
	}
}

// TODO: add additional checks on the buffered output
func TestValidateCdx14ErrorResultsFormatIriReferencesJson(t *testing.T) {
	var EXPECTED_ERROR_NUM = 1
	var EXPECTED_ERROR_CONTEXT = "(root).components.2.externalReferences.0.url"
	_, schemaErrors, _ := innerValidateError(t,
		TEST_CDX_1_4_VALIDATE_ERR_FORMAT_IRI_REFERENCE,
		SCHEMA_VARIANT_NONE,
		FORMAT_JSON,
		&InvalidSBOMError{})

	if len(schemaErrors) != EXPECTED_ERROR_NUM {
		t.Errorf("invalid schema error count: expected `%v`; actual: `%v`)", EXPECTED_ERROR_NUM, len(schemaErrors))
	}

	if schemaErrors[0].Context().String() != EXPECTED_ERROR_CONTEXT {
		t.Errorf("invalid schema error context: expected `%v`; actual: `%v`)", EXPECTED_ERROR_CONTEXT, schemaErrors[0].Context().String())
	}

}

// -----------------------------------------------------------
// Test custom config.json (i.e., `--config-schema` flag)
// -----------------------------------------------------------

func loadCustomSchemaConfig(t *testing.T, filename string) (err error) {
	// Do not pass a default file, it should fail if custom policy cannot be loaded
	err = SupportedFormatConfig.InnerLoadSchemaConfigFile(filename, DEFAULT_SCHEMA_CONFIG)
	if err != nil {
		return
	}
	return
}

func restoreEmbeddedDefaultSchemaConfig(t *testing.T) (err error) {
	return loadCustomSchemaConfig(t, "")
}

func innerValidateCustomSchemaConfig(t *testing.T, filename string, configFile string, variant string, format string, expectedError error) (document *schema.BOM, schemaErrors []gojsonschema.ResultError, actualError error) {
	loadCustomSchemaConfig(t, configFile)
	document, schemaErrors, actualError = innerValidateError(t, TEST_CDX_1_4_MIN_REQUIRED, variant, FORMAT_TEXT, nil)
	// !!!Important!!! MUST reset global flag to its proper default (i.e., empty)
	// which will cause the embedded `config.json` to be used for all other tests
	restoreEmbeddedDefaultSchemaConfig(t)
	return
}

func TestValidateWithCustomSchemaConfiguration(t *testing.T) {
	innerValidateCustomSchemaConfig(t, TEST_CDX_1_4_MIN_REQUIRED, DEFAULT_SCHEMA_CONFIG, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
}

func TestUserInput(t *testing.T) {

	file, err := os.Open(TEST_CDX_1_4_MIN_REQUIRED) // For read access.
	if err != nil {
		log.Fatal(err)
	}

	// convert byte slice to io.Reader
	savedStdIn := os.Stdin
	defer func() { os.Stdin = savedStdIn }()
	os.Stdin = file

	innerValidateError(t,
		INPUT_STANDARD_IN,
		SCHEMA_VARIANT_NONE,
		FORMAT_JSON,
		nil)
}
