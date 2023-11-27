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
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"testing"

	"github.com/CycloneDX/sbom-utility/common"
	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/CycloneDX/sbom-utility/utils"
)

// -------------------------------------------
// test helper functions
// -------------------------------------------

func innerQueryError(t *testing.T, cti *CommonTestInfo, queryRequest *common.QueryRequest, expectedError error) (result interface{}, actualError error) {
	getLogger().Enter()
	defer getLogger().Exit()

	result, _, actualError = innerQuery(t, cti, queryRequest)

	// if the query resulted in a failure
	if !ErrorTypesMatch(actualError, expectedError) {
		getLogger().Tracef("expected error type: `%T`, actual type: `%T`", expectedError, actualError)
		t.Errorf("expected error type: `%T`, actual type: `%T`", expectedError, actualError)
	}
	return
}

// NOTE: This function "mocks" what the "queryCmdImpl()" function would do
func innerQuery(t *testing.T, cti *CommonTestInfo, queryRequest *common.QueryRequest) (resultJson interface{}, outputBuffer bytes.Buffer, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Copy the test filename to the command line flags were the code looks for it
	utils.GlobalFlags.PersistentFlags.InputFile = cti.InputFile

	// allocate response/result object and invoke query
	var queryResponse = new(common.QueryResponse)
	resultJson, outputBuffer, err = innerBufferedTestQuery(t, cti, queryRequest, queryResponse)

	// if the command resulted in a failure
	if err != nil {
		// if tests asks us to report a FAIL to the test framework
		if cti.Autofail {
			encodedTestInfo, _ := utils.EncodeAnyToDefaultIndentedJSONStr(queryRequest)
			t.Errorf("%s: failed: %v\nQueryRequest:\n%s", cti.InputFile, err, encodedTestInfo.String())
		}
		return
	}

	// Log results if trace enabled
	if err != nil {
		var buffer bytes.Buffer
		buffer, err = utils.EncodeAnyToDefaultIndentedJSONStr(resultJson)
		// Output the JSON data directly to stdout (not subject to log-level)
		getLogger().Tracef("%s\n", buffer.String())
	}
	return
}

func innerBufferedTestQuery(t *testing.T, testInfo *CommonTestInfo, queryRequest *common.QueryRequest, queryResponse *common.QueryResponse) (resultJson interface{}, outputBuffer bytes.Buffer, err error) {

	// The command looks for the input & output filename in global flags struct
	utils.GlobalFlags.PersistentFlags.InputFile = testInfo.InputFile
	utils.GlobalFlags.PersistentFlags.OutputFile = testInfo.OutputFile
	utils.GlobalFlags.PersistentFlags.OutputFormat = testInfo.OutputFormat
	utils.GlobalFlags.PersistentFlags.OutputIndent = testInfo.OutputIndent
	var outputWriter io.Writer
	var outputFile *os.File

	// TODO: centralize this logic to a function all Commands can use...
	// Note: Any "Mocking" of os.Stdin/os.Stdout should be done in functions that call this one
	if testInfo.OutputFile == "" {
		// Declare an output outputBuffer/outputWriter to use used during tests
		bufferedWriter := bufio.NewWriter(&outputBuffer)
		outputWriter = bufferedWriter
		// MUST ensure all data is written to buffer before further testing
		defer bufferedWriter.Flush()
	} else {
		outputFile, outputWriter, err = createOutputFile(testInfo.OutputFile)
		getLogger().Tracef("outputFile: `%v`; writer: `%v`", testInfo.OutputFile, outputWriter)

		// use function closure to assure consistent error output based upon error type
		defer func() {
			// always close the output file (even if error, as long as file handle returned)
			if outputFile != nil {
				outputFile.Close()
				getLogger().Infof("Closed output file: `%s`", testInfo.OutputFile)
			}
		}()

		if err != nil {
			return
		}
	}

	resultJson, err = Query(outputWriter, queryRequest, queryResponse)
	return
}

// Used to help verify query results
func UnmarshalResultsToMap(results interface{}) (resultMap map[string]interface{}, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// we need to marshal the data to normalize it to a []byte
	var resultBytes []byte
	resultBytes, err = json.Marshal(results)
	if err != nil {
		return
	}

	err = json.Unmarshal(resultBytes, &resultMap)
	if err != nil {
		return
	}

	return
}

// Used to verify fields specified on a SELECT clause appear in JSON results (map)
func VerifySelectedFieldsInJsonMap(t *testing.T, keys []string, results interface{}) (exists bool, err error) {

	if results == nil {
		t.Errorf("invalid results: %v", results)
	}

	resultMap, err := UnmarshalResultsToMap(results)
	if err != nil {
		getLogger().Tracef("results: %v", resultMap)
		t.Errorf("invalid JSON: %s: %v", err, resultMap)
	}

	for _, key := range keys {
		_, exists = resultMap[key]
		if !exists {
			t.Errorf("invalid results: key: `%s` does not exist.", key)
		}
	}
	return
}

// ----------------------------------------
// Command flag tests
// ----------------------------------------

func TestQueryFailInvalidInputFileLoad(t *testing.T) {
	cti := NewCommonTestInfoBasic(TEST_INPUT_FILE_NON_EXISTENT)
	request, _ := common.NewQueryRequestSelectWildcardFrom(
		"metadata.properties")
	// Assure we return path error
	_, _ = innerQueryError(t, cti, request, &fs.PathError{})
}

// ----------------------------------------
// PASS tests
// ----------------------------------------

func TestQueryCdx14BomFormatSpecVersion(t *testing.T) {
	cti := NewCommonTestInfoBasic(TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE)
	request, _ := common.NewQueryRequestSelectFrom(
		"bomFormat,specVersion",
		"")
	results, _ := innerQueryError(t, cti, request, nil)
	_, _ = VerifySelectedFieldsInJsonMap(t, request.GetSelectKeys(), results)
}

func TestQueryCdx14MetadataTimestampField(t *testing.T) {
	cti := NewCommonTestInfoBasic(TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE)
	request, _ := common.NewQueryRequestSelectFrom(
		"timestamp",
		"metadata")
	results, _ := innerQueryError(t, cti, request, nil)
	_, _ = VerifySelectedFieldsInJsonMap(t, request.GetSelectKeys(), results)
}

func TestQueryCdx14MetadataComponentAll(t *testing.T) {
	cti := NewCommonTestInfoBasic(TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE)
	request, _ := common.NewQueryRequestSelectWildcardFrom(
		"metadata.component")
	results, _ := innerQueryError(t, cti, request, nil)
	// Test for concrete keys that SHOULD have been found using wildcard
	fields := []string{
		"type", "bom-ref", "purl", "version", "externalReferences",
		"name", "description", "licenses", "properties", "hashes",
		"supplier", "publisher"}
	_, _ = VerifySelectedFieldsInJsonMap(t, fields, results)
}

func TestQueryCdx14MetadataComponentNameDescriptionVersion(t *testing.T) {
	cti := NewCommonTestInfoBasic(TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE)
	request, _ := common.NewQueryRequestSelectFrom(
		"name,description,version",
		"metadata.component")
	results, _ := innerQueryError(t, cti, request, nil)
	_, _ = VerifySelectedFieldsInJsonMap(t, request.GetSelectKeys(), results)
}

func TestQueryCdx14MetadataSupplier(t *testing.T) {
	cti := NewCommonTestInfoBasic(TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE)
	request, _ := common.NewQueryRequestSelectFrom(
		common.QUERY_TOKEN_WILDCARD,
		"metadata.supplier")
	results, _ := innerQueryError(t, cti, request, nil)
	// Test for concrete keys that SHOULD have been found using wildcard
	fields := []string{"name", "url", "contact"}
	_, _ = VerifySelectedFieldsInJsonMap(t, fields, results)
}

func TestQueryCdx14MetadataManufacturer(t *testing.T) {
	cti := NewCommonTestInfoBasic(TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE)
	request, _ := common.NewQueryRequestSelectFrom(
		common.QUERY_TOKEN_WILDCARD,
		"metadata.manufacture")
	results, _ := innerQueryError(t, cti, request, nil)
	// Test for concrete keys that SHOULD have been found using wildcard
	fields := []string{"name", "url", "contact"}
	_, _ = VerifySelectedFieldsInJsonMap(t, fields, results)
}

func TestQueryCdx14MetadataComponentLicenses(t *testing.T) {
	cti := NewCommonTestInfoBasic(TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE)
	request, _ := common.NewQueryRequestSelectFrom(
		"licenses",
		"metadata.component")
	results, _ := innerQueryError(t, cti, request, nil)
	_, _ = VerifySelectedFieldsInJsonMap(t, request.GetSelectKeys(), results)
}

func TestQueryCdx14MetadataComponentSupplier(t *testing.T) {
	cti := NewCommonTestInfoBasic(TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE)
	request, _ := common.NewQueryRequestSelectFrom(
		"supplier",
		"metadata.component")
	results, _ := innerQueryError(t, cti, request, nil)
	_, _ = VerifySelectedFieldsInJsonMap(t, request.GetSelectKeys(), results)
}

func TestQueryCdx14MetadataComponentPublisher(t *testing.T) {
	cti := NewCommonTestInfoBasic(TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE)
	request, _ := common.NewQueryRequestSelectFrom(
		"publisher",
		"metadata.component")
	results, _ := innerQueryError(t, cti, request, nil)
	_, _ = VerifySelectedFieldsInJsonMap(t, request.GetSelectKeys(), results)
}

func TestQueryCdx14MetadataAllWithWildcard(t *testing.T) {
	cti := NewCommonTestInfoBasic(TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE)
	request, _ := common.NewQueryRequestSelectWildcardFrom(
		"metadata.component")
	results, _ := innerQueryError(t, cti, request, nil)
	// Check for all known values that should be on the FROM object
	fields := []string{"type", "bom-ref", "licenses", "properties", "publisher", "purl", "name", "description", "version", "externalReferences"}
	_, _ = VerifySelectedFieldsInJsonMap(t, fields, results)
}

// NOTE: properties is an []interface
func TestQueryCdx14MetadataComponentProperties(t *testing.T) {
	cti := NewCommonTestInfoBasic(TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE)
	request, _ := common.NewQueryRequestSelectFrom(
		"properties",
		"metadata.component")
	results, _ := innerQueryError(t, cti, request, nil)
	_, _ = VerifySelectedFieldsInJsonMap(t, request.GetSelectKeys(), results)
}

// ----------------------------------------
// FAIL tests
// ----------------------------------------

func TestQueryFailSpdx22Metadata(t *testing.T) {
	cti := NewCommonTestInfoBasic(TEST_SPDX_2_2_MIN_REQUIRED)
	request, _ := common.NewQueryRequestSelectFrom(
		common.QUERY_TOKEN_WILDCARD,
		"metadata")
	// Expect a QueryError
	_, _ = innerQueryError(t, cti, request, &schema.UnsupportedFormatError{})
}

func TestQueryFailCdx14MetadataComponentInvalidKey(t *testing.T) {
	cti := NewCommonTestInfoBasic(TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE)
	request, _ := common.NewQueryRequestSelectFrom(
		common.QUERY_TOKEN_WILDCARD,
		"metadata.component.foo")
	expectedErrorStrings := []string{
		common.MSG_QUERY_INVALID_FROM_CLAUSE,
		MSG_QUERY_ERROR_FROM_KEY_NOT_FOUND,
	}

	// Expect a QueryError
	_, err := innerQueryError(t, cti, request, &common.QueryError{})

	// Assure we received an error with the expected key phrases
	EvaluateErrorAndKeyPhrases(t, err, expectedErrorStrings)
}

func TestQueryFailCdx14MetadataComponentInvalidDataType(t *testing.T) {
	cti := NewCommonTestInfoBasic(TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE)
	request, _ := common.NewQueryRequestSelectFrom(
		common.QUERY_TOKEN_WILDCARD,
		"metadata.component.name")
	expectedErrorStrings := []string{
		common.MSG_QUERY_INVALID_FROM_CLAUSE,
		MSG_QUERY_INVALID_DATATYPE,
	}
	// Expect a QueryError
	_, err := innerQueryError(t, cti, request, &common.QueryError{})
	// Assure we received an error with the expected key phrases
	EvaluateErrorAndKeyPhrases(t, err, expectedErrorStrings)
}

func TestQueryFailCdx14MetadataComponentInvalidSelectClause(t *testing.T) {
	cti := NewCommonTestInfoBasic(TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE)
	request, _ := common.NewQueryRequestSelectFrom(
		"name,*",
		"metadata.component")
	expectedErrorStrings := []string{
		common.MSG_QUERY_INVALID_SELECT_CLAUSE,
		MSG_QUERY_ERROR_SELECT_WILDCARD,
	}
	// Expect a QueryError
	_, err := innerQueryError(t, cti, request, &common.QueryError{})
	// Assure we received an error with the expected key phrases
	EvaluateErrorAndKeyPhrases(t, err, expectedErrorStrings)
}

func TestQueryFailCdx14InvalidFromClauseWithArray(t *testing.T) {
	cti := NewCommonTestInfoBasic(TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE)
	request, _ := common.NewQueryRequestSelectFrom(
		common.QUERY_TOKEN_WILDCARD,
		"metadata.properties.name")
	expectedErrorStrings := []string{
		common.MSG_QUERY_INVALID_FROM_CLAUSE,
		MSG_QUERY_ERROR_FROM_KEY_SLICE_DEREFERENCE,
	}
	// Expect a QueryError
	_, err := innerQueryError(t, cti, request, &common.QueryError{})
	// Assure we received an error with the expected key phrases
	EvaluateErrorAndKeyPhrases(t, err, expectedErrorStrings)
}

// ----------------------------------------
// WHERE clause tests
// ----------------------------------------

// Force a bad WHERE clause; expect a QueryError
func TestQueryCdx14InvalidWhereClauseNoRegex(t *testing.T) {
	_, err := common.NewQueryRequestSelectFromWhere(
		common.QUERY_TOKEN_WILDCARD,
		"metadata.properties",
		"name")
	// Note: this tests the parameter parsing function
	// TODO: move to "common" package
	if !ErrorTypesMatch(err, &common.QueryError{}) {
		t.Errorf("expected error type: `%T`, actual type: `%T`", &common.QueryError{}, err)
	}
	expectedErrorStrings := []string{
		common.MSG_QUERY_INVALID_WHERE_CLAUSE,
	}
	// Assure we received an error with the expected key phrases
	EvaluateErrorAndKeyPhrases(t, err, expectedErrorStrings)
}

func TestQueryCdx14InvalidWhereClauseMultipleRegex(t *testing.T) {
	_, err := common.NewQueryRequestSelectFromWhere(
		common.QUERY_TOKEN_WILDCARD,
		"metadata.properties",
		"name=foo,value=bar=idk")
	if !ErrorTypesMatch(err, &common.QueryError{}) {
		t.Errorf("expected error type: `%T`, actual type: `%T`", &common.QueryError{}, err)
	}
	expectedErrorStrings := []string{
		common.MSG_QUERY_INVALID_WHERE_CLAUSE,
	}
	// Assure we received an error with the expected key phrases
	EvaluateErrorAndKeyPhrases(t, err, expectedErrorStrings)
}

func TestQueryCdx14InvalidWhereClauseEmptyRegex(t *testing.T) {
	_, err := common.NewQueryRequestSelectFromWhere(
		common.QUERY_TOKEN_WILDCARD,
		"metadata.properties",
		"name=foo,value=")
	if !ErrorTypesMatch(err, &common.QueryError{}) {
		t.Errorf("expected error type: `%T`, actual type: `%T`", &common.QueryError{}, err)
	}
	expectedErrorStrings := []string{
		common.MSG_QUERY_INVALID_WHERE_CLAUSE,
	}
	// Assure we received an error with the expected key phrases
	EvaluateErrorAndKeyPhrases(t, err, expectedErrorStrings)
}

func TestQueryCdx14RequiredDataLegalDisclaimer(t *testing.T) {
	cti := NewCommonTestInfoBasic(TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE)
	request, errNew := common.NewQueryRequestSelectFromWhere(
		common.QUERY_TOKEN_WILDCARD,
		"metadata.properties",
		"name=urn:example.com:classification")
	if errNew != nil {
		t.Errorf("%s: %v", ERR_TYPE_UNEXPECTED_ERROR, errNew)
	}

	// WARN!!!! TODO: handle error tests locally until code is complete
	result, _, err := innerQuery(t, cti, request)
	if err != nil {
		t.Errorf("%s: %v", ERR_TYPE_UNEXPECTED_ERROR, err)
	}

	properties, errUnMarshal := schema.UnMarshalProperties(result)

	// TODO: declare error message as a constant
	if errUnMarshal != nil {
		t.Errorf("invalid `properties` data: %v", errUnMarshal)
	}

	// TODO: verify WHERE clause props. are returned
	getLogger().Debugf("%v", properties)
}

func TestQueryCdx14InvalidWhereClauseOnFromSingleton(t *testing.T) {
	cti := NewCommonTestInfoBasic(TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE)
	request, _ := common.NewQueryRequestSelectFromWhere(
		common.QUERY_TOKEN_WILDCARD,
		"metadata.component",
		"name=foo")
	// Note: this produces a warning, not an error
	_, err := innerQueryError(t, cti, request, nil)
	if err != nil {
		t.Error(err)
	}
}

func TestQueryCdx14MetadataToolsSlice(t *testing.T) {
	cti := NewCommonTestInfoBasic(TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE)
	request, _ := common.NewQueryRequestSelectFromWhere(
		common.QUERY_TOKEN_WILDCARD,
		"metadata.tools",
		"")
	result, err := innerQueryError(t, cti, request, nil)
	if err != nil {
		t.Error(err)
	}
	if !utils.IsJsonSliceType(result) {
		fResult, _ := utils.EncodeAnyToDefaultIndentedJSONStr(result)
		t.Error(fmt.Errorf("expected JSON slice. Actual result: %s", fResult.String()))
	}

	// verify slice length and contents
	slice := result.([]interface{})
	EXPECTED_SLICE_LENGTH := 2
	if actualLength := len(slice); actualLength != EXPECTED_SLICE_LENGTH {
		fResult, _ := utils.EncodeAnyToDefaultIndentedJSONStr(result)
		t.Error(fmt.Errorf("expected slice length: %v, actual length: %v. Actual result: %s", EXPECTED_SLICE_LENGTH, actualLength, fResult.String()))
	}
}

func TestQueryCdx14MetadataToolsSliceWhereName(t *testing.T) {
	cti := NewCommonTestInfoBasic(TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE)
	request, _ := common.NewQueryRequestSelectFromWhere(
		common.QUERY_TOKEN_WILDCARD,
		"components",
		"name=body-parser")
	result, err := innerQueryError(t, cti, request, nil)
	if err != nil {
		t.Error(err)
	}
	if !utils.IsJsonSliceType(result) {
		fResult, _ := utils.EncodeAnyToDefaultIndentedJSONStr(result)
		t.Error(fmt.Errorf("expected JSON slice. Actual result: %s", fResult.String()))
	}

	// verify slice length and contents
	slice := result.([]interface{})
	EXPECTED_SLICE_LENGTH := 1
	if actualLength := len(slice); actualLength != EXPECTED_SLICE_LENGTH {
		fResult, _ := utils.EncodeAnyToDefaultIndentedJSONStr(result)
		t.Error(fmt.Errorf("expected slice length: %v, actual length: %v. Actual result: %s", EXPECTED_SLICE_LENGTH, actualLength, fResult.String()))
	}
}

func TestQueryCdx14MetadataComponentIndent(t *testing.T) {
	cti := NewCommonTestInfoBasic(TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE)
	cti.ResultExpectedLineCount = 6
	cti.ResultExpectedIndentLength = 4
	cti.ResultExpectedIndentAtLineNum = 1
	request, _ := common.NewQueryRequestSelectFrom(
		"name,description,version",
		"metadata.component")

	// Verify that JSON returned by the query command is able to apply default space indent
	results, _ := innerQueryError(t, cti, request, nil)
	buffer, _ := utils.EncodeAnyToIndentedJSONStr(results, utils.DEFAULT_JSON_INDENT_STRING)
	numLines, lines := getBufferLinesAndCount(buffer)

	if numLines != cti.ResultExpectedLineCount {
		t.Errorf("invalid test result: expected: `%v` lines, actual: `%v", cti.ResultExpectedLineCount, numLines)
	}
	if numLines > cti.ResultExpectedIndentAtLineNum {
		line := lines[cti.ResultExpectedIndentAtLineNum]
		if spaceCount := numberOfLeadingSpaces(line); spaceCount != cti.ResultExpectedIndentLength {
			t.Errorf("invalid test result: expected indent:`%v`, actual: `%v", cti.ResultExpectedIndentLength, spaceCount)
		}
	}
}

func TestQueryCdx14MetadataComponentIndentedFileWrite(t *testing.T) {
	cti := NewCommonTestInfoBasic(TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE)
	cti.OutputFile = cti.CreateTemporaryTestOutputFilename(TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE)
	request, _ := common.NewQueryRequestSelectFrom(
		"name,description,version",
		"metadata.component")
	_, err := innerQueryError(t, cti, request, nil)
	if err != nil {
		t.Error(err)
	}
}
