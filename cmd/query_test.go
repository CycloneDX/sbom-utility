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
	"io/fs"
	"testing"

	"github.com/CycloneDX/sbom-utility/common"
	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/CycloneDX/sbom-utility/utils"
)

// TODO: Consolidate query request declarations here

// NOTE: This function "mocks" what the "queryCmdImpl()" function would do
func innerQuery(t *testing.T, filename string, queryRequest *common.QueryRequest, autofail bool) (result interface{}, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Copy the test filename to the command line flags were the code looks for it
	utils.GlobalFlags.PersistentFlags.InputFile = filename

	// Declare an output outputBuffer/outputWriter to use used during tests
	var outputBuffer bytes.Buffer
	var outputWriter = bufio.NewWriter(&outputBuffer)
	// ensure all data is written to buffer before further validation
	defer outputWriter.Flush()

	// allocate response/result object and invoke query
	var response = new(common.QueryResponse)
	result, err = Query(outputWriter, queryRequest, response)

	// if the query resulted in a failure
	if err != nil {
		// if tests asks us to report a FAIL to the test framework
		if autofail {
			t.Errorf("%s: failed: %v\nquery:\n%s", filename, err, queryRequest)
		}
		return
	}

	// This will print results ONLY if --quiet mode is `false`
	printMarshaledResultOnlyIfNotQuiet(result)
	return
}

func innerQueryError(t *testing.T, filename string, queryRequest *common.QueryRequest, expectedError error) (result interface{}, actualError error) {
	getLogger().Enter()
	defer getLogger().Exit()

	result, actualError = innerQuery(t, filename, queryRequest, false)

	// if the query resulted in a failure
	if !ErrorTypesMatch(actualError, expectedError) {
		getLogger().Tracef("expected error type: `%T`, actual type: `%T`", expectedError, actualError)
		t.Errorf("expected error type: `%T`, actual type: `%T`", expectedError, actualError)
	}

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
	request, _ := common.NewQueryRequestSelectWildcardFrom(
		"metadata.properties")
	// Assure we return path error
	_, _ = innerQueryError(t, TEST_INPUT_FILE_NON_EXISTENT, request, &fs.PathError{})
}

// ----------------------------------------
// PASS tests
// ----------------------------------------

func TestQueryCdx14BomFormatSpecVersion(t *testing.T) {
	request, _ := common.NewQueryRequestSelectFrom(
		"bomFormat,specVersion",
		"")
	results, _ := innerQueryError(t, TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE, request, nil)
	_, _ = VerifySelectedFieldsInJsonMap(t, request.GetSelectKeys(), results)
}

func TestQueryCdx14MetadataTimestampField(t *testing.T) {
	request, _ := common.NewQueryRequestSelectFrom(
		"timestamp",
		"metadata")
	results, _ := innerQueryError(t, TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE, request, nil)
	_, _ = VerifySelectedFieldsInJsonMap(t, request.GetSelectKeys(), results)
}

func TestQueryCdx14MetadataComponentAll(t *testing.T) {
	request, _ := common.NewQueryRequestSelectWildcardFrom(
		"metadata.component")
	results, _ := innerQueryError(t, TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE, request, nil)
	// Test for concrete keys that SHOULD have been found using wildcard
	fields := []string{
		"type", "bom-ref", "purl", "version", "externalReferences",
		"name", "description", "licenses", "properties", "hashes",
		"supplier", "publisher"}
	_, _ = VerifySelectedFieldsInJsonMap(t, fields, results)
}

func TestQueryCdx14MetadataComponentNameDescriptionVersion(t *testing.T) {
	request, _ := common.NewQueryRequestSelectFrom(
		"name,description,version",
		"metadata.component")
	results, _ := innerQueryError(t, TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE, request, nil)
	_, _ = VerifySelectedFieldsInJsonMap(t, request.GetSelectKeys(), results)
}

func TestQueryCdx14MetadataSupplier(t *testing.T) {
	request, _ := common.NewQueryRequestSelectFrom(
		common.QUERY_TOKEN_WILDCARD,
		"metadata.supplier")
	results, _ := innerQueryError(t, TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE, request, nil)
	// Test for concrete keys that SHOULD have been found using wildcard
	fields := []string{"name", "url", "contact"}
	_, _ = VerifySelectedFieldsInJsonMap(t, fields, results)
}

func TestQueryCdx14MetadataManufacturer(t *testing.T) {
	request, _ := common.NewQueryRequestSelectFrom(
		common.QUERY_TOKEN_WILDCARD,
		"metadata.manufacture")
	results, _ := innerQueryError(t, TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE, request, nil)
	// Test for concrete keys that SHOULD have been found using wildcard
	fields := []string{"name", "url", "contact"}
	_, _ = VerifySelectedFieldsInJsonMap(t, fields, results)
}

func TestQueryCdx14MetadataComponentLicenses(t *testing.T) {
	request, _ := common.NewQueryRequestSelectFrom(
		"licenses",
		"metadata.component")
	results, _ := innerQueryError(t, TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE, request, nil)
	_, _ = VerifySelectedFieldsInJsonMap(t, request.GetSelectKeys(), results)
}

func TestQueryCdx14MetadataComponentSupplier(t *testing.T) {
	request, _ := common.NewQueryRequestSelectFrom(
		"supplier",
		"metadata.component")
	results, _ := innerQueryError(t, TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE, request, nil)
	_, _ = VerifySelectedFieldsInJsonMap(t, request.GetSelectKeys(), results)
}

func TestQueryCdx14MetadataComponentPublisher(t *testing.T) {
	request, _ := common.NewQueryRequestSelectFrom(
		"publisher",
		"metadata.component")
	results, _ := innerQueryError(t, TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE, request, nil)
	_, _ = VerifySelectedFieldsInJsonMap(t, request.GetSelectKeys(), results)
}

func TestQueryCdx14MetadataAllWithWildcard(t *testing.T) {
	request, _ := common.NewQueryRequestSelectWildcardFrom(
		"metadata.component")
	results, _ := innerQueryError(t, TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE, request, nil)
	// Check for all known values that should be on the FROM object
	fields := []string{"type", "bom-ref", "licenses", "properties", "publisher", "purl", "name", "description", "version", "externalReferences"}
	_, _ = VerifySelectedFieldsInJsonMap(t, fields, results)
}

// NOTE: properties is an []interface
func TestQueryCdx14MetadataComponentProperties(t *testing.T) {
	request, _ := common.NewQueryRequestSelectFrom(
		"properties",
		"metadata.component")
	results, _ := innerQueryError(t, TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE, request, nil)
	_, _ = VerifySelectedFieldsInJsonMap(t, request.GetSelectKeys(), results)
}

// ----------------------------------------
// FAIL tests
// ----------------------------------------

func TestQueryFailSpdx22Metadata(t *testing.T) {
	request, _ := common.NewQueryRequestSelectFrom(
		common.QUERY_TOKEN_WILDCARD,
		"metadata")
	// Expect a QueryError
	_, _ = innerQueryError(t, TEST_SPDX_2_2_MIN_REQUIRED, request, &schema.UnsupportedFormatError{})
}

func TestQueryFailCdx14MetadataComponentInvalidKey(t *testing.T) {
	request, _ := common.NewQueryRequestSelectFrom(
		common.QUERY_TOKEN_WILDCARD,
		"metadata.component.foo")
	expectedErrorStrings := []string{
		common.MSG_QUERY_INVALID_FROM_CLAUSE,
		MSG_QUERY_ERROR_FROM_KEY_NOT_FOUND,
	}

	// Expect a QueryError
	_, err := innerQueryError(t, TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE, request, &common.QueryError{})

	// Assure we received an error with the expected key phrases
	EvaluateErrorAndKeyPhrases(t, err, expectedErrorStrings)
}

func TestQueryFailCdx14MetadataComponentInvalidDataType(t *testing.T) {
	request, _ := common.NewQueryRequestSelectFrom(
		common.QUERY_TOKEN_WILDCARD,
		"metadata.component.name")
	expectedErrorStrings := []string{
		common.MSG_QUERY_INVALID_FROM_CLAUSE,
		MSG_QUERY_INVALID_DATATYPE,
	}
	// Expect a QueryError
	_, err := innerQueryError(t, TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE, request, &common.QueryError{})
	// Assure we received an error with the expected key phrases
	EvaluateErrorAndKeyPhrases(t, err, expectedErrorStrings)
}

func TestQueryFailCdx14MetadataComponentInvalidSelectClause(t *testing.T) {
	request, _ := common.NewQueryRequestSelectFrom(
		"name,*",
		"metadata.component")
	expectedErrorStrings := []string{
		common.MSG_QUERY_INVALID_SELECT_CLAUSE,
		MSG_QUERY_ERROR_SELECT_WILDCARD,
	}
	// Expect a QueryError
	_, err := innerQueryError(t, TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE, request, &common.QueryError{})
	// Assure we received an error with the expected key phrases
	EvaluateErrorAndKeyPhrases(t, err, expectedErrorStrings)
}

func TestQueryFailCdx14InvalidFromClauseWithArray(t *testing.T) {
	request, _ := common.NewQueryRequestSelectFrom(
		common.QUERY_TOKEN_WILDCARD,
		"metadata.properties.name")
	expectedErrorStrings := []string{
		common.MSG_QUERY_INVALID_FROM_CLAUSE,
		MSG_QUERY_ERROR_FROM_KEY_SLICE_DEREFERENCE,
	}
	// Expect a QueryError
	_, err := innerQueryError(t, TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE, request, &common.QueryError{})
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
	request, errNew := common.NewQueryRequestSelectFromWhere(
		common.QUERY_TOKEN_WILDCARD,
		"metadata.properties",
		"name=urn:example.com:classification")
	if errNew != nil {
		t.Errorf("%s: %v", ERR_TYPE_UNEXPECTED_ERROR, errNew)
	}

	// WARN!!!! TODO: handle error tests locally until code is complete
	result, err := innerQuery(t, TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE, request, false)
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
	request, _ := common.NewQueryRequestSelectFromWhere(
		common.QUERY_TOKEN_WILDCARD,
		"metadata.component",
		"name=foo")
	// Note: this produces a warning, not an error
	_, err := innerQueryError(t, TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE, request, nil)
	if err != nil {
		t.Error(err)
	}
}

func TestQueryCdx14MetadataToolsSlice(t *testing.T) {
	request, _ := common.NewQueryRequestSelectFromWhere(
		common.QUERY_TOKEN_WILDCARD,
		"metadata.tools",
		"")
	result, err := innerQueryError(t, TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE, request, nil)
	if err != nil {
		t.Error(err)
	}
	if !utils.IsJsonSliceType(result) {
		fResult, _ := utils.EncodeAnyToIndentedJSON(result, utils.DEFAULT_JSON_INDENT_STRING)
		t.Error(fmt.Errorf("expected JSON slice. Actual result: %s", fResult.String()))
	}

	// verify slice length and contents
	slice := result.([]interface{})
	EXPECTED_SLICE_LENGTH := 2
	if actualLength := len(slice); actualLength != EXPECTED_SLICE_LENGTH {
		fResult, _ := utils.EncodeAnyToIndentedJSON(result, utils.DEFAULT_JSON_INDENT_STRING)
		t.Error(fmt.Errorf("expected slice length: %v, actual length: %v. Actual result: %s", EXPECTED_SLICE_LENGTH, actualLength, fResult.String()))
	}
}

func TestQueryCdx14MetadataToolsSliceWhereName(t *testing.T) {
	request, _ := common.NewQueryRequestSelectFromWhere(
		common.QUERY_TOKEN_WILDCARD,
		"components",
		"name=body-parser")
	result, err := innerQueryError(t, TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE, request, nil)
	if err != nil {
		t.Error(err)
	}
	if !utils.IsJsonSliceType(result) {
		fResult, _ := utils.EncodeAnyToIndentedJSON(result, utils.DEFAULT_JSON_INDENT_STRING)
		t.Error(fmt.Errorf("expected JSON slice. Actual result: %s", fResult.String()))
	}

	// verify slice length and contents
	slice := result.([]interface{})
	EXPECTED_SLICE_LENGTH := 1
	if actualLength := len(slice); actualLength != EXPECTED_SLICE_LENGTH {
		fResult, _ := utils.EncodeAnyToIndentedJSON(result, utils.DEFAULT_JSON_INDENT_STRING)
		t.Error(fmt.Errorf("expected slice length: %v, actual length: %v. Actual result: %s", EXPECTED_SLICE_LENGTH, actualLength, fResult.String()))
	}
}
