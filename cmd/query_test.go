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
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
	"testing"

	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/CycloneDX/sbom-utility/utils"
)

// TODO: Consolidate query request declarations here

// NOTE: This function "mocks" what the "queryCmdImpl()" function would do
func innerQuery(t *testing.T, filename string, queryRequest *QueryRequest, autofail bool) (result interface{}, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Parse normalized query clauses
	err = queryRequest.parseQueryClauses()
	if err != nil {
		if autofail {
			t.Errorf("invalid query parameters: %s: query:\n%s", err, queryRequest)
		}
		return
	}

	// Copy the test filename to the command line flags were the code looks for it
	utils.GlobalFlags.InputFile = filename

	// allocate response/result object and invoke query
	var response = new(QueryResponse)
	result, err = query(queryRequest, response)

	// if the query resulted in a failure
	if err != nil {
		// if tests asks us to report a FAIL to the test framework
		if autofail {
			t.Errorf("%s: failed: %v\nquery:\n%s", filename, err, queryRequest)
		}
		return
	}

	// This will print results ONLY if --quiet mode is `false`
	printResult(result)
	return
}

func innerQueryError(t *testing.T, filename string, queryRequest *QueryRequest, expectedError error) (result interface{}, actualError error) {
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
func VerifySelectedFieldsInJsonMap(t *testing.T, request *QueryRequest, results interface{}) (exists bool, err error) {

	getLogger().Tracef("Testing for keys: \"%s\"", request.selectFieldsRaw)

	if results == nil {
		t.Errorf("invalid results: %v", results)
	}

	resultMap, err := UnmarshalResultsToMap(results)
	if err != nil {
		getLogger().Tracef("results: %v", resultMap)
		t.Errorf("invalid JSON: %s: %v", err, resultMap)
	}

	keys := strings.Split(request.selectFieldsRaw, QUERY_SELECT_CLAUSE_SEP)

	for _, key := range keys {
		_, exists = resultMap[key]
		if !exists {
			t.Errorf("invalid results: key: `%s` does not exist.", key)
		}
	}
	return
}

func printResult(iResult interface{}) {
	if !*TestLogQuiet {
		// Format results in JSON
		fResult, _ := utils.ConvertMapToJson(iResult)
		// Output the JSON data directly to stdout (not subject to log-level)
		fmt.Printf("%s\n", fResult)
	}
}

// ----------------------------------------
// Command flag tests
// ----------------------------------------

func TestQueryFailInvalidInputFileLoad(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: QUERY_TOKEN_WILDCARD,
		fromObjectsRaw:  "metadata.properties",
	}
	// Assure we return path error
	innerQueryError(t, TEST_INPUT_FILE_NON_EXISTENT, &request, &fs.PathError{})
}

// ----------------------------------------
// PASS tests
// ----------------------------------------

func TestQueryCdx14BomFormatSpecVersion(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "bomFormat,specVersion",
		fromObjectsRaw:  "",
	}
	results, _ := innerQueryError(t, TEST_CDX_1_4_MATURITY_BASE, &request, nil)
	VerifySelectedFieldsInJsonMap(t, &request, results)
}

func TestQueryCdx14MetadataTimestampField(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "timestamp",
		fromObjectsRaw:  "metadata",
	}
	results, _ := innerQueryError(t, TEST_CDX_1_4_MATURITY_BASE, &request, nil)
	VerifySelectedFieldsInJsonMap(t, &request, results)
}

func TestQueryCdx14MetadataComponentAll(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: QUERY_TOKEN_WILDCARD,
		fromObjectsRaw:  "metadata.component",
	}
	results, _ := innerQueryError(t, TEST_CDX_1_4_MATURITY_BASE, &request, nil)
	// Test for concrete keys that SHOULD have been found using wildcard
	request.selectFieldsRaw = "type,bom-ref,purl,version,externalReferences,name,description,licenses,properties,hashes,supplier,publisher"
	VerifySelectedFieldsInJsonMap(t, &request, results)
}

func TestQueryCdx14MetadataComponentNameDescriptionVersion(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "name,description,version",
		fromObjectsRaw:  "metadata.component",
	}
	results, _ := innerQueryError(t, TEST_CDX_1_4_MATURITY_BASE, &request, nil)
	VerifySelectedFieldsInJsonMap(t, &request, results)
}

func TestQueryCdx14MetadataSupplier(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: QUERY_TOKEN_WILDCARD,
		fromObjectsRaw:  "metadata.supplier",
	}
	results, _ := innerQueryError(t, TEST_CDX_1_4_MATURITY_BASE, &request, nil)
	// Test for concrete keys that SHOULD have been found using wildcard
	request.selectFieldsRaw = "name,url,contact"
	VerifySelectedFieldsInJsonMap(t, &request, results)
}

func TestQueryCdx14MetadataManufacturer(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: QUERY_TOKEN_WILDCARD,
		fromObjectsRaw:  "metadata.manufacture",
	}
	results, _ := innerQueryError(t, TEST_CDX_1_4_MATURITY_BASE, &request, nil)
	// Test for concrete keys that SHOULD have been found using wildcard
	request.selectFieldsRaw = "name,url,contact"
	match, _ := VerifySelectedFieldsInJsonMap(t, &request, results)
	if !match {
		getLogger().Tracef("Expected fields not matched: %s", request.selectFieldsRaw)
	}
}

func TestQueryCdx14MetadataComponentLicenses(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "licenses",
		fromObjectsRaw:  "metadata.component",
	}
	results, _ := innerQueryError(t, TEST_CDX_1_4_MATURITY_BASE, &request, nil)
	VerifySelectedFieldsInJsonMap(t, &request, results)
}

func TestQueryCdx14MetadataComponentSupplier(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "supplier",
		fromObjectsRaw:  "metadata.component",
	}
	results, _ := innerQueryError(t, TEST_CDX_1_4_MATURITY_BASE, &request, nil)
	VerifySelectedFieldsInJsonMap(t, &request, results)
}

func TestQueryCdx14MetadataComponentPublisher(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "publisher",
		fromObjectsRaw:  "metadata.component",
	}
	results, _ := innerQueryError(t, TEST_CDX_1_4_MATURITY_BASE, &request, nil)
	VerifySelectedFieldsInJsonMap(t, &request, results)
}

// // NOTE: licenses is an []interface
// TODO: Look into supporting reducing array result objects (not maps) to strictly selected fields
// func TestQueryCdx14MetadataComponentLicenseExpression(t *testing.T) {
// 	request := QueryRequest{
// 		selectFieldsRaw: "license,expression",
// 		fromObjectsRaw:  "metadata.component.licenses",
// 	}
// 	innerQuery(t, TEST_CDX_1_4_MATURITY_BASE, &request, true)
// }

// NOTE: properties is an []interface
func TestQueryCdx14MetadataComponentProperties(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "properties",
		fromObjectsRaw:  "metadata.component",
	}
	results, _ := innerQueryError(t, TEST_CDX_1_4_MATURITY_BASE, &request, nil)
	VerifySelectedFieldsInJsonMap(t, &request, results)
}

// ----------------------------------------
// FAIL tests
// ----------------------------------------

func TestQueryFailSpdx22Metadata(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: QUERY_TOKEN_WILDCARD,
		fromObjectsRaw:  "metadata",
	}

	// Expect a QueryError
	innerQueryError(t, TEST_SPDX_2_2_MIN_REQUIRED, &request, &schema.UnsupportedFormatError{})
}

func TestQueryFailCdx14MetadataComponentInvalidKey(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: QUERY_TOKEN_WILDCARD,
		fromObjectsRaw:  "metadata.component.foo",
	}

	expectedErrorStrings := []string{
		MSG_QUERY_INVALID_FROM_CLAUSE,
		MSG_QUERY_ERROR_FROM_KEY_NOT_FOUND,
	}

	// Expect a QueryError
	_, err := innerQueryError(t, TEST_CDX_1_4_MATURITY_BASE, &request, &QueryError{})

	// Assure we received an error with the expected key phrases
	EvaluateErrorAndKeyPhrases(t, err, expectedErrorStrings)
}

func TestQueryFailCdx14MetadataComponentInvalidDataType(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: QUERY_TOKEN_WILDCARD,
		fromObjectsRaw:  "metadata.component.name",
	}
	expectedErrorStrings := []string{
		MSG_QUERY_INVALID_DATATYPE,
		MSG_QUERY_ERROR_FROM_KEY_INVALID_OBJECT,
	}

	// Expect a QueryError
	_, err := innerQueryError(t, TEST_CDX_1_4_MATURITY_BASE, &request, &QueryError{})

	// Assure we received an error with the expected key phrases
	EvaluateErrorAndKeyPhrases(t, err, expectedErrorStrings)
}

func TestQueryFailCdx14MetadataComponentInvalidSelectClause(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "name,*",
		fromObjectsRaw:  "metadata.component",
	}

	expectedErrorStrings := []string{
		MSG_QUERY_INVALID_SELECT_CLAUSE,
		MSG_QUERY_ERROR_SELECT_WILDCARD,
	}

	// Expect a QueryError
	_, err := innerQueryError(t, TEST_CDX_1_4_MATURITY_BASE, &request, &QueryError{})

	// Assure we received an error with the expected key phrases
	EvaluateErrorAndKeyPhrases(t, err, expectedErrorStrings)
}

func TestQueryFailCdx14InvalidFromClauseWithArray(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: QUERY_TOKEN_WILDCARD,
		fromObjectsRaw:  "metadata.properties.name",
	}

	expectedErrorStrings := []string{
		MSG_QUERY_INVALID_FROM_CLAUSE,
		MSG_QUERY_ERROR_FROM_KEY_SLICE_DEREFERENCE,
	}

	// Expect a QueryError
	_, err := innerQueryError(t, TEST_CDX_1_4_MATURITY_BASE, &request, &QueryError{})

	// Assure we received an error with the expected key phrases
	EvaluateErrorAndKeyPhrases(t, err, expectedErrorStrings)
}

// ----------------------------------------
// WHERE clause tests
// ----------------------------------------

func TestQueryCdx14InvalidWhereClauseNoRegex(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: QUERY_TOKEN_WILDCARD,
		fromObjectsRaw:  "metadata.properties",
		whereValuesRaw:  "name",
	}

	// Expect a QueryError
	_, err := innerQueryError(t, TEST_CDX_1_4_MATURITY_BASE, &request, &QueryError{})

	expectedErrorStrings := []string{
		MSG_QUERY_INVALID_WHERE_CLAUSE,
	}

	// Assure we received an error with the expected key phrases
	EvaluateErrorAndKeyPhrases(t, err, expectedErrorStrings)
}

func TestQueryCdx14InvalidWhereClauseMultipleRegex(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: QUERY_TOKEN_WILDCARD,
		fromObjectsRaw:  "metadata.properties",
		whereValuesRaw:  "name=foo,value=bar=idk",
	}

	_, err := innerQueryError(t, TEST_CDX_1_4_MATURITY_BASE, &request, &QueryError{})

	expectedErrorStrings := []string{
		MSG_QUERY_INVALID_WHERE_CLAUSE,
	}

	// Assure we received an error with the expected key phrases
	EvaluateErrorAndKeyPhrases(t, err, expectedErrorStrings)
}

func TestQueryCdx14InvalidWhereClauseEmptyRegex(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: QUERY_TOKEN_WILDCARD,
		fromObjectsRaw:  "metadata.properties",
		whereValuesRaw:  "name=foo,value=",
	}

	_, err := innerQueryError(t, TEST_CDX_1_4_MATURITY_BASE, &request, &QueryError{})

	expectedErrorStrings := []string{
		MSG_QUERY_INVALID_WHERE_CLAUSE,
	}

	// Assure we received an error with the expected key phrases
	EvaluateErrorAndKeyPhrases(t, err, expectedErrorStrings)
}

func TestQueryCdx14RequiredDataLegalDisclaimer(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: QUERY_TOKEN_WILDCARD,
		fromObjectsRaw:  "metadata.properties",
		whereValuesRaw:  "name=urn:example.com:classification",
	}

	// WARN!!!! TODO: handle error tests locally until code is complete
	result, err := innerQuery(t, TEST_CDX_1_4_MATURITY_BASE, &request, false)

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
