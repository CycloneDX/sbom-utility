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
	"fmt"
	"io/fs"
	"strings"
	"testing"

	"github.com/scs/sbom-utility/schema"
	"github.com/scs/sbom-utility/utils"
)

const (
	// Test "resource list" command
	TEST_RESOURCE_LIST_CDX_1_3            = "test/cyclonedx/cdx-1-3-resource-list.json"
	TEST_RESOURCE_LIST_CDX_1_3_NONE_FOUND = "test/cyclonedx/cdx-1-3-resource-list-none-found.json"
	TEST_RESOURCE_LIST_CDX_1_4_SAAS_1     = "examples/cyclonedx/SaaSBOM/apigateway-microservices-datastores/bom.json"
)

type ResourceTestInfo struct {
	InputFile       string
	Format          string
	ResourceType    string
	WhereClause     string
	ExpectedError   error
	ResultContains  string
	ResultLineCount int
}

func (rti *ResourceTestInfo) String() string {
	return fmt.Sprintf("InputFile: `%s`, Format: `%s`, ResourceType: `%s`, WhereClause: `%s`",
		rti.InputFile, rti.Format, rti.ResourceType, rti.WhereClause)
}

func NewResourceTestInfo(inputFile string, format string, resourceType string,
	whereClause string, resultContains string, resultLines int, expectedError error) *ResourceTestInfo {

	var rti = new(ResourceTestInfo)
	rti.InputFile = inputFile
	rti.Format = format
	rti.ResourceType = resourceType
	if !sliceContains(VALID_RESOURCE_TYPES, resourceType) {
		rti.ResourceType = RESOURCE_TYPE_DEFAULT
	}
	rti.WhereClause = whereClause
	rti.ResultContains = resultContains
	rti.ResultLineCount = resultLines
	rti.ExpectedError = expectedError
	return rti
}

func NewResourceTestInfoBasic(inputFile string, format string, resourceType string, expectedError error) *ResourceTestInfo {
	return NewResourceTestInfo(inputFile, format, resourceType, "", "", -1, expectedError)
}

// -------------------------------------------
// resource list test helper functions
// -------------------------------------------

func innerTestResourceList(t *testing.T, testInfo *ResourceTestInfo) (outputBuffer bytes.Buffer, basicTestInfo string, err error) {
	getLogger().Tracef("TestInfo: %s", testInfo)

	// Declare an output outputBuffer/outputWriter to use used during tests
	var outputWriter = bufio.NewWriter(&outputBuffer)
	// ensure all data is written to buffer before further validation
	defer outputWriter.Flush()

	var whereFilters []WhereFilter = nil
	if testInfo.WhereClause != "" {
		whereFilters, err = retrieveWhereFilters(testInfo.WhereClause)
		if err != nil {
			getLogger().Error(err)
			t.Errorf("test failed: %s: detail: %s ", basicTestInfo, err.Error())
		}
	}

	// Use a test input SBOM formatted in SPDX
	utils.GlobalFlags.InputFile = testInfo.InputFile
	err = ListResources(outputWriter, testInfo.Format, testInfo.ResourceType, whereFilters)

	if testInfo.ExpectedError != nil {
		if !ErrorTypesMatch(err, testInfo.ExpectedError) {
			t.Errorf("expected error: %T, actual error: %T", &fs.PathError{}, err)
		}
		return
	}

	if err != nil {
		t.Errorf("test failed: %s: detail: %s ", testInfo, err.Error())
	}

	return
}

func innerTestResourceListResults(t *testing.T, testInfo *ResourceTestInfo) (outputBuffer bytes.Buffer, testDetails string, err error) {

	outputBuffer, testDetails, err = innerTestResourceList(t, testInfo)

	// Test buffer has ONLY correct results for test case
	if err == nil {
		outputResults := outputBuffer.String()
		outputLineCount := strings.Count(outputResults, "\n")
		getLogger().Debugf("output: \"%s\"", outputResults)

		if !strings.Contains(outputResults, testInfo.ResultContains) {
			err = getLogger().Errorf("output did not contain expected value: `%s`", testInfo.ResultContains)
			t.Errorf("%s: input file: `%s`, where clause: `%s`",
				err.Error(),
				testInfo.InputFile,
				testInfo.WhereClause)
			return
		}

		if outputLineCount != testInfo.ResultLineCount {
			err = getLogger().Errorf("output did not contain expected line count: %v/%v (expected/actual)", testInfo.ResultLineCount, outputLineCount)
			t.Errorf("%s: input file: `%s`, where clause: `%s`",
				err.Error(),
				testInfo.InputFile,
				testInfo.WhereClause)
			return
		}
	}

	return
}

// ----------------------------------------
// Command flag tests
// ----------------------------------------

func TestResourceListInvalidInputFileLoad(t *testing.T) {
	rti := NewResourceTestInfoBasic(
		TEST_INPUT_FILE_NON_EXISTENT,
		OUTPUT_DEFAULT,
		RESOURCE_TYPE_DEFAULT,
		&fs.PathError{})

	// verify correct error is returned
	innerTestResourceList(t, rti)
}

// -------------------------------------------
// Test format unsupported (SPDX)
// -------------------------------------------
func TestResourceListFormatUnsupportedSPDX1(t *testing.T) {
	rti := NewResourceTestInfoBasic(
		TEST_SPDX_2_2_MIN_REQUIRED,
		OUTPUT_DEFAULT,
		RESOURCE_TYPE_DEFAULT,
		&schema.UnsupportedFormatError{})

	// verify correct error is returned
	innerTestResourceList(t, rti)
}

func TestResourceListFormatUnsupportedSPDX2(t *testing.T) {
	rti := NewResourceTestInfoBasic(
		TEST_SPDX_2_2_EXAMPLE_1,
		OUTPUT_DEFAULT,
		RESOURCE_TYPE_DEFAULT,
		&schema.UnsupportedFormatError{})

	// verify correct error is returned
	innerTestResourceList(t, rti)
}

// -------------------------------------------
// CDX variants - Test for list (data) errors
// -------------------------------------------

func TestResourceListTextCdx14NoneFound(t *testing.T) {
	rti := NewResourceTestInfoBasic(
		TEST_RESOURCE_LIST_CDX_1_3_NONE_FOUND,
		OUTPUT_TEXT,
		RESOURCE_TYPE_SERVICE,
		nil)

	// verify there is a (warning) message present when no resources are found
	rti.ResultContains = MSG_OUTPUT_NO_RESOURCES_FOUND
	innerTestResourceList(t, rti)
}

// -------------------------------------------
// CDX variants - List only
// -------------------------------------------

// Assure text format listing (report) works
func TestResourceListTextCdx13(t *testing.T) {
	rti := NewResourceTestInfoBasic(
		TEST_RESOURCE_LIST_CDX_1_3,
		OUTPUT_TEXT,
		RESOURCE_TYPE_DEFAULT,
		nil)

	innerTestResourceList(t, rti)
}

func TestResourceListTextCdx14SaaS(t *testing.T) {

	rti := NewResourceTestInfoBasic(
		TEST_RESOURCE_LIST_CDX_1_3,
		OUTPUT_TEXT,
		RESOURCE_TYPE_COMPONENT,
		nil)

	innerTestResourceList(t, rti)
}

// -------------------------------------------
// CDX variants - WHERE clause tests
// -------------------------------------------

func TestResourceListTextCdx13WhereClauseAndResults1(t *testing.T) {
	TEST_INPUT_WHERE_CLAUSE := "name=Library A"
	TEST_OUTPUT_CONTAINS := "Library A"
	TEST_OUTPUT_LINES := 3

	rti := NewResourceTestInfo(
		TEST_RESOURCE_LIST_CDX_1_3,
		OUTPUT_TEXT,
		RESOURCE_TYPE_COMPONENT,
		TEST_INPUT_WHERE_CLAUSE,
		TEST_OUTPUT_CONTAINS,
		TEST_OUTPUT_LINES,
		nil)

	innerTestResourceListResults(t, rti)
}

func TestResourceListTextCdx13WhereClauseAndResults2(t *testing.T) {
	TEST_INPUT_WHERE_CLAUSE := "version=2.0"
	TEST_OUTPUT_CONTAINS := "ACME Application"
	TEST_OUTPUT_LINES := 3

	rti := NewResourceTestInfo(
		TEST_RESOURCE_LIST_CDX_1_3,
		OUTPUT_TEXT,
		RESOURCE_TYPE_COMPONENT,
		TEST_INPUT_WHERE_CLAUSE,
		TEST_OUTPUT_CONTAINS,
		TEST_OUTPUT_LINES,
		nil)

	innerTestResourceListResults(t, rti)
}

func TestResourceListTextCdx13WhereClauseAndResultsNone(t *testing.T) {
	TEST_INPUT_WHERE_CLAUSE := "version=2.0"
	TEST_OUTPUT_CONTAINS := MSG_OUTPUT_NO_RESOURCES_FOUND
	TEST_OUTPUT_LINES := 3

	rti := NewResourceTestInfo(
		TEST_RESOURCE_LIST_CDX_1_3,
		OUTPUT_TEXT,
		RESOURCE_TYPE_SERVICE,
		TEST_INPUT_WHERE_CLAUSE,
		TEST_OUTPUT_CONTAINS,
		TEST_OUTPUT_LINES,
		nil)

	// THere are no services that meet the where filter criteria
	// check for warning message in output
	innerTestResourceListResults(t, rti)
}
