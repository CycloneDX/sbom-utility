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
	"io/fs"
	"log"
	"os"
	"testing"

	"github.com/CycloneDX/sbom-utility/common"
	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/CycloneDX/sbom-utility/utils"
)

const (
	// Test "resource list" command
	TEST_RESOURCE_LIST_CDX_1_3            = "test/cyclonedx/cdx-1-3-resource-list.json"
	TEST_RESOURCE_LIST_CDX_1_3_NONE_FOUND = "test/cyclonedx/cdx-1-3-resource-list-none-found.json"
	TEST_RESOURCE_LIST_CDX_1_4_SAAS_1     = "examples/cyclonedx/SaaSBOM/apigateway-microservices-datastores/bom.json"
)

type ResourceTestInfo struct {
	CommonTestInfo
	ResourceType string
}

func (ti *ResourceTestInfo) String() string {
	buffer, _ := utils.EncodeAnyToDefaultIndentedJSONStr(ti)
	return buffer.String()
}

func NewResourceTestInfo(inputFile string, outputFormat string, listSummary bool, whereClause string,
	resultExpectedLineCount int, resourceType string) *ResourceTestInfo {

	var ti = new(ResourceTestInfo)
	var pCommon = &ti.CommonTestInfo
	// initialize common fields
	pCommon.Init(inputFile, outputFormat, listSummary, whereClause,
		nil, resultExpectedLineCount, nil)
	// Initialize resource-unique fields
	ti.ResourceType = resourceType
	return ti
}

func NewResourceTestInfoBasic(inputFile string, listFormat string, resultExpectedError error, resourceType string) *ResourceTestInfo {
	var ti = new(ResourceTestInfo)
	var pCommon = &ti.CommonTestInfo
	pCommon.InitBasic(inputFile, listFormat, resultExpectedError)
	return ti
}

// -------------------------------------------
// resource list test helper functions
// -------------------------------------------
func innerBufferedTestResourceList(t *testing.T, testInfo *ResourceTestInfo, whereFilters []common.WhereFilter) (outputBuffer bytes.Buffer, err error) {
	// Declare an output outputBuffer/outputWriter to use used during tests
	var outputWriter = bufio.NewWriter(&outputBuffer)
	// ensure all data is written to buffer before further validation
	defer outputWriter.Flush()

	var persistentFlags utils.PersistentCommandFlags
	persistentFlags.OutputFormat = testInfo.OutputFormat
	resourceFlags := utils.NewResourceCommandFlags(testInfo.ResourceType)

	err = ListResources(outputWriter, persistentFlags, resourceFlags, whereFilters)
	return
}

func innerTestResourceList(t *testing.T, testInfo *ResourceTestInfo) (outputBuffer bytes.Buffer, basicTestInfo string, err error) {
	getLogger().Tracef("TestInfo: %s", testInfo)

	// Parse out --where filters and exit out if error detected
	whereFilters, err := prepareWhereFilters(t, &testInfo.CommonTestInfo)
	if err != nil {
		return
	}

	// The command looks for the input filename in global flags struct
	utils.GlobalFlags.PersistentFlags.InputFile = testInfo.InputFile

	// Mock stdin if requested
	if testInfo.MockStdin == true {
		utils.GlobalFlags.PersistentFlags.InputFile = INPUT_TYPE_STDIN
		file, err := os.Open(testInfo.InputFile) // For read access.
		if err != nil {
			log.Fatal(err)
		}

		// convert byte slice to io.Reader
		savedStdIn := os.Stdin
		// !!!Important restore stdin
		defer func() { os.Stdin = savedStdIn }()
		os.Stdin = file
	}

	// invoke resource list command with a byte buffer
	outputBuffer, err = innerBufferedTestResourceList(t, testInfo, whereFilters)

	// Run all common tests against "result" values in the CommonTestInfo struct
	err = innerRunReportResultTests(t, &testInfo.CommonTestInfo, outputBuffer, err)

	return
}

// ----------------------------------------
// Command flag tests
// ----------------------------------------

func TestResourceListInvalidInputFileLoad(t *testing.T) {
	rti := NewResourceTestInfoBasic(
		TEST_INPUT_FILE_NON_EXISTENT,
		FORMAT_DEFAULT,
		&fs.PathError{},
		schema.RESOURCE_TYPE_DEFAULT,
	)

	// verify correct error is returned
	innerTestResourceList(t, rti)
}

// -------------------------------------------
// Test format unsupported (SPDX)
// -------------------------------------------
func TestResourceListFormatUnsupportedSPDXMinReq(t *testing.T) {
	rti := NewResourceTestInfoBasic(
		TEST_SPDX_2_2_MIN_REQUIRED,
		FORMAT_DEFAULT,
		&schema.UnsupportedFormatError{},
		schema.RESOURCE_TYPE_DEFAULT,
	)

	// verify correct error is returned
	innerTestResourceList(t, rti)
}

func TestResourceListFormatUnsupportedSPDX22(t *testing.T) {
	rti := NewResourceTestInfoBasic(
		TEST_SPDX_2_2_EXAMPLE_1,
		FORMAT_DEFAULT,
		&schema.UnsupportedFormatError{},
		schema.RESOURCE_TYPE_DEFAULT,
	)

	// verify correct error is returned
	innerTestResourceList(t, rti)
}

// -------------------------------------------
// CDX variants - Test for list (data) errors
// -------------------------------------------

func TestResourceListTextCdx14NoServicesFound(t *testing.T) {
	rti := NewResourceTestInfoBasic(
		TEST_RESOURCE_LIST_CDX_1_3_NONE_FOUND,
		FORMAT_TEXT,
		nil, // no error
		schema.RESOURCE_TYPE_SERVICE,
	)

	// verify there is a (warning) message present when no resources are found
	rti.ResultLineContainsValues = []string{MSG_OUTPUT_NO_RESOURCES_FOUND}
	rti.ResultLineContainsValuesAtLineNum = 2
	innerTestResourceList(t, rti)
}

// -------------------------------------------
// CDX variants - List only
// -------------------------------------------

// Assure text format listing (report) works
func TestResourceListTextCdx13(t *testing.T) {
	rti := NewResourceTestInfoBasic(
		TEST_RESOURCE_LIST_CDX_1_3,
		FORMAT_TEXT,
		nil, // no error
		schema.RESOURCE_TYPE_DEFAULT,
	)

	innerTestResourceList(t, rti)
}

func TestResourceListTextCdx14SaaS(t *testing.T) {

	rti := NewResourceTestInfoBasic(
		TEST_RESOURCE_LIST_CDX_1_4_SAAS_1,
		FORMAT_TEXT,
		nil, // no error
		schema.RESOURCE_TYPE_COMPONENT)

	innerTestResourceList(t, rti)
}

// -------------------------------------------
// CDX variants - WHERE clause tests
// -------------------------------------------

func TestResourceListTextCdx13WhereClauseAndResultsByNameStartswith(t *testing.T) {
	TEST_INPUT_WHERE_CLAUSE := "name=Library A"
	TEST_OUTPUT_CONTAINS := []string{"component", "Library A", "1.0.0", "pkg:lib/libraryA@1.0.0"}
	TEST_OUTPUT_LINES := 3
	rti := NewResourceTestInfo(
		TEST_RESOURCE_LIST_CDX_1_3,
		FORMAT_TEXT,
		TI_LIST_SUMMARY_FALSE,
		TEST_INPUT_WHERE_CLAUSE,
		TEST_OUTPUT_LINES,
		schema.RESOURCE_TYPE_COMPONENT)
	rti.ResultLineContainsValues = TEST_OUTPUT_CONTAINS
	rti.ResultLineContainsValuesAtLineNum = 2
	innerTestResourceList(t, rti)
}

func TestResourceListTextCdx13WhereClauseAndResultsByNameContains(t *testing.T) {
	TEST_INPUT_WHERE_CLAUSE := "name=^.*\\sF.*$"
	TEST_OUTPUT_CONTAINS := []string{"component", "Library F", "1.0.0", "pkg:lib/libraryF@1.0.0"}
	TEST_OUTPUT_LINES := 3

	rti := NewResourceTestInfo(
		TEST_RESOURCE_LIST_CDX_1_3,
		FORMAT_TEXT,
		TI_LIST_SUMMARY_FALSE,
		TEST_INPUT_WHERE_CLAUSE,
		TEST_OUTPUT_LINES,
		schema.RESOURCE_TYPE_COMPONENT)
	rti.ResultLineContainsValues = TEST_OUTPUT_CONTAINS
	rti.ResultLineContainsValuesAtLineNum = 2
	innerTestResourceList(t, rti)
}

func TestResourceListTextCdx13WhereClauseAndResultsBomRefContains(t *testing.T) {
	TEST_INPUT_WHERE_CLAUSE := "bom-ref=^.*library.*$"
	TEST_OUTPUT_CONTAINS := []string{"component", "Library J", "1.0.0", "pkg:lib/libraryJ@1.0.0"}
	TEST_OUTPUT_LINES := 12

	rti := NewResourceTestInfo(
		TEST_RESOURCE_LIST_CDX_1_3,
		FORMAT_TEXT,
		TI_LIST_SUMMARY_FALSE,
		TEST_INPUT_WHERE_CLAUSE,
		TEST_OUTPUT_LINES,
		schema.RESOURCE_TYPE_COMPONENT)
	rti.ResultLineContainsValues = TEST_OUTPUT_CONTAINS
	rti.ResultLineContainsValuesAtLineNum = 10
	innerTestResourceList(t, rti)
}

func TestResourceListTextCdx13WhereClauseAndResultsVersionStartswith(t *testing.T) {
	TEST_INPUT_WHERE_CLAUSE := "version=2.0"
	TEST_OUTPUT_CONTAINS := []string{"component", "ACME Application", "2.0.0", "pkg:app/sample@1.0.0"}
	TEST_OUTPUT_LINES := 3

	rti := NewResourceTestInfo(
		TEST_RESOURCE_LIST_CDX_1_3,
		FORMAT_TEXT,
		TI_LIST_SUMMARY_FALSE,
		TEST_INPUT_WHERE_CLAUSE,
		TEST_OUTPUT_LINES,
		schema.RESOURCE_TYPE_COMPONENT)
	rti.ResultLineContainsValues = TEST_OUTPUT_CONTAINS
	rti.ResultLineContainsValuesAtLineNum = 2
	innerTestResourceList(t, rti)
}

func TestResourceListTextCdx13WhereClauseAndResultsNone(t *testing.T) {
	TEST_INPUT_WHERE_CLAUSE := "version=2.0"
	TEST_OUTPUT_CONTAINS := []string{MSG_OUTPUT_NO_RESOURCES_FOUND}
	TEST_OUTPUT_LINES := 3

	rti := NewResourceTestInfo(
		TEST_RESOURCE_LIST_CDX_1_3,
		FORMAT_TEXT,
		TI_LIST_SUMMARY_FALSE,
		TEST_INPUT_WHERE_CLAUSE,
		TEST_OUTPUT_LINES,
		schema.RESOURCE_TYPE_SERVICE)
	rti.ResultLineContainsValues = TEST_OUTPUT_CONTAINS
	rti.ResultLineContainsValuesAtLineNum = 2

	// THere are no services that meet the where filter criteria
	// check for warning message in output
	innerTestResourceList(t, rti)
}

func TestResourceListUsingStdin(t *testing.T) {

	rti := NewResourceTestInfoBasic(
		TEST_RESOURCE_LIST_CDX_1_3,
		FORMAT_TEXT,
		nil, // no error
		schema.RESOURCE_TYPE_DEFAULT,
	)

	rti.MockStdin = true

	innerTestResourceList(t, rti)
}
