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

// -------------------------------------------
// resource list test helper functions
// -------------------------------------------

func innerTestResourceList(t *testing.T, inputFile string, format string, resourceType string, whereClause string, expected error) (outputBuffer bytes.Buffer, testInfo string, err error) {

	testInfo = fmt.Sprintf("test file: \"%s\", format: %s, resource type: %s, where clause: %s", inputFile, format, resourceType, whereClause)
	getLogger().Trace(testInfo)

	// Declare an output outputBuffer/outputWriter to use used during tests
	var outputWriter = bufio.NewWriter(&outputBuffer)
	// ensure all data is written to buffer before further validation
	defer outputWriter.Flush()

	var whereFilters []WhereFilter = nil
	if whereClause != "" {
		whereFilters, err = retrieveWhereFilters(whereClause)
		if err != nil {
			getLogger().Error(err)
			t.Errorf("Test failed: %s: details: %s ", testInfo, err.Error())
		}
	}

	// Use a test input SBOM formatted in SPDX
	utils.GlobalFlags.InputFile = inputFile
	err = ListResources(outputWriter, format, resourceType, whereFilters)

	if expected != nil {
		if !ErrorTypesMatch(err, expected) {
			t.Errorf("expected error: %T, actual error: %T", &fs.PathError{}, err)
		}
		return
	}

	if err != nil {
		t.Errorf("Test failed: %s: details: %s ", testInfo, err.Error())
	}

	return
}

func innerTestResourceListBasic(t *testing.T, inputFile string, format string, expected error) (outputBuffer bytes.Buffer, testInfo string, err error) {
	return innerTestResourceList(t, inputFile, format, RESOURCE_TYPE_DEFAULT, "", expected)
}

func innerTestResourceListResults(t *testing.T, inputFile string, format string, resourceType string, whereClause string, resultContains string, resultLines int, expected error) (outputBuffer bytes.Buffer, testInfo string, err error) {

	outputBuffer, testInfo, err = innerTestResourceList(t,
		inputFile,
		format,
		resourceType,
		whereClause,
		expected)

	// Test buffer has ONLY correct results for test case
	if err == nil {
		str := outputBuffer.String()
		lines := strings.Count(str, "\n")
		getLogger().Debugf("output: \"%s\"", str)

		if lines > resultLines || !strings.Contains(str, resultContains) {
			err = getLogger().Errorf("invalid output for where clause")
			t.Errorf("%s: input file: `%s`, where clause: `%s`",
				err.Error(),
				inputFile,
				whereClause)
		}
	}

	return
}

// ----------------------------------------
// Command flag tests
// ----------------------------------------

func TestResourceListInvalidInputFileLoad(t *testing.T) {
	innerTestResourceListBasic(t,
		TEST_INPUT_FILE_NON_EXISTENT,
		OUTPUT_DEFAULT,
		&fs.PathError{})
}

// -------------------------------------------
// Test format unsupported (SPDX)
// -------------------------------------------
func TestResourceListFormatUnsupportedSPDX1(t *testing.T) {
	innerTestResourceListBasic(t,
		TEST_SPDX_2_2_MIN_REQUIRED,
		OUTPUT_DEFAULT,
		&schema.UnsupportedFormatError{})
}

func TestResourceListFormatUnsupportedSPDX2(t *testing.T) {
	innerTestResourceListBasic(t,
		TEST_SPDX_2_2_EXAMPLE_1,
		OUTPUT_DEFAULT,
		&schema.UnsupportedFormatError{})
}

// -------------------------------------------
// CDX variants - Test for list (data) errors
// -------------------------------------------

func TestResourceListTextCdx14NoneFound(t *testing.T) {
	outputBuffer, _, _ := innerTestResourceListBasic(t,
		TEST_RESOURCE_LIST_CDX_1_3_NONE_FOUND,
		OUTPUT_TEXT,
		nil)

	// verify there is a (warning) message present when no resources are found
	s := outputBuffer.String()
	if !strings.Contains(s, MSG_OUTPUT_NO_RESOURCES_FOUND) {
		t.Errorf("ListResources(): did not include the message: `%s`", MSG_OUTPUT_NO_LICENSES_FOUND)
		t.Logf("%s", outputBuffer.String())
	}
}

// -------------------------------------------
// CDX variants - List only
// -------------------------------------------

// Assure text format listing (report) works
func TestResourceListTextCdx13(t *testing.T) {
	innerTestResourceListBasic(t,
		TEST_RESOURCE_LIST_CDX_1_3,
		OUTPUT_TEXT,
		nil)
}

func TestResourceListTextCdx14SaaS(t *testing.T) {
	innerTestResourceListBasic(t,
		TEST_RESOURCE_LIST_CDX_1_4_SAAS_1,
		OUTPUT_TEXT,
		nil)
}

// -------------------------------------------
// CDX variants - WHERE clause tests
// -------------------------------------------

func TestResourceListTextCdx13WhereClauseAndResults(t *testing.T) {
	TEST_INPUT_WHERE_FILTERS := "name=Library A"
	TEST_OUTPUT_CONTAINS := "Library A"
	TEST_OUTPUT_LINES := 3

	innerTestResourceListResults(t,
		TEST_RESOURCE_LIST_CDX_1_3,
		OUTPUT_TEXT,
		RESOURCE_TYPE_DEFAULT,
		TEST_INPUT_WHERE_FILTERS,
		TEST_OUTPUT_CONTAINS,
		TEST_OUTPUT_LINES,
		nil)
}
