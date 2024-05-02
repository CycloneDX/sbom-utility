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
	"github.com/CycloneDX/sbom-utility/utils"
)

// Test "resource list" command
const (
	// test/cyclonedx/cdx-1-3-resource-list.json
	TEST_COMPONENT_LIST_CDX_1_3 = TEST_RESOURCE_LIST_CDX_1_3
	// test/cyclonedx/cdx-1-5-mature-example-1.json
	TEST_COMPONENT_LIST_CDX_1_5_MATURE = TEST_CDX_1_5_MATURE_EXAMPLE_1_BASE
	// test/cyclonedx/1.6/cdx-1-6-valid-cbom-full-1.6.json
	TEST_COMPONENT_LIST_CDX_1_6_CBOM = TEST_CDX_1_6_CRYPTO_BOM
	// test/cyclonedx/1.6/cdx-1-6-valid-mlbom-environmental-considerations.json
	TEST_COMPONENT_LIST_CDX_1_6_MLBOM = TEST_CDX_1_6_MACHINE_LEARNING_BOM
)

type ComponentTestInfo struct {
	CommonTestInfo
}

func (ti *ComponentTestInfo) String() string {
	buffer, _ := utils.EncodeAnyToDefaultIndentedJSONStr(ti)
	return buffer.String()
}

func NewComponentTestInfo(inputFile string, outputFormat string, listSummary bool, whereClause string,
	resultExpectedLineCount int) *ComponentTestInfo {

	var ti = new(ComponentTestInfo)
	var pCommon = &ti.CommonTestInfo
	// initialize common fields
	pCommon.Init(inputFile, outputFormat, listSummary, whereClause,
		nil, resultExpectedLineCount, nil)
	return ti
}

func NewComponentTestInfoBasic(inputFile string, listFormat string, resultExpectedError error) *ComponentTestInfo {
	var ti = new(ComponentTestInfo)
	var pCommon = &ti.CommonTestInfo
	pCommon.InitBasic(inputFile, listFormat, resultExpectedError)
	return ti
}

// -------------------------------------------
// resource list test helper functions
// -------------------------------------------
func innerBufferedTestComponentList(testInfo *ComponentTestInfo, whereFilters []common.WhereFilter) (outputBuffer bytes.Buffer, err error) {
	// Declare an output outputBuffer/outputWriter to use used during tests
	var outputWriter = bufio.NewWriter(&outputBuffer)
	// ensure all data is written to buffer before further validation
	defer outputWriter.Flush()

	var persistentFlags utils.PersistentCommandFlags
	persistentFlags.OutputFormat = testInfo.OutputFormat

	err = ListComponents(outputWriter, persistentFlags, whereFilters)
	return
}

func innerTestComponentList(t *testing.T, testInfo *ComponentTestInfo) (outputBuffer bytes.Buffer, basicTestInfo string, err error) {
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
	outputBuffer, err = innerBufferedTestComponentList(testInfo, whereFilters)

	// Run all common tests against "result" values in the CommonTestInfo struct
	err = innerRunReportResultTests(t, &testInfo.CommonTestInfo, outputBuffer, err)

	return
}

// -------------------------------------------
// Test format unsupported (SPDX)
// -------------------------------------------
func TestComponentListFormatUnsupportedSPDXMinReq(t *testing.T) {
	ti := NewComponentTestInfoBasic(
		TEST_INPUT_FILE_NON_EXISTENT,
		FORMAT_DEFAULT,
		&fs.PathError{},
	)
	// verify correct error is returned
	innerTestComponentList(t, ti)
}

// -------------------------------------------
// Format variants
// -------------------------------------------

func TestComponentListCdx13Text(t *testing.T) {
	ti := NewComponentTestInfoBasic(TEST_RESOURCE_LIST_CDX_1_3, FORMAT_TEXT, nil)
	ti.ResultExpectedLineCount = 14 // title + separator + 11 data + EOF LF
	ti.ResultLineContainsValuesAtLineNum = 6
	ti.ResultLineContainsValues = []string{"Library G"}
	innerTestComponentList(t, ti)
}

func TestComponentListCdx13Csv(t *testing.T) {
	ti := NewComponentTestInfoBasic(TEST_RESOURCE_LIST_CDX_1_3, FORMAT_CSV, nil)
	ti.ResultExpectedLineCount = 13 // title + 11 data + EOF LF
	ti.ResultLineContainsValuesAtLineNum = 5
	ti.ResultLineContainsValues = []string{"Library G"}
	innerTestComponentList(t, ti)
}

func TestComponentListCdx13Markdown(t *testing.T) {
	ti := NewComponentTestInfoBasic(TEST_RESOURCE_LIST_CDX_1_3, FORMAT_MARKDOWN, nil)
	ti.ResultExpectedLineCount = 14 // title + separator + 11 data + EOF LF
	ti.ResultLineContainsValuesAtLineNum = 6
	ti.ResultLineContainsValues = []string{"Library G"}
	innerTestComponentList(t, ti)
}

// -------------------------------------------
// CDX variants
// -------------------------------------------

func TestComponentListCdx15MatureCsv(t *testing.T) {
	ti := NewComponentTestInfoBasic(TEST_COMPONENT_LIST_CDX_1_5_MATURE, FORMAT_CSV, nil)
	//ti.ListSummary = false
	//ti.WhereClause = "version=2.0"
	ti.ResultExpectedLineCount = 5 // title + 3 data + EOF LF
	ti.ResultLineContainsValuesAtLineNum = 3
	ti.ResultLineContainsValues = []string{"sample"}
	innerTestComponentList(t, ti)
}

func TestComponentListCdx16CryptoBOM(t *testing.T) {
	ti := NewComponentTestInfoBasic(TEST_COMPONENT_LIST_CDX_1_6_CBOM, FORMAT_CSV, nil)
	ti.ResultExpectedLineCount = 6 // title + 4 data + EOF LF
	ti.ResultLineContainsValuesAtLineNum = 2
	ti.ResultLineContainsValues = []string{"asset-2"}
	innerTestComponentList(t, ti)
}

func TestComponentListCdx16MachineLearningBOM(t *testing.T) {
	ti := NewComponentTestInfoBasic(TEST_COMPONENT_LIST_CDX_1_6_MLBOM, FORMAT_CSV, nil)
	ti.ResultExpectedLineCount = 3 // title + 1 data + EOF LF
	ti.ResultLineContainsValuesAtLineNum = 1
	ti.ResultLineContainsValues = []string{"Llama-2-7b"}
	innerTestComponentList(t, ti)
}
