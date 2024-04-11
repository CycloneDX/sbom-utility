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
	"io"
	"log"
	"os"
	"testing"

	"github.com/CycloneDX/sbom-utility/utils"
)

const (
	TEST_CDX_1_5_SORT_COMPONENTS_XXL           = "test/sort/cdx-1-4-components-xxl.json"
	TEST_CDX_1_5_SORT_LICENSES                 = "test/sort/cdx-1-5-licenses.json"
	TEST_CDX_1_5_SORT_DEPENDENCIES             = "test/sort/cdx-1-5-dependencies.json"
	TEST_CDX_1_5_SORT_EXTERNAL_REFERENCES      = "test/sort/cdx-1-5-external-references.json"
	TEST_CDX_1_5_SORT_VULNERABILITIES          = "test/sort/cdx-1-5-vulnerabilities.json"
	TEST_CDX_1_5_SORT_VULNERABILITIES_NATS_BOX = "test/sort/cdx-1-5-vulnerabilities-container-nats-box.bom.json"
	TEST_CDX_1_2_SORT_COMPONENTS_PROTON        = "test/sort/cdx-1-2-components-protonmail.bom.json"
)

type SortTestInfo struct {
	CommonTestInfo
	Keys      []string
	FromPaths []string
	Sort      bool
}

func (ti *SortTestInfo) String() string {
	buffer, _ := utils.EncodeAnyToDefaultIndentedJSONStr(ti)
	return buffer.String()
}

func NewSortTestInfo(inputFile string, resultExpectedError error) *SortTestInfo {
	var ti = new(SortTestInfo)
	var pCommon = &ti.CommonTestInfo
	pCommon.InitBasic(inputFile, FORMAT_JSON, resultExpectedError)
	return ti
}

func innerTestSort(t *testing.T, testInfo *SortTestInfo) (outputBuffer bytes.Buffer, basicTestInfo string, err error) {
	getLogger().Tracef("TestInfo: %s", testInfo)

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
	outputBuffer, err = innerBufferedTestSort(testInfo)
	// if the command resulted in a failure
	if err != nil {
		// if tests asks us to report a FAIL to the test framework
		cti := &testInfo.CommonTestInfo
		if cti.Autofail {
			encodedTestInfo, _ := utils.EncodeAnyToDefaultIndentedJSONStr(testInfo)
			t.Errorf("%s: failed: %v\n%s", cti.InputFile, err, encodedTestInfo.String())
		}
		return
	}

	return
}

func innerBufferedTestSort(testInfo *SortTestInfo) (outputBuffer bytes.Buffer, err error) {

	// The command looks for the input & output filename in global flags struct
	utils.GlobalFlags.PersistentFlags.InputFile = testInfo.InputFile
	utils.GlobalFlags.PersistentFlags.OutputFile = testInfo.OutputFile
	utils.GlobalFlags.PersistentFlags.OutputFormat = testInfo.OutputFormat
	utils.GlobalFlags.PersistentFlags.OutputIndent = testInfo.OutputIndent
	utils.GlobalFlags.PersistentFlags.Sort = testInfo.Sort // TODO: default true
	utils.GlobalFlags.TrimFlags.Keys = testInfo.Keys
	utils.GlobalFlags.TrimFlags.FromPaths = testInfo.FromPaths
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

	err = Trim(outputWriter, utils.GlobalFlags.PersistentFlags, utils.GlobalFlags.TrimFlags)
	return
}

func TestSortCdx15ComponentsXXL(t *testing.T) {
	ti := NewSortTestInfo(TEST_CDX_1_5_SORT_COMPONENTS_XXL, nil)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_CDX_1_5_SORT_COMPONENTS_XXL)
	ti.Sort = true // TODO: default true
	innerTestSort(t, ti)
}

func TestSortCdx15Dependencies(t *testing.T) {
	ti := NewSortTestInfo(TEST_CDX_1_5_SORT_DEPENDENCIES, nil)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_CDX_1_5_SORT_DEPENDENCIES)
	ti.Sort = true // TODO: default true
	innerTestSort(t, ti)
}

func TestSortCdx15ExternalReferences(t *testing.T) {
	ti := NewSortTestInfo(TEST_CDX_1_5_SORT_EXTERNAL_REFERENCES, nil)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_CDX_1_5_SORT_EXTERNAL_REFERENCES)
	ti.Sort = true // TODO: default true
	innerTestSort(t, ti)
}

func TestSortCdx15Vulnerabilities(t *testing.T) {
	ti := NewSortTestInfo(TEST_CDX_1_5_SORT_VULNERABILITIES, nil)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_CDX_1_5_SORT_VULNERABILITIES)
	ti.Sort = true // TODO: default true
	innerTestSort(t, ti)
}

func TestSortCdx15Licenses(t *testing.T) {
	ti := NewSortTestInfo(TEST_CDX_1_5_SORT_LICENSES, nil)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_CDX_1_5_SORT_LICENSES)
	ti.Sort = true // TODO: default true
	innerTestSort(t, ti)
}
