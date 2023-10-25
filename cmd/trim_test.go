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
	// Test "resource list" command
	TEST_TRIM_CDX_1_5_COMP_PROPS_1 = "test/trim/trim-cdx-1-5-comp-props-1.json"
	TEST_TRIM_CDX_1_4_SAMPLE_XXL_1 = "test/trim/trim-cdx-1-4-sample-xxl-1.sbom.json"
)

type TrimTestInfo struct {
	CommonTestInfo
}

func (ti *TrimTestInfo) String() string {
	pParent := &ti.CommonTestInfo
	return pParent.String()
}

func NewTrimTestInfoBasic(inputFile string, resultExpectedError error) *TrimTestInfo {
	var ti = new(TrimTestInfo)
	var pCommon = &ti.CommonTestInfo
	pCommon.InitBasic(inputFile, FORMAT_JSON, resultExpectedError)
	return ti
}

// -------------------------------------------
// resource list test helper functions
// -------------------------------------------
func innerBufferedTestTrim(t *testing.T, testInfo *TrimTestInfo) (outputBuffer bytes.Buffer, err error) {

	// The command looks for the input & output filename in global flags struct
	utils.GlobalFlags.PersistentFlags.InputFile = testInfo.InputFile
	utils.GlobalFlags.PersistentFlags.OutputFile = testInfo.OutputFile
	utils.GlobalFlags.PersistentFlags.OutputFormat = testInfo.OutputFormat
	var trimFlags utils.TrimCommandFlags
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
		outputFile, outputWriter, err = createOutputFile(TEST_OUTPUT_PATH + testInfo.OutputFile)
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

	err = Trim(outputWriter, utils.GlobalFlags.PersistentFlags, trimFlags)
	return
}

func innerTestTrim(t *testing.T, testInfo *TrimTestInfo) (outputBuffer bytes.Buffer, basicTestInfo string, err error) {
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
	outputBuffer, err = innerBufferedTestTrim(t, testInfo)

	return
}

func TestTrimCdx15ComponentProperties(t *testing.T) {
	ti := NewTrimTestInfoBasic(TEST_TRIM_CDX_1_5_COMP_PROPS_1, nil)
	outputBuffer, _ := innerBufferedTestTrim(t, ti)
	// TODO: verify "after" trim lengths and content have removed properties
	getLogger().Tracef("Len(outputBuffer): `%v`\n", outputBuffer.Len())
}

func TestTrimCdx14ComponentPropertiesSampleXXL(t *testing.T) {
	ti := NewTrimTestInfoBasic(TEST_TRIM_CDX_1_4_SAMPLE_XXL_1, nil)
	outputBuffer, _ := innerBufferedTestTrim(t, ti)
	// TODO: verify "after" trim lengths and content have removed properties
	getLogger().Tracef("Len(outputBuffer): `%v`\n", outputBuffer.Len())
}

func TestTrimCdx14ComponentPropertiesSampleXXL2(t *testing.T) {
	ti := NewTrimTestInfoBasic(TEST_TRIM_CDX_1_4_SAMPLE_XXL_1, nil)
	ti.OutputFile = "output.sbom.json"
	innerTestTrim(t, ti)
	// TODO: verify output file was written and trimmed props.
}
