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
	"log"
	"os"
	"testing"

	"github.com/CycloneDX/sbom-utility/utils"
)

const (
	// Test "resource list" command
	TEST_TRIM_CDX_1_5_COMP_PROPS_1   = "test/stats/trim-cdx-1-5-comp-props-1.json"
	TEST_TRIM_CDX_1_4_LARGE_SAMPLE_1 = "test/stats/sample-1.sbom.json"
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
	// Declare an output outputBuffer/outputWriter to use used during tests
	var outputWriter = bufio.NewWriter(&outputBuffer)
	// ensure all data is written to buffer before further validation
	defer outputWriter.Flush()

	var persistentFlags utils.PersistentCommandFlags
	persistentFlags.OutputFormat = testInfo.OutputFormat
	var trimFlags utils.TrimCommandFlags

	err = Trim(outputWriter, persistentFlags, trimFlags)
	return
}

func innerTestTrim(t *testing.T, testInfo *TrimTestInfo) (outputBuffer bytes.Buffer, basicTestInfo string, err error) {
	getLogger().Tracef("TestInfo: %s", testInfo)

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
	outputBuffer, err = innerBufferedTestTrim(t, testInfo)

	return
}

func TestTrimExample1(t *testing.T) {
	ti := NewTrimTestInfoBasic(TEST_TRIM_CDX_1_5_COMP_PROPS_1, nil)
	innerTestTrim(t, ti)
}

func TestTrimLargeSample1(t *testing.T) {
	ti := NewTrimTestInfoBasic(TEST_TRIM_CDX_1_4_LARGE_SAMPLE_1, nil)
	innerTestTrim(t, ti)
}
