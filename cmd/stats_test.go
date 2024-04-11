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

	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/CycloneDX/sbom-utility/utils"
)

const (
	// Test "resource list" command
	TEST_STATS_CDX_1_4_SAMPLE_XXL_1 = "test/stats/stats-cdx-1-4-sample-xxl-1.json"
)

type StatsTestInfo struct {
	CommonTestInfo
}

func (ti *StatsTestInfo) String() string {
	buffer, _ := utils.EncodeAnyToDefaultIndentedJSONStr(ti)
	return buffer.String()
}

func NewStatsTestInfoBasic(inputFile string, listFormat string, resultExpectedError error) *StatsTestInfo {
	var ti = new(StatsTestInfo)
	var pCommon = &ti.CommonTestInfo
	pCommon.InitBasic(inputFile, listFormat, resultExpectedError)
	return ti
}

// -------------------------------------------
// resource list test helper functions
// -------------------------------------------
func innerBufferedTestStatsList(testInfo *StatsTestInfo) (outputBuffer bytes.Buffer, err error) {
	// Declare an output outputBuffer/outputWriter to use used during tests
	var outputWriter = bufio.NewWriter(&outputBuffer)
	// ensure all data is written to buffer before further validation
	defer outputWriter.Flush()

	var persistentFlags utils.PersistentCommandFlags
	persistentFlags.OutputFormat = testInfo.OutputFormat
	var statsFlags utils.StatsCommandFlags

	err = ListStats(outputWriter, persistentFlags, statsFlags)
	return
}

func innerTestStatsList(t *testing.T, testInfo *StatsTestInfo) (outputBuffer bytes.Buffer, basicTestInfo string, err error) {
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
	outputBuffer, err = innerBufferedTestStatsList(testInfo)

	return
}

// ----------------------------------------
// Command flag tests
// ----------------------------------------

// TBD

// -------------------------------------------
// Test format unsupported (SPDX)
// -------------------------------------------
func TestStatsListFormatUnsupportedSPDXMinReq(t *testing.T) {
	ti := NewStatsTestInfoBasic(
		TEST_SPDX_2_2_MIN_REQUIRED,
		FORMAT_DEFAULT,
		&schema.UnsupportedFormatError{},
	)

	// verify correct error is returned
	innerTestStatsList(t, ti)
}

// -------------------------------------------
// Data tests
// -------------------------------------------
func TestStatsCdx14SampleXXL1(t *testing.T) {
	ti := NewStatsTestInfoBasic(
		TEST_STATS_CDX_1_4_SAMPLE_XXL_1,
		FORMAT_DEFAULT,
		&fs.PathError{},
	)

	// verify correct error is returned
	innerTestStatsList(t, ti)
}
