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
	// "base" JSON files for patching from IETF RFC 6902 Appendix A
	TEST_PATCH_RFC_6902_APPX_A_1_BASE = "test/patch/rfc6902/rfc6902-appendix-a-1-base.json"
	TEST_PATCH_RFC_6902_APPX_A_2_BASE = "test/patch/rfc6902/rfc6902-appendix-a-2-base.json"
	TEST_PATCH_RFC_6902_APPX_A_3_BASE = "test/patch/rfc6902/rfc6902-appendix-a-3-base.json"

	// "base" BOM files for patching
	TEST_PATCH_BOM_1_5_SLICE_BASE  = "test/patch/cdx-1-5-slice-base.json"
	TEST_PATCH_BOM_1_5_SIMPLE_BASE = "test/patch/cdx-1-5-simple-base.json"
	TEST_PATCH_BOM_1_5_MATURE_BASE = "test/patch/cdx-1-5-mature-base.json"
)

const (
	// RFC 6901 "patch" files
	TEST_PATCH_RFC_6902_APPX_A_1_PATCH_1 = "test/patch/rfc6902/rfc6902-appendix-a-1-patch-1.json"
	TEST_PATCH_RFC_6902_APPX_A_2_PATCH_1 = "test/patch/rfc6902/rfc6902-appendix-a-2-patch-1.json"
	TEST_PATCH_RFC_6902_APPX_A_2_PATCH_2 = "test/patch/rfc6902/rfc6902-appendix-a-2-patch-2.json"
	TEST_PATCH_RFC_6902_APPX_A_2_PATCH_3 = "test/patch/rfc6902/rfc6902-appendix-a-2-patch-3.json"
	TEST_PATCH_RFC_6902_APPX_A_2_PATCH_4 = "test/patch/rfc6902/rfc6902-appendix-a-2-patch-4.json"
	TEST_PATCH_RFC_6902_APPX_A_3_PATCH_1 = "test/patch/rfc6902/rfc6902-appendix-a-3-patch-1.json"

	// CycloneDX BOM "patch" files
	TEST_PATCH_BOM_ADD_SLICE_1       = "test/patch/cdx-patch-add-slice-1.json"
	TEST_PATCH_METADATA_PROPERTIES_1 = "test/patch/cdx-patch-metadata-properties-1.json"

	// CycloneDX BOM "patch" files (error tests)
	TEST_PATCH_ERR_ADD_MISSING_VALUE = "test/patch/cdx-patch-add-err-missing-value.json"
	TEST_PATCH_ERR_OP_PATH_EMPTY     = "test/patch/cdx-patch-op-err-empty-path.json"
)

type PatchTestInfo struct {
	CommonTestInfo
	PatchFile string
}

func (ti *PatchTestInfo) String() string {
	buffer, _ := utils.EncodeAnyToDefaultIndentedJSONStr(ti)
	return buffer.String()
}

func NewPatchTestInfo(inputFile string, patchFile string, resultExpectedError error) *PatchTestInfo {
	var ti = new(PatchTestInfo)
	var pCommon = &ti.CommonTestInfo
	pCommon.InitBasic(inputFile, FORMAT_JSON, resultExpectedError)
	ti.PatchFile = patchFile
	return ti
}

// -------------------------------------------
// test helper functions
// -------------------------------------------

func innerTestPatch(t *testing.T, testInfo *PatchTestInfo) (outputBuffer bytes.Buffer, basicTestInfo string, err error) {
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
	outputBuffer, err = innerBufferedTestPatch(t, testInfo)
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

func innerBufferedTestPatch(t *testing.T, testInfo *PatchTestInfo) (outputBuffer bytes.Buffer, err error) {

	// The command looks for the input & output filename in global flags struct
	utils.GlobalFlags.PersistentFlags.InputFile = testInfo.InputFile
	utils.GlobalFlags.PersistentFlags.OutputFile = testInfo.OutputFile
	utils.GlobalFlags.PersistentFlags.OutputFormat = testInfo.OutputFormat
	utils.GlobalFlags.PersistentFlags.OutputIndent = testInfo.OutputIndent
	utils.GlobalFlags.PatchFlags.PatchFile = testInfo.PatchFile
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

	err = Patch(outputWriter, utils.GlobalFlags.PersistentFlags, utils.GlobalFlags.PatchFlags)
	return
}

func VerifyPatchedOutputFileResult(t *testing.T, originalTest PatchTestInfo) (err error) {

	// Create a new test info. structure copying in data from the original test
	queryTestInfo := NewCommonTestInfo()
	queryTestInfo.InputFile = originalTest.OutputFile

	// Load an Query output BOM file using the "patch" records
	// NOTE: Default to "root" (i.e,, "") path if none selected.

	// TODO: logic
	// request, err := common.NewQueryRequestSelectFromWhere(
	// 	common.QUERY_TOKEN_WILDCARD, fromPath, "")
	// if err != nil {
	// 	t.Errorf("%s: %v", ERR_TYPE_UNEXPECTED_ERROR, err)
	// 	return
	// }

	// Verify each patch record was applied
	// var pResult interface{}
	// for _, key := range originalTest.Keys {

	// 	// use a buffered query on the temp. output file on the (parent) path
	// 	pResult, _, err = innerQuery(t, queryTestInfo, request)
	// 	if err != nil {
	// 		t.Errorf("%s: %v", ERR_TYPE_UNEXPECTED_ERROR, err)
	// 		return
	// 	}

	// 	// short-circuit if the "from" path dereferenced to a non-existent key
	// 	if pResult == nil {
	// 		t.Errorf("empty (nil) found at from clause: %s", fromPath)
	// 		return
	// 	}

	// 	// verify the "key" was removed from the (parent) JSON map
	// 	err = VerifyTrimmed(pResult, key)
	// }

	return
}

func TestPatchAddErrorMissingValue(t *testing.T) {
	ti := NewPatchTestInfo(TEST_PATCH_BOM_1_5_MATURE_BASE, TEST_PATCH_ERR_ADD_MISSING_VALUE, nil)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_PATCH_BOM_1_5_MATURE_BASE)
	_, _, err := innerTestPatch(t, ti)
	// Expected an error
	if err == nil {
		t.Error(err)
	}
}

func TestPatchOpErrorPathEmpty(t *testing.T) {
	ti := NewPatchTestInfo(TEST_PATCH_BOM_1_5_MATURE_BASE, TEST_PATCH_ERR_OP_PATH_EMPTY, nil)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_PATCH_BOM_1_5_MATURE_BASE)
	_, _, err := innerTestPatch(t, ti)
	// Expected an error
	if err == nil {
		t.Error(err)
	}
}

func TestPatchCdx15(t *testing.T) {
	ti := NewPatchTestInfo(TEST_PATCH_BOM_1_5_SIMPLE_BASE, TEST_PATCH_METADATA_PROPERTIES_1, nil)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_PATCH_BOM_1_5_SIMPLE_BASE)
	buffer, _, err := innerTestPatch(t, ti)
	if err != nil {
		t.Error(err)
	}
	getLogger().Tracef("%s\n", buffer.String())
}

func TestPatchCdx15SliceAdd(t *testing.T) {
	ti := NewPatchTestInfo(TEST_PATCH_BOM_1_5_SLICE_BASE, TEST_PATCH_BOM_ADD_SLICE_1, nil)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_PATCH_BOM_1_5_SLICE_BASE)
	buffer, _, err := innerTestPatch(t, ti)
	if err != nil {
		t.Error(err)
	}
	getLogger().Tracef("%s\n", buffer.String())
}

// func TestPatchRFC6902AppendixA2(t *testing.T) {
// 	ti := NewPatchTestInfo(
// 		TEST_PATCH_RFC_6902_APPX_A_2_BASE,
// 		TEST_PATCH_RFC_6902_APPX_A_2_PATCH_1, nil)
// 	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_PATCH_RFC_6902_APPX_A_2_BASE)
// 	buffer, _, err := innerTestPatch(t, ti)
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	fmt.Printf("%s\n", buffer.String())
// }
