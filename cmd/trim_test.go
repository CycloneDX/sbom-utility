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
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/CycloneDX/sbom-utility/common"
	"github.com/CycloneDX/sbom-utility/utils"
)

const (
	// Trim test BOM files
	TEST_TRIM_CDX_1_4_ENCODED_CHARS           = "test/trim/trim-cdx-1-4-sample-encoded-chars.sbom.json"
	TEST_TRIM_CDX_1_4_SAMPLE_XXL_1            = "test/trim/trim-cdx-1-4-sample-xxl-1.sbom.json"
	TEST_TRIM_CDX_1_5_SAMPLE_SMALL_COMPS_ONLY = "test/trim/trim-cdx-1-5-sample-small-components-only.sbom.json"
	TEST_TRIM_CDX_1_5_SAMPLE_MEDIUM_1         = "test/trim/trim-cdx-1-5-sample-medium-1.sbom.json"
)

type TrimTestInfo struct {
	CommonTestInfo
	Keys      []string
	FromPaths []string
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

func VerifyTrimOutputFileResult(t *testing.T, ti *TrimTestInfo, keys []string, fromPath string) (err error) {
	// Query temporary "trimmed" BOM to assure known fields were removed
	request, err := common.NewQueryRequestSelectFromWhere(
		common.QUERY_TOKEN_WILDCARD,
		fromPath,
		"")
	if err != nil {
		t.Errorf("%s: %v", ERR_TYPE_UNEXPECTED_ERROR, err)
		return
	}

	for _, key := range keys {

		// use a buffered query on the temp. output file on the (parent) path
		var pResult interface{}
		pResult, err = innerQuery(t, ti.OutputFile, request, true)
		if err != nil {
			t.Errorf("%s: %v", ERR_TYPE_UNEXPECTED_ERROR, err)
			return
		}

		// short-circuit if the "from" path dereferenced to a non-existent key
		if pResult == nil {
			t.Errorf("empty (nil) found at from clause: %s", fromPath)
			return
		}

		// verify the "key" was removed from the (parent) JSON map
		err = VerifyTrimmed(pResult, key)
	}

	return
}

func VerifyTrimmed(pResult interface{}, key string) (err error) {
	// verify the "key" was removed from the (parent) JSON map
	if pResult != nil {
		switch typedValue := pResult.(type) {
		case map[string]interface{}:
			// verify map key was removed
			if _, ok := typedValue[key]; ok {
				formattedValue, _ := utils.MarshalAnyToFormattedJsonString(typedValue)
				err = getLogger().Errorf("trim failed. Key `%s`, found in: `%s`", key, formattedValue)
				return
			}
		case []interface{}:
			if len(typedValue) == 0 {
				err = getLogger().Errorf("empty slice found at from clause.")
				return
			}
			// Verify all elements of slice
			for _, value := range typedValue {
				err = VerifyTrimmed(value, key)
				return err
			}
		default:
			err = getLogger().Errorf("trim failed. Unexpected JSON type: `%T`", typedValue)
			return
		}
	}
	return
}

// ----------------------------------------
// Trim with encoded chars
// ----------------------------------------

// NOTE: The JSON Marshal(), by default, encodes chars (assumes JSON docs are being transmitted over HTML streams)
// which is not true for BOM documents as stream (wire) transmission encodings
// are specified for both formats.  We need to assure any commands that
// rewrite BOMs (after edits) preserve original characters.
func TestTrimCdx14PreserveUnencodedChars(t *testing.T) {
	ti := NewTrimTestInfoBasic(TEST_TRIM_CDX_1_4_ENCODED_CHARS, nil)
	ti.OutputFile = ti.CreateTemporaryFilename(TEST_TRIM_CDX_1_4_ENCODED_CHARS)
	ti.Keys = append(ti.Keys, "name")
	outputBuffer, _ := innerBufferedTestTrim(t, ti)
	TEST1 := "<guillem@debian.org>"
	TEST2 := "<adduser@packages.debian.org>"

	outputString := outputBuffer.String()

	if strings.Contains(outputString, TEST1) {
		t.Errorf("removed expected utf8 characters from string: `%s`", TEST1)
	}

	if strings.Contains(outputString, TEST2) {
		t.Errorf("removed expected utf8 characters from string: `%s`", TEST2)
	}
}

// ----------------------------------------
// Trim "keys" globally (entire BOM)
// ----------------------------------------
func TestTrimCdx14ComponentPropertiesSampleXXLBuffered(t *testing.T) {
	ti := NewTrimTestInfoBasic(TEST_TRIM_CDX_1_4_SAMPLE_XXL_1, nil)
	ti.Keys = append(ti.Keys, "properties")
	outputBuffer, _ := innerBufferedTestTrim(t, ti)
	// TODO: verify "after" trim lengths and content have removed properties
	getLogger().Tracef("Len(outputBuffer): `%v`\n", outputBuffer.Len())
}

// TODO: enable for when we have a "from" parameter to limit trim scope
func TestTrimCdx14ComponentPropertiesSampleXXL(t *testing.T) {
	ti := NewTrimTestInfoBasic(TEST_TRIM_CDX_1_4_SAMPLE_XXL_1, nil)
	ti.Keys = append(ti.Keys, "properties")
	ti.OutputFile = ti.CreateTemporaryFilename(TEST_TRIM_CDX_1_4_SAMPLE_XXL_1)
	innerTestTrim(t, ti)
	// Assure JSON map does not contain the trimmed key(s)
	err := VerifyTrimOutputFileResult(t, ti, ti.Keys, "metadata.component")
	if err != nil {
		t.Error(err)
	}
}

func TestTrimCdx15MultipleKeys(t *testing.T) {
	ti := NewTrimTestInfoBasic(TEST_TRIM_CDX_1_5_SAMPLE_SMALL_COMPS_ONLY, nil)
	ti.Keys = append(ti.Keys, "properties", "hashes", "version", "description", "name")
	ti.OutputFile = ti.CreateTemporaryFilename(TEST_TRIM_CDX_1_5_SAMPLE_SMALL_COMPS_ONLY)
	innerTestTrim(t, ti)
	// Assure JSON map does not contain the trimmed key(s)
	err := VerifyTrimOutputFileResult(t, ti, []string{"hashes"}, "")
	if err != nil {
		t.Error(err)
	}
	err = VerifyTrimOutputFileResult(t, ti, []string{"version"}, "")
	if err != nil {
		t.Error(err)
	}
}

func TestTrimCdx15Properties(t *testing.T) {
	ti := NewTrimTestInfoBasic(TEST_TRIM_CDX_1_5_SAMPLE_MEDIUM_1, nil)
	ti.Keys = append(ti.Keys, "properties")
	ti.OutputFile = ti.CreateTemporaryFilename(TEST_TRIM_CDX_1_5_SAMPLE_MEDIUM_1)
	innerTestTrim(t, ti)
	// Assure JSON map does not contain the trimmed key(s)
	// Document "root" properties
	err := VerifyTrimOutputFileResult(t, ti, ti.Keys, "") // document root
	if err != nil {
		t.Error(err)
	}
	// metadata properties
	err = VerifyTrimOutputFileResult(t, ti, ti.Keys, "metadata") // document root
	if err != nil {
		t.Error(err)
	}
	// metadata.component properties
	err = VerifyTrimOutputFileResult(t, ti, ti.Keys, "metadata.component") // document root
	if err != nil {
		t.Error(err)
	}
}

// ----------------------------------------
// Trim "keys" only under specified "paths"
// ----------------------------------------

func TestTrimCdx15PropertiesFromMetadataComponent(t *testing.T) {
	ti := NewTrimTestInfoBasic(TEST_TRIM_CDX_1_5_SAMPLE_MEDIUM_1, nil)
	ti.Keys = append(ti.Keys, "properties")
	ti.FromPaths = []string{"metadata.component"}
	ti.TestOutputVariantName = utils.GetCallerFunctionName(2)
	ti.OutputFile = ti.CreateTemporaryFilename(TEST_TRIM_CDX_1_5_SAMPLE_MEDIUM_1)
	innerTestTrim(t, ti)
	// Assure JSON map does not contain the trimmed key(s)
	err := VerifyTrimOutputFileResult(t, ti, ti.Keys, "metadata.component") // document root
	if err != nil {
		t.Error(err)
	}
}

func TestTrimCdx15HashesFromTools(t *testing.T) {
	ti := NewTrimTestInfoBasic(TEST_TRIM_CDX_1_5_SAMPLE_MEDIUM_1, nil)
	ti.Keys = append(ti.Keys, "hashes")
	ti.FromPaths = []string{"metadata.tools"}
	ti.TestOutputVariantName = utils.GetCallerFunctionName(2)
	ti.OutputFile = ti.CreateTemporaryFilename(TEST_TRIM_CDX_1_5_SAMPLE_MEDIUM_1)
	innerTestTrim(t, ti)
	// Assure JSON map does not contain the trimmed key(s)
	err := VerifyTrimOutputFileResult(t, ti, ti.Keys, "metadata.tools") // document root
	if err != nil {
		t.Error(err)
	}
}

func TestTrimCdx15AllIncrementallyFromSmallSample(t *testing.T) {
	ti := NewTrimTestInfoBasic(TEST_TRIM_CDX_1_5_SAMPLE_SMALL_COMPS_ONLY, nil)
	ti.Keys = append(ti.Keys, "type", "purl", "bom-ref", "serialNumber", "components", "name", "description", "properties")
	ti.FromPaths = []string{""}
	ti.TestOutputVariantName = utils.GetCallerFunctionName(2)
	ti.OutputFile = ti.CreateTemporaryFilename(TEST_TRIM_CDX_1_5_SAMPLE_SMALL_COMPS_ONLY)
	_, _, err := innerTestTrim(t, ti)
	if err != nil {
		t.Error(err)
	}
	// Assure JSON map does not contain the trimmed key(s)
	err = VerifyTrimOutputFileResult(t, ti, ti.Keys, "") // document root
	if err != nil {
		t.Error(err)
	}
}

func TestTrimCdx15FooFromTools(t *testing.T) {
	ti := NewTrimTestInfoBasic(TEST_TRIM_CDX_1_5_SAMPLE_MEDIUM_1, nil)
	ti.Keys = append(ti.Keys, "foo")
	ti.FromPaths = []string{"metadata.tools"}
	ti.TestOutputVariantName = utils.GetCallerFunctionName(2)
	ti.OutputFile = "" // ti.CreateTemporaryFilename(TEST_TRIM_CDX_1_5_SAMPLE_MEDIUM_1)
	ti.TestOutputExpectedByteSize = 5351

	buffer, _, err := innerTestTrim(t, ti)
	if err != nil {
		t.Error(err)
	}

	// Validate expected output file size in bytes (assumes 4 space indent)
	if actualSize := buffer.Len(); actualSize != ti.TestOutputExpectedByteSize {
		t.Error(fmt.Errorf("invalid trim result (output size (byte)): expected size: %v, actual size: %v", ti.TestOutputExpectedByteSize, actualSize))
	}

	// validate test-specific strings still exist
	TEST_STRING_1 := "\"name\": \"urn:example.com:identifier:product\""
	contains := bufferContainsValues(buffer, TEST_STRING_1)
	if !contains {
		t.Error(fmt.Errorf("invalid trim result: string not found: %s", TEST_STRING_1))
	}
}
