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
	"reflect"
	"strings"
	"testing"

	"github.com/CycloneDX/sbom-utility/common"
	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/CycloneDX/sbom-utility/utils"
)

const (
	// "base" JSON files for patching from IETF RFC 6902 Appendix A
	TEST_PATCH_RFC_6902_APPX_A_1_BASE  = "test/patch/rfc6902/rfc6902-appendix-a-1-base.json"
	TEST_PATCH_RFC_6902_APPX_A_2_BASE  = "test/patch/rfc6902/rfc6902-appendix-a-2-base.json"
	TEST_PATCH_RFC_6902_APPX_A_3_BASE  = "test/patch/rfc6902/rfc6902-appendix-a-3-base.json"
	TEST_PATCH_RFC_6902_APPX_A_4_BASE  = "test/patch/rfc6902/rfc6902-appendix-a-4-base.json"
	TEST_PATCH_RFC_6902_APPX_A_5_BASE  = "test/patch/rfc6902/rfc6902-appendix-a-5-base.json"
	TEST_PATCH_RFC_6902_APPX_A_6_BASE  = "test/patch/rfc6902/rfc6902-appendix-a-6-base.json"
	TEST_PATCH_RFC_6902_APPX_A_7_BASE  = "test/patch/rfc6902/rfc6902-appendix-a-7-base.json"
	TEST_PATCH_RFC_6902_APPX_A_8_BASE  = "test/patch/rfc6902/rfc6902-appendix-a-8-base.json"
	TEST_PATCH_RFC_6902_APPX_A_9_BASE  = "test/patch/rfc6902/rfc6902-appendix-a-9-base.json"
	TEST_PATCH_RFC_6902_APPX_A_10_BASE = "test/patch/rfc6902/rfc6902-appendix-a-10-base.json"
	TEST_PATCH_RFC_6902_APPX_A_16_BASE = "test/patch/rfc6902/rfc6902-appendix-a-16-base.json"

	// "base" BOM files for patching
	TEST_PATCH_BOM_1_5_SLICE_BASE  = "test/patch/cdx-1-5-slice-base.json"
	TEST_PATCH_BOM_1_5_SIMPLE_BASE = "test/patch/cdx-1-5-simple-base.json"
	TEST_PATCH_BOM_1_5_MATURE_BASE = "test/patch/cdx-1-5-mature-base.json"
)

const (
	// RFC 6901 "patch" files
	TEST_PATCH_RFC_6902_APPX_A_1_PATCH_ADD_OBJ_1      = "test/patch/rfc6902/rfc6902-appendix-a-1-patch-add-obj-1.json"
	TEST_PATCH_RFC_6902_APPX_A_1_PATCH_ADD_INT        = "test/patch/rfc6902/rfc6902-appendix-a-1-patch-add-integer.json"
	TEST_PATCH_RFC_6902_APPX_A_1_PATCH_ADD_BOOL       = "test/patch/rfc6902/rfc6902-appendix-a-1-patch-add-bool.json"
	TEST_PATCH_RFC_6902_APPX_A_2_PATCH_ADD_ARRAY_1    = "test/patch/rfc6902/rfc6902-appendix-a-2-patch-add-array-1.json"
	TEST_PATCH_RFC_6902_APPX_A_2_PATCH_ADD_ARRAY_2    = "test/patch/rfc6902/rfc6902-appendix-a-2-patch-add-array-2.json"
	TEST_PATCH_RFC_6902_APPX_A_2_PATCH_ADD_ARRAY_3    = "test/patch/rfc6902/rfc6902-appendix-a-2-patch-add-array-3.json"
	TEST_PATCH_RFC_6902_APPX_A_2_PATCH_ADD_ARRAY_4    = "test/patch/rfc6902/rfc6902-appendix-a-2-patch-add-array-4.json"
	TEST_PATCH_RFC_6902_APPX_A_3_PATCH_REMOVE_OBJ_1   = "test/patch/rfc6902/rfc6902-appendix-a-3-patch-remove-obj-1.json"
	TEST_PATCH_RFC_6902_APPX_A_4_PATCH_REMOVE_ARRAY_1 = "test/patch/rfc6902/rfc6902-appendix-a-4-patch-remove-array-1.json"
	TEST_PATCH_RFC_6902_APPX_A_10_PATCH_ADD_NESTED_1  = "test/patch/rfc6902/rfc6902-appendix-a-10-patch-add-nested-1.json"
	TEST_PATCH_RFC_6902_APPX_A_16_PATCH_ADD_ARRAY_1   = "test/patch/rfc6902/rfc6902-appendix-a-16-patch-add-array-1.json"

	// NOTE: Currently unsupported patch operations (i.e., should return consistent error)
	TEST_PATCH_RFC_6902_APPX_A_6_PATCH_1 = "test/patch/rfc6902/rfc6902-appendix-a-6-patch-1.json"
	TEST_PATCH_RFC_6902_APPX_A_7_PATCH_1 = "test/patch/rfc6902/rfc6902-appendix-a-7-patch-1.json"
	TEST_PATCH_RFC_6902_APPX_A_8_PATCH_1 = "test/patch/rfc6902/rfc6902-appendix-a-8-patch-1.json"
	TEST_PATCH_RFC_6902_APPX_A_9_PATCH_1 = "test/patch/rfc6902/rfc6902-appendix-a-9-patch-1.json"

	// CycloneDX BOM "patch" files
	TEST_PATCH_BOM_ADD_SLICE_1 = "test/patch/cdx-patch-add-slice-1.json"
	//TEST_PATCH_METADATA_PROPERTIES_1 = "test/patch/cdx-patch-metadata-properties-1.json"
	TEST_PATCH_BOM_ADD_METADATA_PROPS_MIXED      = "test/patch/cdx-patch-add-metadata-properties-mixed.json"
	TEST_PATCH_BOM_ADD_METADATA_PROP_AT_END      = "test/patch/cdx-patch-add-metadata-property-at-end.json"
	TEST_PATCH_BOM_ADD_METADATA_PROP_AT_INDEX    = "test/patch/cdx-patch-add-metadata-property-at-index.json"
	TEST_PATCH_BOM_ADD_ROOT_UPDATE_VERSION       = "test/patch/cdx-patch-add-root-update-version.json"
	TEST_PATCH_BOM_ADD_ROOT_INVALID_KEY_MODIFIED = "test/patch/cdx-patch-add-root-invalid-key-modified.json"

	// CycloneDX BOM "patch" files (error tests)
	TEST_PATCH_ERR_ADD_MISSING_VALUE = "test/patch/cdx-patch-add-err-missing-value.json"
	TEST_PATCH_ERR_OP_PATH_EMPTY     = "test/patch/cdx-patch-op-err-empty-path.json"
)

type PatchTestInfo struct {
	CommonTestInfo
	PatchFile   string
	IsInputJSON bool
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

	// If this is a base JSON patch test
	if testInfo.IsInputJSON == true {
		// NOTE: we use the BOM "document" structure, but only use the JSON Map portion
		document := schema.NewBOM(utils.GlobalFlags.PersistentFlags.InputFile)
		document.UnmarshalBOMAsJSONMap()
		if err = innerPatch(document); err != nil {
			return
		}
		// store patch records for output verification
		indentString := utils.GenerateIndentString(int(testInfo.OutputIndent))
		outputBuffer, err = utils.EncodeAnyToIndentedJSONStr(document.JsonMap, indentString)
	} else {
		// else this is a BOM input test
		err = Patch(outputWriter, utils.GlobalFlags.PersistentFlags, utils.GlobalFlags.PatchFlags)
	}

	return
}

func retrieveQueryPathFromPatchRecord(recordPath string) (queryPath string, key string, err error) {
	var paths []string
	paths, err = parseMapKeysFromPath(recordPath)
	if err != nil {
		return
	}

	lenPaths := len(paths)
	// if record's path is not root, separate it from the last path segment
	// (which is the map key or slice index)
	if lenPaths > 1 {
		queryPath = strings.Join(paths[0:lenPaths-1], ".")
		key = paths[lenPaths-1]
	} else {
		queryPath = paths[0]
		// NOTE: default root (i.e., "")
	}
	return
}

func VerifyPatchedOutputFileResult(t *testing.T, originalTest PatchTestInfo) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	patchDocument := NewIETFRFC6902PatchDocument(originalTest.PatchFile)
	if err = patchDocument.UnmarshalRecords(); err != nil {
		return
	}

	// If no patch records were found after unmarshal
	if patchDocument.Records == nil {
		return
	}

	// Create a new test info. structure copying in data from the original test
	queryTestInfo := NewCommonTestInfo()
	queryTestInfo.InputFile = originalTest.OutputFile

	// Load and Query temporary "patched" output BOM file using the "from" path
	// Default to "root" (i.e,, "") path if none selected.
	DEFAULT_PATH_DOC_ROOT := ""
	request, err := common.NewQueryRequestSelectFromWhere(
		common.QUERY_TOKEN_WILDCARD, DEFAULT_PATH_DOC_ROOT, "")
	if err != nil {
		t.Errorf("%s: %v", ERR_TYPE_UNEXPECTED_ERROR, err)
		return
	}
	getLogger().Tracef("request: %s\n", request.String())

	// Verify each key was removed
	var pResult interface{}
	for _, record := range patchDocument.Records {
		var queryPath, key string
		queryPath, key, err = retrieveQueryPathFromPatchRecord(record.Path)
		//fmt.Printf("queryPath: %s, key: %s\n", queryPath, key)
		if err != nil {
			t.Errorf("%s: %v", "unable to parse patch record path.", err)
			return
		}
		request.SetRawFromPaths(queryPath)

		// use a buffered query on the temp. output file on the (parent) path
		pResult, _, err = innerQuery(t, queryTestInfo, request)

		// NOTE: Query typically does NOT support non JSON map or slice
		// we need to allow float64, bool and string for "patch" validation
		if err != nil && !ErrorTypesMatch(err, &common.QueryResultInvalidTypeError{}) {
			t.Errorf("%s: %v", ERR_TYPE_UNEXPECTED_ERROR, err)
			return
		}

		// short-circuit if the "from" path dereferenced to a non-existent key
		if pResult == nil {
			t.Errorf("empty (nil) found at from clause: %s", request.String())
			return
		}

		// verify the "key" was removed from the (parent) JSON map
		err = VerifyPatched(record, pResult, key)
		if err != nil {
			return
		}
	}

	return
}

func VerifyPatched(record IETF6902Record, pResult interface{}, key string) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// verify the "key" was removed from the (parent) JSON map
	if pResult != nil {
		switch typedResult := pResult.(type) {
		case map[string]interface{}:
			// NOTE: this is for "Add" operation only
			if record.Operation == IETF_RFC6902_OP_ADD {
				if _, ok := typedResult[key]; !ok {
					formattedResult, _ := utils.EncodeAnyToDefaultIndentedJSONStr(typedResult)
					err = getLogger().Errorf("patch failed. Key `%s`, found in: `%s`", key, formattedResult.String())
					return
				}
			}
		case []interface{}:
			// NOTE: this is for "Add" operation only
			if record.Operation == IETF_RFC6902_OP_ADD {
				if len(typedResult) == 0 {
					err = getLogger().Errorf("verify failed. Record slice value is empty.")
					return
				}

				if record.Value == nil {
					err = getLogger().Errorf("verify failed. Document slice value is nil.")
					return
				}
				var contains bool
				contains, err = sliceContainsValue(typedResult, record.Value)
				if !contains {
					err = getLogger().Errorf("verify failed. Document value (%v) does not contain expected value (%v).", typedResult, record.Value)
					return
				}
			}
		case bool:
			if record.Value != typedResult {
				err = getLogger().Errorf("verify failed. Document value (%v) does not contain expected value (%v).", typedResult, record.Value)
				return
			}
			return
		case float64: // NOTE: encoding/json turns int64 to float64
			if record.Value != typedResult {
				err = getLogger().Errorf("verify failed. Document value (%v) does not contain expected value (%v).", typedResult, record.Value)
				return
			}
			return
		default:
			err = getLogger().Errorf("verify failed. Unexpected JSON type: `%T`", typedResult)
			return
		}
	} else {
		// TODO: return typed error
		getLogger().Trace("nil results")
	}
	return
}

func sliceContainsValue(slice []interface{}, value interface{}) (contains bool, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Debug trace
	// buffer, _ := utils.EncodeAnyToDefaultIndentedJSONStr(value)
	// fmt.Printf("sliceContainsValue(): value (%T): %s\n", value, buffer.String())
	// buffer, _ = utils.EncodeAnyToDefaultIndentedJSONStr(slice)
	// fmt.Printf("sliceContainsValue(): slice: %s\n", buffer.String())

	switch typedValue := value.(type) {
	case map[string]interface{}:
		var tempValue map[string]interface{}
		var ok bool
		for _, entry := range slice {
			if tempValue, ok = entry.(map[string]interface{}); !ok {
				err = fmt.Errorf("type mismatch error. Slice values: %v (%T), value: %v (%T)", entry, entry, tempValue, tempValue)
				return
			}
			if reflect.DeepEqual(tempValue, typedValue) {
				contains = true
				return
			}
		}
		return
	case []interface{}:
		var tempValue []interface{}
		for _, entry := range slice {
			if tempValue, ok := entry.([]interface{}); !ok {
				err = fmt.Errorf("type mismatch error. Slice values: %v (%T), value: %v (%T)", entry, entry, tempValue, tempValue)
				return
			}
			if reflect.DeepEqual(tempValue, typedValue) {
				contains = true
				return
			}
		}
	case string: // TODO
		// NOTE: "slices.Contains()" does not work on []interface{}
		return
	case bool: // TODO
		return
	case float64: // TODO
		return
	default:
		getLogger().Errorf("contains test failed. Unexpected JSON type: `%T`", typedValue)
	}
	return
}

// ----------------
// Error tests
// ----------------
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

// -------------------------------------
// RFC6902 Unsupported operation tests
// -------------------------------------
func TestPatchRFC6902AppendixA6Patch1(t *testing.T) {
	ti := NewPatchTestInfo(
		TEST_PATCH_RFC_6902_APPX_A_6_BASE,
		TEST_PATCH_RFC_6902_APPX_A_6_PATCH_1, nil)
	ti.IsInputJSON = true
	_, _, err := innerTestPatch(t, ti)
	if !ErrorTypesMatch(err, &UnsupportedError{}) {
		t.Error(err)
	}
}

func TestPatchRFC6902AppendixA7Patch1(t *testing.T) {
	ti := NewPatchTestInfo(
		TEST_PATCH_RFC_6902_APPX_A_7_BASE,
		TEST_PATCH_RFC_6902_APPX_A_7_PATCH_1, nil)
	ti.IsInputJSON = true
	_, _, err := innerTestPatch(t, ti)
	if !ErrorTypesMatch(err, &UnsupportedError{}) {
		t.Error(err)
	}
}

func TestPatchRFC6902AppendixA8Patch1(t *testing.T) {
	ti := NewPatchTestInfo(
		TEST_PATCH_RFC_6902_APPX_A_8_BASE,
		TEST_PATCH_RFC_6902_APPX_A_8_PATCH_1, nil)
	ti.IsInputJSON = true
	_, _, err := innerTestPatch(t, ti)
	if !ErrorTypesMatch(err, &UnsupportedError{}) {
		t.Error(err)
	}
}

func TestPatchRFC6902AppendixA9Patch1(t *testing.T) {
	ti := NewPatchTestInfo(
		TEST_PATCH_RFC_6902_APPX_A_9_BASE,
		TEST_PATCH_RFC_6902_APPX_A_9_PATCH_1, nil)
	ti.IsInputJSON = true
	_, _, err := innerTestPatch(t, ti)
	if !ErrorTypesMatch(err, &UnsupportedError{}) {
		t.Error(err)
	}
}

// ----------------
// RFC6902 Tests
// ----------------

func TestPatchRFC6902AppendixA1Patch1(t *testing.T) {
	ti := NewPatchTestInfo(
		TEST_PATCH_RFC_6902_APPX_A_1_BASE,
		TEST_PATCH_RFC_6902_APPX_A_1_PATCH_ADD_OBJ_1, nil)
	ti.IsInputJSON = true
	ti.OutputIndent = 0
	buffer, _, err := innerTestPatch(t, ti)
	if err != nil {
		t.Error(err)
	}
	getLogger().Tracef("%s\n", buffer.String())
	TEST_RESULT := "{\"baz\":\"qux\",\"foo\":\"bar\"}\n"
	if buffer.String() != TEST_RESULT {
		t.Errorf("invalid patch result. Expected:\n`%s`,\nActual:\n`%s`", TEST_RESULT, buffer.String())
	}
}

func TestPatchRFC6902AppendixA1BaseAddInteger(t *testing.T) {
	ti := NewPatchTestInfo(
		TEST_PATCH_RFC_6902_APPX_A_1_BASE,
		TEST_PATCH_RFC_6902_APPX_A_1_PATCH_ADD_INT, nil)
	ti.IsInputJSON = true
	ti.OutputIndent = 0
	buffer, _, err := innerTestPatch(t, ti)
	if err != nil {
		t.Error(err)
	}
	getLogger().Tracef("%s\n", buffer.String())
	TEST_RESULT := "{\"foo\":\"bar\",\"size\":100}\n"
	if buffer.String() != TEST_RESULT {
		t.Errorf("invalid patch result. Expected:\n`%s`,\nActual:\n`%s`", TEST_RESULT, buffer.String())
	}
}

func TestPatchRFC6902AppendixA1BaseAddBool(t *testing.T) {
	ti := NewPatchTestInfo(
		TEST_PATCH_RFC_6902_APPX_A_1_BASE,
		TEST_PATCH_RFC_6902_APPX_A_1_PATCH_ADD_BOOL, nil)
	ti.IsInputJSON = true
	ti.OutputIndent = 0
	buffer, _, err := innerTestPatch(t, ti)
	if err != nil {
		t.Error(err)
	}
	getLogger().Tracef("%s\n", buffer.String())
	TEST_RESULT := "{\"foo\":\"bar\",\"modified\":true}\n"
	if buffer.String() != TEST_RESULT {
		t.Errorf("invalid patch result. Expected:\n`%s`,\nActual:\n`%s`", TEST_RESULT, buffer.String())
	}
}

func TestPatchRFC6902AppendixA2Patch1(t *testing.T) {
	ti := NewPatchTestInfo(
		TEST_PATCH_RFC_6902_APPX_A_2_BASE,
		TEST_PATCH_RFC_6902_APPX_A_2_PATCH_ADD_ARRAY_1, nil)
	ti.IsInputJSON = true
	ti.OutputIndent = 0
	buffer, _, err := innerTestPatch(t, ti)
	if err != nil {
		t.Error(err)
	}
	getLogger().Tracef("%s\n", buffer.String())
	TEST_RESULT := "{\"foo\":[\"bar\",\"qux\",\"baz\"]}\n"
	if buffer.String() != TEST_RESULT {
		t.Errorf("invalid patch result. Expected:\n`%s`,\nActual:\n`%s`", TEST_RESULT, buffer.String())
	}
}

func TestPatchRFC6902AppendixA2Patch2(t *testing.T) {
	ti := NewPatchTestInfo(
		TEST_PATCH_RFC_6902_APPX_A_2_BASE,
		TEST_PATCH_RFC_6902_APPX_A_2_PATCH_ADD_ARRAY_2, nil)
	ti.IsInputJSON = true
	ti.OutputIndent = 0
	buffer, _, err := innerTestPatch(t, ti)
	if err != nil {
		t.Error(err)
	}
	getLogger().Tracef("%s\n", buffer.String())
	TEST_RESULT := "{\"foo\":[\"bar\",\"baz\",\"qux\"]}\n"
	if buffer.String() != TEST_RESULT {
		t.Errorf("invalid patch result. Expected:\n`%s`,\nActual:\n`%s`", TEST_RESULT, buffer.String())
	}
}

func TestPatchRFC6902AppendixA2Patch3(t *testing.T) {
	ti := NewPatchTestInfo(
		TEST_PATCH_RFC_6902_APPX_A_2_BASE,
		TEST_PATCH_RFC_6902_APPX_A_2_PATCH_ADD_ARRAY_3, nil)
	ti.IsInputJSON = true
	ti.OutputIndent = 0
	buffer, _, err := innerTestPatch(t, ti)
	if err != nil {
		t.Error(err)
	}
	getLogger().Tracef("%s\n", buffer.String())
	TEST_RESULT := "{\"foo\":[\"bar\",\"baz\",\"qux\"]}\n"
	if buffer.String() != TEST_RESULT {
		t.Errorf("invalid patch result. Expected:\n`%s`,\nActual:\n`%s`", TEST_RESULT, buffer.String())
	}
}

func TestPatchRFC6902AppendixA2Patch4(t *testing.T) {
	ti := NewPatchTestInfo(
		TEST_PATCH_RFC_6902_APPX_A_2_BASE,
		TEST_PATCH_RFC_6902_APPX_A_2_PATCH_ADD_ARRAY_4, nil)
	ti.IsInputJSON = true
	ti.OutputIndent = 0
	buffer, _, err := innerTestPatch(t, ti)
	if err != nil {
		t.Error(err)
	}
	getLogger().Tracef("%s\n", buffer.String())
	TEST_RESULT := "{\"foo\":[\"bar\",\"baz\",\"qux\"]}\n"
	if buffer.String() != TEST_RESULT {
		t.Errorf("invalid patch result. Expected:\n`%s`,\nActual:\n`%s`", TEST_RESULT, buffer.String())
	}
}

func TestPatchRFC6902AppendixA10Patch1(t *testing.T) {
	ti := NewPatchTestInfo(
		TEST_PATCH_RFC_6902_APPX_A_10_BASE,
		TEST_PATCH_RFC_6902_APPX_A_10_PATCH_ADD_NESTED_1, nil)
	ti.OutputIndent = 0
	ti.IsInputJSON = true
	buffer, _, err := innerTestPatch(t, ti)
	if err != nil {
		t.Error(err)
	}
	getLogger().Tracef("%s\n", buffer.String())
	TEST_RESULT := "{\"child\":{\"grandchild\":{}},\"foo\":\"bar\"}\n"
	if buffer.String() != TEST_RESULT {
		t.Errorf("invalid patch result. Expected:\n`%s`,\nActual:\n`%s`", TEST_RESULT, buffer.String())
	}
}

func TestPatchRFC6902AppendixA16Patch1(t *testing.T) {
	ti := NewPatchTestInfo(
		TEST_PATCH_RFC_6902_APPX_A_16_BASE,
		TEST_PATCH_RFC_6902_APPX_A_16_PATCH_ADD_ARRAY_1, nil)
	ti.OutputIndent = 0
	ti.IsInputJSON = true
	buffer, _, err := innerTestPatch(t, ti)
	if err != nil {
		t.Error(err)
	}
	getLogger().Tracef("%s\n", buffer.String())
	TEST_RESULT := "{\"foo\":[\"bar\",[\"abc\",\"def\"]]}\n"
	if buffer.String() != TEST_RESULT {
		t.Errorf("invalid patch result. Expected:\n`%s`,\nActual:\n`%s`", TEST_RESULT, buffer.String())
	}
}

// ----------------
// CycloneDX Tests
// ----------------

func TestPatchCdx15InvalidAddRootModified(t *testing.T) {
	ti := NewPatchTestInfo(TEST_PATCH_BOM_1_5_SIMPLE_BASE, TEST_PATCH_BOM_ADD_METADATA_PROPS_MIXED, nil)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_PATCH_BOM_1_5_SIMPLE_BASE)
	buffer, _, err := innerTestPatch(t, ti)
	if err != nil {
		t.Error(err)
	}
	// NOTE: patch record: { "op": "add", "path": "/modified", "value": true }
	// will NOT be written to the output BOM as "modified" is not a CycloneDX key
	getLogger().Tracef("%s\n", buffer.String())
}

func TestPatchCdx15AddPropertiesAtEnd(t *testing.T) {
	ti := NewPatchTestInfo(TEST_PATCH_BOM_1_5_SIMPLE_BASE, TEST_PATCH_BOM_ADD_METADATA_PROP_AT_END, nil)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_PATCH_BOM_1_5_SIMPLE_BASE)
	buffer, _, err := innerTestPatch(t, ti)
	if err != nil {
		t.Error(err)
	}
	getLogger().Tracef("%s\n", buffer.String())
	// verify JSON document has applied all patch records
	err = VerifyPatchedOutputFileResult(t, *ti)
	if err != nil {
		t.Error(err)
	}
}

func TestPatchCdx15AddPropertiesAtIndex(t *testing.T) {
	ti := NewPatchTestInfo(TEST_PATCH_BOM_1_5_SIMPLE_BASE, TEST_PATCH_BOM_ADD_METADATA_PROP_AT_INDEX, nil)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_PATCH_BOM_1_5_SIMPLE_BASE)
	buffer, _, err := innerTestPatch(t, ti)
	if err != nil {
		t.Error(err)
	}
	getLogger().Tracef("%s\n", buffer.String())
	// verify JSON document has applied all patch records
	err = VerifyPatchedOutputFileResult(t, *ti)
	if err != nil {
		t.Error(err)
	}
}

func TestPatchCdx15AddPropertiesMixed(t *testing.T) {
	ti := NewPatchTestInfo(TEST_PATCH_BOM_1_5_SIMPLE_BASE, TEST_PATCH_BOM_ADD_METADATA_PROPS_MIXED, nil)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_PATCH_BOM_1_5_SIMPLE_BASE)
	buffer, _, err := innerTestPatch(t, ti)
	if err != nil {
		t.Error(err)
	}
	getLogger().Tracef("%s\n", buffer.String())
	// verify JSON document has applied all patch records
	err = VerifyPatchedOutputFileResult(t, *ti)
	if err != nil {
		t.Error(err)
	}
}

func TestPatchCdx15SliceAdd(t *testing.T) {
	ti := NewPatchTestInfo(TEST_PATCH_BOM_1_5_SLICE_BASE, TEST_PATCH_BOM_ADD_SLICE_1, nil)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_PATCH_BOM_1_5_SLICE_BASE)
	buffer, _, err := innerTestPatch(t, ti)
	if err != nil {
		t.Error(err)
	}
	getLogger().Tracef("%s\n", buffer.String())
	// TODO: verify results
}

// Note: the encoding/json package turns all integers (i.e., int64) to float64
func TestPatchCdx15SliceAddUpdateVersionInteger(t *testing.T) {
	ti := NewPatchTestInfo(TEST_PATCH_BOM_1_5_SLICE_BASE, TEST_PATCH_BOM_ADD_ROOT_UPDATE_VERSION, nil)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_PATCH_BOM_1_5_SLICE_BASE)
	buffer, _, err := innerTestPatch(t, ti)
	if err != nil {
		t.Error(err)
	}
	getLogger().Tracef("%s\n", buffer.String())
	// verify JSON document has applied all patch records
	err = VerifyPatchedOutputFileResult(t, *ti)
	if err != nil {
		t.Error(err)
	}
}
