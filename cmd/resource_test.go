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
func innerTestResourceList(t *testing.T, inputFile string, format string) (outputBuffer bytes.Buffer, err error) {

	// Declare an output outputBuffer/outputWriter to use used during tests
	var outputWriter = bufio.NewWriter(&outputBuffer)
	// ensure all data is written to buffer before further validation
	defer outputWriter.Flush()

	// Use a test input SBOM formatted in SPDX
	utils.GlobalFlags.InputFile = inputFile
	err = ListResources(outputWriter, format, RESOURCE_TYPE_DEFAULT, nil)

	return
}

// ----------------------------------------
// Command flag tests
// ----------------------------------------

func TestResourceListInvalidInputFileLoad(t *testing.T) {
	_, err := innerTestResourceList(t,
		TEST_INPUT_FILE_NON_EXISTENT,
		OUTPUT_DEFAULT)

	// Assure we return path error
	if err == nil || !ErrorTypesMatch(err, &fs.PathError{}) {
		t.Errorf("expected error: %T, actual error: %T", &fs.PathError{}, err)
	}
}

// -------------------------------------------
// Test format unsupported (SPDX)
// -------------------------------------------
func TestResourceListFormatUnsupportedSPDX1(t *testing.T) {

	_, err := innerTestResourceList(t,
		TEST_SPDX_2_2_MIN_REQUIRED,
		OUTPUT_DEFAULT)

	if !ErrorTypesMatch(err, &schema.UnsupportedFormatError{}) {
		getLogger().Error(err)
		t.Errorf("expected error type: `%T`, actual type: `%T`", &schema.UnsupportedFormatError{}, err)
	}
}

func TestResourceListFormatUnsupportedSPDX2(t *testing.T) {

	_, err := innerTestResourceList(t,
		TEST_SPDX_2_2_EXAMPLE_1,
		OUTPUT_DEFAULT)

	if !ErrorTypesMatch(err, &schema.UnsupportedFormatError{}) {
		getLogger().Error(err)
		t.Errorf("expected error type: `%T`, actual type: `%T`", &schema.UnsupportedFormatError{}, err)
	}
}

// -------------------------------------------
// CDX variants - Test for list (data) errors
// -------------------------------------------

func TestResourceListTextCdx14NoneFound(t *testing.T) {
	outputBuffer, err := innerTestResourceList(t,
		TEST_RESOURCE_LIST_CDX_1_3_NONE_FOUND,
		OUTPUT_TEXT)

	if err != nil {
		t.Errorf("%s: input file: %s", err.Error(), utils.GlobalFlags.InputFile)
	}

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
func TestResourceListTextCdx13Licenses(t *testing.T) {
	_, err := innerTestResourceList(t,
		TEST_RESOURCE_LIST_CDX_1_3,
		OUTPUT_TEXT)

	if err != nil {
		getLogger().Error(err)
		t.Errorf("%s: input file: %s", err.Error(), utils.GlobalFlags.InputFile)
	}
}

func TestResourceListTextCdx14SaaS(t *testing.T) {
	_, err := innerTestResourceList(t,
		TEST_RESOURCE_LIST_CDX_1_4_SAAS_1,
		OUTPUT_TEXT)

	if err != nil {
		getLogger().Error(err)
		t.Errorf("%s: input file: %s", err.Error(), utils.GlobalFlags.InputFile)
	}
}

// -------------------------------------------
// CDX variants - List only
// -------------------------------------------

// func TestResourceListJSONCdx14NoneFound(t *testing.T) {
// 	outputBuffer, err := innerTestResourceList(t,
// 		TEST_RESOURCE_LIST_CDX_1_4_NONE_FOUND,
// 		OUTPUT_JSON)
//
// 	if err != nil {
// 		getLogger().Error(err)
// 		t.Errorf("%s: input file: %s", err.Error(), utils.GlobalFlags.InputFile)
// 	}
//
// 	// Note: if no resources are found, the "json.Marshal" method(s) will return a value of "null"
// 	// which is valid JSON (and not an empty array)
// 	if !utils.IsValidJsonRaw(outputBuffer.Bytes()) {
// 		t.Errorf("ListResources(): did not produce valid JSON output")
// 		t.Logf("%s", outputBuffer.String())
// 	}
// }

// func TestResourceListCSVCdxNoneFound(t *testing.T) {
// 	// Test CDX 1.3 document
// 	outputBuffer, err := innerTestResourceList(t,
// 		TEST_RESOURCE_LIST_CDX_1_3_NONE_FOUND,
// 		OUTPUT_CSV)

// 	if err != nil {
// 		t.Errorf("%s: input file: %s", err.Error(), utils.GlobalFlags.InputFile)
// 	}

// 	s := outputBuffer.String()
// 	if !strings.Contains(s, MSG_OUTPUT_NO_RESOURCES_FOUND) {
// 		t.Errorf("ListResources(): did not include the message: `%s`", MSG_OUTPUT_NO_RESOURCES_FOUND)
// 		t.Logf("%s", outputBuffer.String())
// 	}

// 	// Test CDX 1.4 document
// 	outputBuffer, err = innerTestResourceList(t,
// 		TEST_RESOURCE_LIST_CDX_1_4_NONE_FOUND,
// 		OUTPUT_CSV)

// 	if err != nil {
// 		t.Errorf("%s: input file: %s", err.Error(), utils.GlobalFlags.InputFile)
// 	}

// 	s = outputBuffer.String()
// 	if !strings.Contains(s, MSG_OUTPUT_NO_RESOURCES_FOUND) {
// 		t.Errorf("ListResources(): did not include the message: `%s`", MSG_OUTPUT_NO_RESOURCES_FOUND)
// 		t.Logf("%s", outputBuffer.String())
// 	}
// }

//func TestResourceListTextCdx14NoneFound(t *testing.T) {
// outputBuffer, err := innerTestResourceList(t,
// 	TEST_RESOURCE_LIST_CDX_1_4_NONE_FOUND,
// 	OUTPUT_JSON,
// 	true)
//
// if err != nil {
// 	t.Errorf("%s: input file: %s", err.Error(), utils.GlobalFlags.InputFile)
// }
//
// TODO
// verify there is a (warning) message present when no resources are found
// s := outputBuffer.String()
// if !strings.Contains(s, MSG_OUTPUT_NO_LICENSES_FOUND) {
// 	t.Errorf("ListResources(): did not include the message: `%s`", MSG_OUTPUT_NO_LICENSES_FOUND)
// 	t.Logf("%s", outputBuffer.String())
// }
//}
