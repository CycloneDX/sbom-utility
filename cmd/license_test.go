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
	// Test "license list" command
	TEST_LICENSE_LIST_CDX_1_3            = "test/cyclonedx/cdx-1-3-license-list.json"
	TEST_LICENSE_LIST_CDX_1_3_NONE_FOUND = "test/cyclonedx/cdx-1-3-license-list-empty.json"
	TEST_LICENSE_LIST_CDX_1_4_NONE_FOUND = TEST_CUSTOM_CDX_1_4_INVALID_LICENSES_NOT_FOUND

	TEST_LICENSE_LIST_TEXT_CDX_1_4_INVALID_LICENSE_ID   = "test/cyclonedx/cdx-1-4-license-policy-invalid-spdx-id.json"
	TEST_LICENSE_LIST_TEXT_CDX_1_4_INVALID_LICENSE_NAME = "test/cyclonedx/cdx-1-4-license-policy-invalid-license-name.json"
)

// -------------------------------------------
// license test helper functions
// -------------------------------------------
func innerTestLicenseList(t *testing.T, inputFile string, format string, summary bool) (outputBuffer bytes.Buffer, err error) {

	// Declare an output outputBuffer/outputWriter to use used during tests
	var outputWriter = bufio.NewWriter(&outputBuffer)
	// ensure all data is written to buffer before further validation
	defer outputWriter.Flush()

	// Use a test input SBOM formatted in SPDX
	utils.GlobalFlags.InputFile = inputFile
	err = ListLicenses(outputWriter, format, summary)

	return
}

func listOutputContainsLicense(buffer bytes.Buffer, policy string, licenseType string, licenseId string) bool {

	lines := strings.Split(buffer.String(), "\n")
	getLogger().Tracef("output: %s", lines)

	for _, line := range lines {
		if strings.Contains(line, policy) &&
			strings.Contains(line, licenseType) &&
			strings.Contains(line, licenseId) {
			getLogger().Debugf("matched: %s", line)
			return true
		}
	}
	return false
}

// ----------------------------------------
// Command flag tests
// ----------------------------------------

func TestLicenseListInvalidInputFileLoad(t *testing.T) {
	_, err := innerTestLicenseList(t,
		TEST_INPUT_FILE_NON_EXISTENT,
		OUTPUT_DEFAULT,
		false)

	// Assure we return path error
	if err == nil || !ErrorTypesMatch(err, &fs.PathError{}) {
		t.Errorf("expected error: %T, actual error: %T", &fs.PathError{}, err)
	}
}

// -------------------------------------------
// Test SPDX ID (validity)
// -------------------------------------------

func TestLicenseSpdxIdSimple(t *testing.T) {
	ID := "MIT"
	if !IsValidSpdxId(ID) {
		t.Errorf("IsValidSpdxId(`%s`) == `false`: Expected `true`.", ID)
	}
}

func TestLicenseSpdxIdComplex(t *testing.T) {
	ID := "AGPL-3.0-or-later"
	if !IsValidSpdxId(ID) {
		t.Errorf("IsValidSpdxId(`%s`) == `false`: Expected `true`.", ID)
	}
}

func TestLicenseSpdxIdFailEmptyString(t *testing.T) {
	ID := ""
	if IsValidSpdxId(ID) {
		t.Errorf("IsValidSpdxId(`%s`) == `true`: Expected `false`.", ID)
	}
}

func TestLicenseSpdxIdFailBadCharacter1(t *testing.T) {
	ID := "?"
	if IsValidSpdxId(ID) {
		t.Errorf("IsValidSpdxId(`%s`) == `true`: Expected `false`.", ID)
	}
}

func TestLicenseSpdxIdFailBadCharacter2(t *testing.T) {
	ID := "MIT+Apache-2.0"
	if IsValidSpdxId(ID) {
		t.Errorf("IsValidSpdxId(`%s`) == `true`: Expected `false`.", ID)
	}
}

func TestLicenseSpdxIdFailWhiteSpace(t *testing.T) {
	ID := "Apache 2.0"
	if IsValidSpdxId(ID) {
		t.Errorf("IsValidSpdxId(`%s`) == `true`: Expected `false`.", ID)
	}
}

// -------------------------------------------
// Test format unsupported (SPDX)
// -------------------------------------------
func TestLicenseListFormatUnsupportedSPDX1(t *testing.T) {

	_, err := innerTestLicenseList(t,
		TEST_SPDX_2_2_MIN_REQUIRED,
		OUTPUT_DEFAULT,
		false)

	if !ErrorTypesMatch(err, &schema.UnsupportedFormatError{}) {
		getLogger().Error(err)
		t.Errorf("expected error type: `%T`, actual type: `%T`", &schema.UnsupportedFormatError{}, err)
	}
}

func TestLicenseListFormatUnsupportedSPDX2(t *testing.T) {

	_, err := innerTestLicenseList(t,
		TEST_SPDX_2_2_EXAMPLE_1,
		OUTPUT_DEFAULT,
		false)

	if !ErrorTypesMatch(err, &schema.UnsupportedFormatError{}) {
		getLogger().Error(err)
		t.Errorf("expected error type: `%T`, actual type: `%T`", &schema.UnsupportedFormatError{}, err)
	}
}

// Verify "license list" command finds all licenses regardless of where they
// are declared in schema (e.g., metadata.component, components list, service list, etc.)
// Note: this includes licenses in ANY hierarchical nesting of components as well.
func TestLicenseListJSONCdx13(t *testing.T) {
	outputBuffer, err := innerTestLicenseList(t,
		TEST_LICENSE_LIST_CDX_1_3,
		OUTPUT_JSON,
		false)

	if err != nil {
		getLogger().Error(err)
		t.Errorf("%s: input file: %s", err.Error(), utils.GlobalFlags.InputFile)
	}

	// TODO Actually the marshalled bytes is an array of CDX LicenseChoice (struct)
	// with values matching what we expected
	if !utils.IsValidJsonRaw(outputBuffer.Bytes()) {
		t.Errorf("ListLicenses(): did not produce valid JSON output")
		t.Logf("%s", outputBuffer.String())
	}
}

// Assure listing (report) works with summary flag (i.e., format: "txt")
func TestLicenseListSummaryTextCdx13(t *testing.T) {
	_, err := innerTestLicenseList(t,
		TEST_LICENSE_LIST_CDX_1_3,
		OUTPUT_TEXT,
		true)

	if err != nil {
		t.Error(err)
	}
}

func TestLicenseListJSONCdx14NoneFound(t *testing.T) {
	outputBuffer, err := innerTestLicenseList(t,
		TEST_LICENSE_LIST_CDX_1_4_NONE_FOUND,
		OUTPUT_JSON,
		false)

	if err != nil {
		getLogger().Error(err)
		t.Errorf("%s: input file: %s", err.Error(), utils.GlobalFlags.InputFile)
	}

	// Note: if no license are found, the "json.Marshal" method(s) will return a value of "null"
	// which is valid JSON (and not an empty array)
	if !utils.IsValidJsonRaw(outputBuffer.Bytes()) {
		t.Errorf("ListLicenses(): did not produce valid JSON output")
		t.Logf("%s", outputBuffer.String())
	}
}

func TestLicenseListCSVCdxNoneFound(t *testing.T) {

	// Test CDX 1.3 document
	outputBuffer, err := innerTestLicenseList(t,
		TEST_LICENSE_LIST_CDX_1_3_NONE_FOUND,
		OUTPUT_CSV,
		false)

	if err != nil {
		t.Errorf("%s: input file: %s", err.Error(), utils.GlobalFlags.InputFile)
	}

	s := outputBuffer.String()
	if !strings.Contains(s, MSG_LICENSE_NO_LICENSES_FOUND) {
		t.Errorf("ListLicenses(): did not include the message: `%s`", MSG_LICENSE_NO_LICENSES_FOUND)
		t.Logf("%s", outputBuffer.String())
	}

	// Test CDX 1.4 document
	outputBuffer, err = innerTestLicenseList(t,
		TEST_LICENSE_LIST_CDX_1_4_NONE_FOUND,
		OUTPUT_CSV,
		false)

	if err != nil {
		t.Errorf("%s: input file: %s", err.Error(), utils.GlobalFlags.InputFile)
	}

	s = outputBuffer.String()
	if !strings.Contains(s, MSG_LICENSE_NO_LICENSES_FOUND) {
		t.Errorf("ListLicenses(): did not include the message: `%s`", MSG_LICENSE_NO_LICENSES_FOUND)
		t.Logf("%s", outputBuffer.String())
	}
}

func TestLicenseListTextSummaryCdx14NoneFound(t *testing.T) {
	outputBuffer, err := innerTestLicenseList(t,
		TEST_LICENSE_LIST_CDX_1_4_NONE_FOUND,
		OUTPUT_JSON,
		true)

	if err != nil {
		t.Errorf("%s: input file: %s", err.Error(), utils.GlobalFlags.InputFile)
	}

	// verify there is a (warning) message present when no licenses are found
	s := outputBuffer.String()
	if !strings.Contains(s, MSG_LICENSE_NO_LICENSES_FOUND) {
		t.Errorf("ListLicenses(): did not include the message: `%s`", MSG_LICENSE_NO_LICENSES_FOUND)
		t.Logf("%s", outputBuffer.String())
	}
}

func TestLicenseListPolicyCdx14InvalidLicenseId(t *testing.T) {
	TEST_POLICY := POLICY_UNDEFINED
	TEST_LICENSE_TYPE := "id"
	TEST_LICENSE_ID_OR_NAME := "foo"

	output, err := innerTestLicenseList(t,
		TEST_LICENSE_LIST_TEXT_CDX_1_4_INVALID_LICENSE_ID,
		OUTPUT_TEXT,
		true)

	if err != nil {
		t.Error(err)
	}

	matched := listOutputContainsLicense(output, TEST_POLICY, TEST_LICENSE_TYPE, TEST_LICENSE_ID_OR_NAME)
	if !matched {
		t.Errorf("ListLicenses(): did not include license policy `%s`, type `%s`, name `%s`\n",
			TEST_POLICY, TEST_LICENSE_TYPE, TEST_LICENSE_ID_OR_NAME)
	}
}

func TestLicenseListPolicyCdx14InvalidLicenseName(t *testing.T) {
	TEST_POLICY := POLICY_UNDEFINED
	TEST_LICENSE_TYPE := "name"
	TEST_LICENSE_ID_OR_NAME := "bar"

	output, err := innerTestLicenseList(t,
		TEST_LICENSE_LIST_TEXT_CDX_1_4_INVALID_LICENSE_NAME,
		OUTPUT_TEXT,
		true)

	if err != nil {
		t.Error(err)
	}

	matched := listOutputContainsLicense(output, TEST_POLICY, TEST_LICENSE_TYPE, TEST_LICENSE_ID_OR_NAME)
	if !matched {
		t.Errorf("ListLicenses(): did not include license policy `%s`, type `%s`, name `%s`\n",
			TEST_POLICY, TEST_LICENSE_TYPE, TEST_LICENSE_ID_OR_NAME)
	}
}
