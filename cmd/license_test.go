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
	"io/fs"
	"strings"
	"testing"

	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/CycloneDX/sbom-utility/utils"
)

const (
	// Test "license list" command
	TEST_LICENSE_LIST_CDX_1_3            = "test/cyclonedx/cdx-1-3-license-list.json"
	TEST_LICENSE_LIST_CDX_1_3_NONE_FOUND = "test/cyclonedx/cdx-1-3-license-list-none-found.json"
	TEST_LICENSE_LIST_CDX_1_4_NONE_FOUND = "test/cyclonedx/cdx-1-4-license-list-none-found.json"

	TEST_LICENSE_LIST_TEXT_CDX_1_4_INVALID_LICENSE_ID   = "test/cyclonedx/cdx-1-4-license-policy-invalid-spdx-id.json"
	TEST_LICENSE_LIST_TEXT_CDX_1_4_INVALID_LICENSE_NAME = "test/cyclonedx/cdx-1-4-license-policy-invalid-license-name.json"

	// Test custom license policy (with license expression)
	TEST_CUSTOM_POLICY_1                           = "test/policy/license-policy-expression-outer-parens.policy.json"
	TEST_LICENSE_LIST_TEXT_CDX_1_4_CUSTOM_POLICY_1 = "test/policy/license-policy-expression-outer-parens.bom.json"
)

// default ResourceTestInfo struct values
const (
	LTI_DEFAULT_LINE_COUNT = -1
)

type LicenseTestInfo struct {
	PolicyFile              string // Note: if not filled in, uses default file: DEFAULT_LICENSE_POLICIES
	InputFile               string
	Format                  string
	WhereClause             string
	ExpectedError           error
	ResultContainsValues    []string
	ResultContainsValue     string
	ResultExpectedAtLineNum int
	ResultExpectedLineCount int
	ListSummary             bool
	ListLineWrap            bool
	ValidateJson            bool
}

// Stringer interface for ResourceTestInfo (just display subset of key values)
func (lti *LicenseTestInfo) String() string {
	return fmt.Sprintf("InputFile: `%s`, Format: `%s`, WhereClause: `%s`, Summary: `%v`",
		lti.InputFile, lti.Format, lti.WhereClause, lti.ListSummary)
}

func NewLicenseTestInfo(inputFile string, format string, whereClause string, summary bool, validateJson bool,
	resultContainsValue string, expectedLines int, expectedError error) *LicenseTestInfo {

	var lti = new(LicenseTestInfo)
	lti.InputFile = inputFile
	lti.Format = format
	lti.WhereClause = whereClause
	lti.ResultContainsValue = resultContainsValue
	lti.ResultExpectedLineCount = expectedLines
	lti.ExpectedError = expectedError
	lti.ListSummary = summary
	lti.ValidateJson = validateJson
	return lti
}

func NewLicenseTestInfoBasic(inputFile string, format string, summary bool) *LicenseTestInfo {
	return NewLicenseTestInfo(inputFile, format, "", summary, true, "", LTI_DEFAULT_LINE_COUNT, nil)
}

// -------------------------------------------
// license test helper functions
// -------------------------------------------

func innerTestLicenseListBuffered(t *testing.T, testInfo *LicenseTestInfo, whereFilters []WhereFilter) (outputBuffer bytes.Buffer, err error) {
	// Declare an output outputBuffer/outputWriter to use used during tests
	var outputWriter = bufio.NewWriter(&outputBuffer)
	// ensure all data is written to buffer before further validation
	defer outputWriter.Flush()

	// Use a test input SBOM formatted in SPDX
	utils.GlobalFlags.InputFile = testInfo.InputFile

	// Invoke the actual List command (API)
	err = ListLicenses(outputWriter, testInfo.Format, testInfo.ListSummary, whereFilters)

	return
}

func innerTestLicenseList(t *testing.T, testInfo *LicenseTestInfo) (outputBuffer bytes.Buffer, err error) {

	// Prepare WHERE filters from where clause
	var whereFilters []WhereFilter = nil
	if testInfo.WhereClause != "" {
		whereFilters, err = retrieveWhereFilters(testInfo.WhereClause)
		if err != nil {
			getLogger().Error(err)
			t.Errorf("test failed: %s: detail: %s ", testInfo, err.Error())
			return
		}
	}

	// Perform the test with buffered output
	outputBuffer, err = innerTestLicenseListBuffered(t, testInfo, whereFilters)

	// TEST: Expected error matches actual error
	if testInfo.ExpectedError != nil {
		// NOTE: err = nil will also fail if error was expected
		if !ErrorTypesMatch(err, testInfo.ExpectedError) {
			t.Errorf("expected error: %T, actual error: %T", testInfo.ExpectedError, err)
		}
		// Always return the expected error
		return
	}

	// Unexpected error: return immediately/do not test output/results
	if err != nil {
		t.Errorf("test failed: %s: detail: %s ", testInfo, err.Error())
		return
	}

	// TEST: Output contains string(s)
	// TODO: Support []string
	var outputResults string
	if testInfo.ResultContainsValue != "" {
		outputResults = outputBuffer.String()
		getLogger().Debugf("output: \"%s\"", outputResults)

		if !strings.Contains(outputResults, testInfo.ResultContainsValue) {
			err = getLogger().Errorf("output did not contain expected value: `%s`", testInfo.ResultContainsValue)
			t.Errorf("%s: input file: `%s`, where clause: `%s`",
				err.Error(),
				testInfo.InputFile,
				testInfo.WhereClause)
			return
		}
	}

	// TEST: Expected Line Count
	if testInfo.ResultExpectedLineCount != LTI_DEFAULT_LINE_COUNT {
		if outputResults == "" {
			outputResults = outputBuffer.String()
		}
		outputLineCount := strings.Count(outputResults, "\n")
		if outputLineCount != testInfo.ResultExpectedLineCount {
			err = getLogger().Errorf("output did not contain expected line count: %v/%v (expected/actual)", testInfo.ResultExpectedLineCount, outputLineCount)
			t.Errorf("%s: input file: `%s`, where clause: `%s`: \n%s",
				err.Error(),
				testInfo.InputFile,
				testInfo.WhereClause,
				outputResults,
			)
			return
		}
	}

	// TEST: valid JSON if format JSON
	// TODO the marshalled bytes is an array of CDX LicenseChoice (struct)
	// TODO: add general validation for CSV and Markdown formats
	if testInfo.ValidateJson {
		if testInfo.Format == FORMAT_JSON {
			// Use Marshal to test for validity
			if !utils.IsValidJsonRaw(outputBuffer.Bytes()) {
				t.Errorf("output did not contain valid JSON")
				t.Logf("%s", outputBuffer.String())
				return
			}
		}
	}

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
	lti := NewLicenseTestInfoBasic(TEST_INPUT_FILE_NON_EXISTENT, FORMAT_DEFAULT, false)
	lti.ExpectedError = &fs.PathError{}
	innerTestLicenseList(t, lti)
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
	lti := NewLicenseTestInfoBasic(TEST_SPDX_2_2_MIN_REQUIRED, FORMAT_DEFAULT, false)
	lti.ExpectedError = &schema.UnsupportedFormatError{}
	innerTestLicenseList(t, lti)
}

func TestLicenseListFormatUnsupportedSPDX2(t *testing.T) {
	lti := NewLicenseTestInfoBasic(TEST_SPDX_2_2_EXAMPLE_1, FORMAT_DEFAULT, false)
	lti.ExpectedError = &schema.UnsupportedFormatError{}
	innerTestLicenseList(t, lti)
}

//---------------------------
// Raw output tests
//---------------------------

// Verify "license list" command finds all licenses regardless of where they
// are declared in schema (e.g., metadata.component, components list, service list, etc.)
// Note: this includes licenses in ANY hierarchical nesting of components as well.
func TestLicenseListCdx13JsonNoneFound(t *testing.T) {
	// Test CDX 1.3 document
	lti := NewLicenseTestInfoBasic(TEST_LICENSE_LIST_CDX_1_3_NONE_FOUND, FORMAT_JSON, false)
	lti.ResultExpectedLineCount = 1 // null (valid json)
	innerTestLicenseList(t, lti)
}
func TestLicenseListCdx14JsonNoneFound(t *testing.T) {
	lti := NewLicenseTestInfoBasic(TEST_LICENSE_LIST_CDX_1_4_NONE_FOUND, FORMAT_JSON, false)
	lti.ResultExpectedLineCount = 1 // null (valid json)
	innerTestLicenseList(t, lti)
}

func TestLicenseListCdx13CsvNoneFound(t *testing.T) {
	// Test CDX 1.3 document
	lti := NewLicenseTestInfoBasic(TEST_LICENSE_LIST_CDX_1_3_NONE_FOUND, FORMAT_CSV, false)
	lti.ResultExpectedLineCount = 1 // title only
	innerTestLicenseList(t, lti)
}

func TestLicenseListCdx14CsvNoneFound(t *testing.T) {
	// Test CDX 1.4 document
	lti := NewLicenseTestInfoBasic(TEST_LICENSE_LIST_CDX_1_4_NONE_FOUND, FORMAT_CSV, false)
	lti.ResultExpectedLineCount = 1 // title only
	innerTestLicenseList(t, lti)
}

func TestLicenseListCdx13MarkdownNoneFound(t *testing.T) {
	// Test CDX 1.3 document
	lti := NewLicenseTestInfoBasic(TEST_LICENSE_LIST_CDX_1_3_NONE_FOUND, FORMAT_MARKDOWN, false)
	lti.ResultExpectedLineCount = 2 // title and separator rows
	innerTestLicenseList(t, lti)
}

func TestLicenseListCdx14MarkdownNoneFound(t *testing.T) {
	// Test CDX 1.4 document
	lti := NewLicenseTestInfoBasic(TEST_LICENSE_LIST_CDX_1_4_NONE_FOUND, FORMAT_MARKDOWN, false)
	lti.ResultExpectedLineCount = 2 // title and separator rows
	innerTestLicenseList(t, lti)
}

func TestLicenseListCdx13Json(t *testing.T) {
	lti := NewLicenseTestInfoBasic(TEST_LICENSE_LIST_CDX_1_3, FORMAT_JSON, false)
	lti.ResultExpectedLineCount = 210 // array of LicenseChoice JSON objects
	innerTestLicenseList(t, lti)
}

//---------------------------
// Summary flag tests
//---------------------------

// Assure listing (report) works with summary flag (i.e., format: "txt")
func TestLicenseListSummaryCdx13Text(t *testing.T) {
	lti := NewLicenseTestInfoBasic(TEST_LICENSE_LIST_CDX_1_3, FORMAT_TEXT, true)
	lti.ResultExpectedLineCount = 20 // title, separator and data rows
	innerTestLicenseList(t, lti)
}

func TestLicenseListSummaryCdx13Markdown(t *testing.T) {
	lti := NewLicenseTestInfoBasic(TEST_LICENSE_LIST_CDX_1_3, FORMAT_MARKDOWN, true)
	lti.ResultExpectedLineCount = 20 // title, separator and data rows
	innerTestLicenseList(t, lti)
}

func TestLicenseListSummaryCdx13Csv(t *testing.T) {
	lti := NewLicenseTestInfoBasic(TEST_LICENSE_LIST_CDX_1_3, FORMAT_CSV, true)
	lti.ResultExpectedLineCount = 19 // title and data rows
	innerTestLicenseList(t, lti)
}

func TestLicenseListTextSummaryCdx14ContainsUndefined(t *testing.T) {

	lti := NewLicenseTestInfoBasic(TEST_LICENSE_LIST_CDX_1_4_NONE_FOUND, FORMAT_DEFAULT, true)
	lti.ResultContainsValue = POLICY_UNDEFINED
	lti.ResultExpectedLineCount = 4 // 2 title, 2 with UNDEFINED
	innerTestLicenseList(t, lti)
}

func TestLicenseListPolicyCdx14InvalidLicenseId(t *testing.T) {
	TEST_POLICY := POLICY_UNDEFINED
	TEST_LICENSE_TYPE := "id"
	TEST_LICENSE_ID_OR_NAME := "foo"

	lti := NewLicenseTestInfoBasic(TEST_LICENSE_LIST_TEXT_CDX_1_4_INVALID_LICENSE_ID, FORMAT_TEXT, true)
	outputBuffer, _ := innerTestLicenseList(t, lti)

	matched := listOutputContainsLicense(outputBuffer, TEST_POLICY, TEST_LICENSE_TYPE, TEST_LICENSE_ID_OR_NAME)
	if !matched {
		t.Errorf("ListLicenses(): did not include license policy `%s`, type `%s`, name `%s`\n",
			TEST_POLICY, TEST_LICENSE_TYPE, TEST_LICENSE_ID_OR_NAME)
	}
}

func TestLicenseListPolicyCdx14InvalidLicenseName(t *testing.T) {
	TEST_POLICY := POLICY_UNDEFINED
	TEST_LICENSE_TYPE := "name"
	TEST_LICENSE_ID_OR_NAME := "bar"

	lti := NewLicenseTestInfoBasic(TEST_LICENSE_LIST_TEXT_CDX_1_4_INVALID_LICENSE_NAME, FORMAT_TEXT, true)
	outputBuffer, _ := innerTestLicenseList(t, lti)

	matched := listOutputContainsLicense(outputBuffer, TEST_POLICY, TEST_LICENSE_TYPE, TEST_LICENSE_ID_OR_NAME)
	if !matched {
		t.Errorf("ListLicenses(): did not include license policy `%s`, type `%s`, name `%s`\n",
			TEST_POLICY, TEST_LICENSE_TYPE, TEST_LICENSE_ID_OR_NAME)
	}
}

//---------------------------
// Where filter tests
//---------------------------
func TestLicenseListSummaryTextCdx13WhereUsageNeedsReview(t *testing.T) {
	lti := NewLicenseTestInfoBasic(TEST_LICENSE_LIST_CDX_1_3, FORMAT_TEXT, true)
	lti.WhereClause = "usage-policy=needs-review"
	lti.ResultExpectedLineCount = 8 // title and data rows
	innerTestLicenseList(t, lti)
}

func TestLicenseListSummaryTextCdx13WhereUsageUndefined(t *testing.T) {
	lti := NewLicenseTestInfoBasic(TEST_LICENSE_LIST_CDX_1_3, FORMAT_TEXT, true)
	lti.WhereClause = "usage-policy=UNDEFINED"
	lti.ResultExpectedLineCount = 4 // title and data rows
	innerTestLicenseList(t, lti)
}

func TestLicenseListSummaryTextCdx13WhereLicenseTypeName(t *testing.T) {
	lti := NewLicenseTestInfoBasic(TEST_LICENSE_LIST_CDX_1_3, FORMAT_TEXT, true)
	lti.WhereClause = "license-type=name"
	lti.ResultExpectedLineCount = 8 // title and data rows
	innerTestLicenseList(t, lti)
}

func TestLicenseListPolicyCdx14CustomPolicy(t *testing.T) {
	TEST_POLICY := POLICY_ALLOW
	TEST_LICENSE_TYPE := "expression"
	TEST_LICENSE_ID_OR_NAME := "(MIT OR CC0-1.0)"

	// Load a custom policy file ONLY for the specific unit test
	loadHashCustomPolicyFile(TEST_CUSTOM_POLICY_1)

	lti := NewLicenseTestInfoBasic(TEST_LICENSE_LIST_TEXT_CDX_1_4_CUSTOM_POLICY_1, FORMAT_TEXT, true)
	outputBuffer, _ := innerTestLicenseList(t, lti)

	matched := listOutputContainsLicense(outputBuffer, TEST_POLICY, TEST_LICENSE_TYPE, TEST_LICENSE_ID_OR_NAME)
	if !matched {
		t.Errorf("LicenseList(): did not include license policy `%s`, type `%s`, name `%s`\n",
			TEST_POLICY, TEST_LICENSE_TYPE, TEST_LICENSE_ID_OR_NAME)
	}

	// !!! IMPORTANT !!! restore default policy file to default for all other tests
	loadHashCustomPolicyFile(utils.GlobalFlags.ConfigLicensePolicyFile)
}
