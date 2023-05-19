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
	"testing"

	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/CycloneDX/sbom-utility/utils"
)

const (
	// Test "license list" command
	TEST_LICENSE_LIST_CDX_1_3            = "test/cyclonedx/cdx-1-3-license-list.json"
	TEST_LICENSE_LIST_CDX_1_3_NONE_FOUND = "test/cyclonedx/cdx-1-3-license-list-none-found.json"
	TEST_LICENSE_LIST_CDX_1_4_NONE_FOUND = "test/cyclonedx/cdx-1-4-license-list-none-found.json"

	TEST_LICENSE_LIST_TEXT_CDX_1_4_INVALID_LICENSE_ID    = "test/cyclonedx/cdx-1-4-license-policy-invalid-spdx-id.json"
	TEST_LICENSE_LIST_TEXT_CDX_1_4_INVALID_LICENSE_NAME  = "test/cyclonedx/cdx-1-4-license-policy-invalid-license-name.json"
	TEST_LICENSE_LIST_CDX_1_4_LICENSE_EXPRESSION_IN_NAME = "test/cyclonedx/cdx-1-4-license-expression-in-name.json"

	// Test custom license policy (with license expression)
	TEST_CUSTOM_POLICY_1                           = "test/policy/license-policy-expression-outer-parens.policy.json"
	TEST_LICENSE_LIST_TEXT_CDX_1_4_CUSTOM_POLICY_1 = "test/policy/license-policy-expression-outer-parens.bom.json"
)

// default ResourceTestInfo struct values
const (
	LTI_DEFAULT_LINE_COUNT = -1
)

type LicenseTestInfo struct {
	CommonTestInfo
	ListLineWrap bool
	PolicyFile   string // Note: if not filled in, uses default file: DEFAULT_LICENSE_POLICIES
}

func (ti *LicenseTestInfo) String() string {
	pParent := &ti.CommonTestInfo
	return pParent.String()
}

func NewLicenseTestInfo(inputFile string, listFormat string, listSummary bool, whereClause string,
	resultContainsValues []string, resultExpectedLineCount int, resultExpectedError error,
	listLineWrap bool, policyFile string) *LicenseTestInfo {

	var ti = new(LicenseTestInfo)
	var pCommon = &ti.CommonTestInfo
	// initialize common fields
	pCommon.Init(inputFile, listFormat, listSummary, whereClause,
		resultContainsValues, resultExpectedLineCount, resultExpectedError)
	// Initialize resource-unique fields
	ti.ListLineWrap = listLineWrap
	ti.PolicyFile = policyFile
	return ti
}

func NewLicenseTestInfoBasic(inputFile string, listFormat string, listSummary bool) *LicenseTestInfo {
	var ti = new(LicenseTestInfo)
	var pCommon = &ti.CommonTestInfo
	pCommon.InitBasic(inputFile, listFormat, nil)
	ti.ListSummary = listSummary
	return ti
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
	err = ListLicenses(outputWriter, testInfo.ListFormat, whereFilters, testInfo.ListSummary)

	return
}

func innerTestLicenseList(t *testing.T, testInfo *LicenseTestInfo) (outputBuffer bytes.Buffer, err error) {

	// Parse out --where filters and exit out if error detected
	whereFilters, err := prepareWhereFilters(t, &testInfo.CommonTestInfo)
	if err != nil {
		return
	}

	// Perform the test with buffered output
	outputBuffer, err = innerTestLicenseListBuffered(t, testInfo, whereFilters)

	// Run all common tests against "result" values in the CommonTestInfo struct
	err = innerRunReportResultTests(t, &testInfo.CommonTestInfo, outputBuffer, err)

	return
}

// ----------------------------------------
// Command flag tests
// ----------------------------------------

func TestLicenseListInvalidInputFileLoad(t *testing.T) {
	lti := NewLicenseTestInfoBasic(TEST_INPUT_FILE_NON_EXISTENT, FORMAT_DEFAULT, false)
	lti.ResultExpectedError = &fs.PathError{}
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
	lti.ResultExpectedError = &schema.UnsupportedFormatError{}
	innerTestLicenseList(t, lti)
}

func TestLicenseListFormatUnsupportedSPDX2(t *testing.T) {
	lti := NewLicenseTestInfoBasic(TEST_SPDX_2_2_EXAMPLE_1, FORMAT_DEFAULT, false)
	lti.ResultExpectedError = &schema.UnsupportedFormatError{}
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
	lti.ResultExpectedLineCount = 92 // array of LicenseChoice JSON objects
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
	lti.ResultExpectedLineCount = 4 // 2 title, 2 with UNDEFINED
	lti.ResultLineContainsValues = []string{POLICY_UNDEFINED, LC_TYPE_NAMES[LC_LOC_UNKNOWN], LICENSE_NONE, "package-lock.json"}
	lti.ResultLineContainsValuesAtLineNum = 3
	innerTestLicenseList(t, lti)
}

func TestLicenseListPolicyCdx14InvalidLicenseId(t *testing.T) {
	TEST_LICENSE_ID_OR_NAME := "foo"
	lti := NewLicenseTestInfoBasic(TEST_LICENSE_LIST_TEXT_CDX_1_4_INVALID_LICENSE_ID, FORMAT_TEXT, true)
	lti.ResultLineContainsValues = []string{POLICY_UNDEFINED, LC_VALUE_ID, TEST_LICENSE_ID_OR_NAME}
	lti.ResultLineContainsValuesAtLineNum = 3
	innerTestLicenseList(t, lti)
}

func TestLicenseListPolicyCdx14InvalidLicenseName(t *testing.T) {
	TEST_LICENSE_ID_OR_NAME := "bar"
	lti := NewLicenseTestInfoBasic(TEST_LICENSE_LIST_TEXT_CDX_1_4_INVALID_LICENSE_NAME, FORMAT_TEXT, true)
	lti.ResultLineContainsValues = []string{POLICY_UNDEFINED, LC_VALUE_NAME, TEST_LICENSE_ID_OR_NAME}
	lti.ResultLineContainsValuesAtLineNum = 3
	innerTestLicenseList(t, lti)
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

func TestLicenseListSummaryTextCdx14LicenseExpInName(t *testing.T) {
	lti := NewLicenseTestInfoBasic(
		TEST_LICENSE_LIST_CDX_1_4_LICENSE_EXPRESSION_IN_NAME,
		FORMAT_TEXT, true)
	lti.WhereClause = "license-type=name"
	lti.ResultLineContainsValues = []string{POLICY_UNDEFINED, "BSD-3-Clause OR MIT"}
	lti.ResultLineContainsValuesAtLineNum = 3
	lti.ResultExpectedLineCount = 4 // title and data rows
	innerTestLicenseList(t, lti)
}

func TestLicenseListPolicyCdx14CustomPolicy(t *testing.T) {
	TEST_LICENSE_ID_OR_NAME := "(MIT OR CC0-1.0)"

	lti := NewLicenseTestInfoBasic(TEST_LICENSE_LIST_TEXT_CDX_1_4_CUSTOM_POLICY_1, FORMAT_TEXT, true)
	lti.ResultLineContainsValues = []string{POLICY_ALLOW, LC_VALUE_EXPRESSION, TEST_LICENSE_ID_OR_NAME}
	lti.ResultLineContainsValuesAtLineNum = 2

	// Load a custom policy file ONLY for the specific unit test
	loadHashCustomPolicyFile(TEST_CUSTOM_POLICY_1)

	innerTestLicenseList(t, lti)

	// !!! IMPORTANT !!! restore default policy file to default for all other tests
	loadHashCustomPolicyFile(utils.GlobalFlags.ConfigLicensePolicyFile)
}

// Test custom marshal of CDXLicense (empty CDXAttachment)

func TestLicenseListCdx13JsonEmptyAttachment(t *testing.T) {
	lti := NewLicenseTestInfoBasic(
		"test/cyclonedx/cdx-1-3-license-list-no-attachment.json",
		FORMAT_JSON,
		false)
	lti.ResultExpectedLineCount = 36
	lti.ResultLineContainsValues = []string{"\"content\": \"CiAgICAgICAgICAgICA...\""}
	lti.ResultLineContainsValuesAtLineNum = -1 // JSON Hashmaps in Go are not ordered
	innerTestLicenseList(t, lti)
}
