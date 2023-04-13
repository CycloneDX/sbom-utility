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
	"strings"
	"testing"

	"github.com/CycloneDX/sbom-utility/utils"
)

const (
	// TODO: use the following file to test license expressions with "needs-review" usage policy value
	TEST_LICENSE_EXPRESSION_USAGE_POLICIES = "test/policy/license-policy-license-expression-test-data.json"
)

// Alternative license policy files for testing
const (
	POLICY_FILE_GOOD_BAD_MAYBE = "test/policy/license-policy-license-expression-test-data.json"
	// TODO: to confirm this conflict is caught at has time AND
	// TODO: to confirm this conflict is caught as part of "license list" command
	POLICY_FILE_FAMILY_NAME_USAGE_CONFLICT = "test/policy/license-policy-family-name-usage-conflict.json"
)

// Corresponding license IDs for testing (i.e., within POLICY_FILE_GOOD_BAD_MAYBE)
const (
	LICENSE_ID_GOOD  = "Good"
	LICENSE_ID_BAD   = "Bad"
	LICENSE_ID_MAYBE = "Maybe"
)

// -------------------------------------------
// license test helper functions
// -------------------------------------------

func NewLicensePolicyTestInfoBasic(format string, wrapLines bool) *LicenseTestInfo {
	lti := NewLicenseTestInfo("", format, "", false, false, "", LTI_DEFAULT_LINE_COUNT, nil)
	lti.ListLineWrap = wrapLines
	return lti
}

func loadHashCustomPolicyFile(policyFile string) (err error) {
	err = licensePolicyConfig.innerLoadLicensePolicies(policyFile)
	if err != nil {
		return
	}
	// Note: the HashLicensePolicies function creates new id and name hashmaps
	// therefore there is no need to clear them
	err = licensePolicyConfig.innerHashLicensePolicies()
	return
}

func innerTestLicensePolicyListCustomAndBuffered(t *testing.T, testInfo *LicenseTestInfo, whereFilters []WhereFilter) (outputBuffer bytes.Buffer, err error) {
	// Declare an output outputBuffer/outputWriter to use used during tests
	var outputWriter = bufio.NewWriter(&outputBuffer)
	// ensure all data is written to buffer before further validation
	defer outputWriter.Flush()

	if testInfo.PolicyFile != "" && testInfo.PolicyFile != DEFAULT_LICENSE_POLICIES {
		// !!! IMPORTANT !!! restore default policy file to default for all other tests
		loadHashCustomPolicyFile(testInfo.PolicyFile)
	}

	// Use the test data to set the BOM input file and output format
	utils.GlobalFlags.InputFile = testInfo.InputFile
	utils.GlobalFlags.OutputFormat = testInfo.Format

	// Invoke the actual List command (API)
	err = ListLicensePolicies(outputWriter, whereFilters)

	if testInfo.PolicyFile != "" && testInfo.PolicyFile != DEFAULT_LICENSE_POLICIES {
		// !!! IMPORTANT !!! restore default policy file to default for all other tests
		loadHashCustomPolicyFile(DEFAULT_LICENSE_POLICIES)
	}

	return
}

func innerTestLicensePolicyList(t *testing.T, testInfo *LicenseTestInfo) (outputBuffer bytes.Buffer, err error) {

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
	outputBuffer, err = innerTestLicensePolicyListCustomAndBuffered(t, testInfo, whereFilters)

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

	// TEST: Line contains a set of string values
	if len(testInfo.ResultContainsValues) > 0 {
		matchFoundLine, matchFound := lineContainsValues(outputBuffer, testInfo.ResultExpectedAtLineNum, testInfo.ResultContainsValues...)
		if !matchFound {
			t.Errorf("policy file does not contain expected values: %v", testInfo.ResultContainsValues)
			return
		} else {
			getLogger().Tracef("policy file contains expected values: %v on line: %v\n", testInfo.ResultContainsValues, matchFoundLine)
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

//-----------------------------------
// Usage Policy: allowed value tests
//-----------------------------------
func TestLicensePolicyUsageValueAllow(t *testing.T) {
	value := POLICY_ALLOW
	if !IsValidUsagePolicy(value) {
		t.Errorf("isValidUsagePolicy(): returned: %t; expected: %t", false, true)
	}
}

func TestLicensePolicyUsageValueDeny(t *testing.T) {
	value := POLICY_DENY
	if !IsValidUsagePolicy(value) {
		t.Errorf("isValidUsagePolicy(): returned: %t; expected: %t", false, true)
	}
}

func TestLicensePolicyUsageValueNeedsReview(t *testing.T) {
	value := POLICY_NEEDS_REVIEW
	if !IsValidUsagePolicy(value) {
		t.Errorf("isValidUsagePolicy(): returned: %t; expected: %t", false, true)
	}
}

func TestLicensePolicyUsageValueUndefined(t *testing.T) {
	value := POLICY_UNDEFINED
	if IsValidUsagePolicy(value) {
		t.Errorf("isValidUsagePolicy(): returned: %t; expected: %t", false, true)
	}
}

func TestLicensePolicyUsageInvalidValue(t *testing.T) {
	value := POLICY_CONFLICT
	if IsValidUsagePolicy(value) {
		t.Errorf("isValidUsagePolicy(): returned: %t; expected: %t", true, false)
	}
}

//------------------------------------
// Policy Family: allowed value tests
//------------------------------------

func TestLicensePolicyInvalidFamily1(t *testing.T) {
	value := "CONFLICT"
	if IsValidFamilyKey(value) {
		t.Errorf("isValidUsagePolicy(): returned: %t; expected: %t", true, false)
	}

	value = "conflict"
	if IsValidFamilyKey(value) {
		t.Errorf("isValidUsagePolicy(): returned: %t; expected: %t", true, false)
	}

	value = "Conflict"
	if IsValidFamilyKey(value) {
		t.Errorf("isValidUsagePolicy(): returned: %t; expected: %t", true, false)
	}
}

func TestLicensePolicyInvalidFamilyKeywords1(t *testing.T) {
	value := "CONFLICT"
	if IsValidFamilyKey(value) {
		t.Errorf("isValidUsagePolicy(): returned: %t; expected: %t", true, false)
	}

	value = "conflict"
	if IsValidFamilyKey(value) {
		t.Errorf("isValidUsagePolicy(): returned: %t; expected: %t", true, false)
	}

	value = "Conflict"
	if IsValidFamilyKey(value) {
		t.Errorf("isValidUsagePolicy(): returned: %t; expected: %t", true, false)
	}

	value = "Foo-Conflict-2.0-Bar"
	if IsValidFamilyKey(value) {
		t.Errorf("isValidUsagePolicy(): returned: %t; expected: %t", true, false)
	}
}

func TestLicensePolicyInvalidFamilyKeywords2(t *testing.T) {
	value := "UNKNOWN"
	if IsValidFamilyKey(value) {
		t.Errorf("isValidUsagePolicy(): returned: %t; expected: %t", true, false)
	}

	value = "unknown"
	if IsValidFamilyKey(value) {
		t.Errorf("isValidUsagePolicy(): returned: %t; expected: %t", true, false)
	}

	value = "Unknown"
	if IsValidFamilyKey(value) {
		t.Errorf("isValidUsagePolicy(): returned: %t; expected: %t", true, false)
	}

	value = "Foo-Unknown-1.1-Bar"
	if IsValidFamilyKey(value) {
		t.Errorf("isValidUsagePolicy(): returned: %t; expected: %t", true, false)
	}
}

//------------------------------------------------
// Policy Expression: parser & usage policy tests
//------------------------------------------------

func TestLicensePolicyMatchByExpFailureInvalidRightExp(t *testing.T) {

	EXP := "(Apache-1.0 OR Apache-1.1) AND Foobar"
	EXPECTED_POLICY := POLICY_UNDEFINED

	expressionTree, err := parseExpression(EXP)

	if err != nil {
		t.Errorf(err.Error())
	}

	getLogger().Tracef("Parsed expression:\n%v", expressionTree)
	resolvedPolicy := expressionTree.CompoundUsagePolicy

	if resolvedPolicy != EXPECTED_POLICY {
		t.Errorf("FindPolicyBySpdxId(): expression: %s, returned: %v; expected: %v", EXP, resolvedPolicy, EXPECTED_POLICY)
	} else {
		getLogger().Tracef("FindPolicyBySpdxId(): id: %s, policy: %s\n", EXP, resolvedPolicy)
	}
}

func TestLicensePolicyMatchByExpFailureInvalidLeftExp(t *testing.T) {

	EXP := "Foobar AND ( Apache-1.0 OR Apache-1.1 )"
	EXPECTED_POLICY := POLICY_UNDEFINED

	expressionTree, err := parseExpression(EXP)

	if err != nil {
		t.Errorf(err.Error())
	}

	getLogger().Tracef("Parsed expression:\n%v", expressionTree)
	resolvedPolicy := expressionTree.CompoundUsagePolicy

	if resolvedPolicy != EXPECTED_POLICY {
		t.Errorf("FindPolicyBySpdxId(): expression: %s, returned: %v; expected: %v", EXP, resolvedPolicy, EXPECTED_POLICY)
	} else {
		getLogger().Tracef("FindPolicyBySpdxId(): id: %s, policy: %s\n", EXP, resolvedPolicy)
	}
}

//------------------------------------------------------
// Policy Expression: test 3-state logic combinations
// NOTE: uses a custom policy file with min. number
//       of entries to represent the 3 supported states
//------------------------------------------------------

// The policy config. has 3 states: { "allow", "deny", "needs-review" }; n=3
// which are always paired with a conjunctions; r=2
// and for evaluation, we do not care about order.  This means we have to
// account for 6 combinations with unique results (policy determinations)
// 1. POLICY_DENY AND POLICY_ALLOW
// 2. POLICY_DENY AND POLICY_NEEDS_REVIEW
// 3. POLICY_DENY AND POLICY_DENY
// 4. POLICY_NEEDS_REVIEW AND POLICY_ALLOW
// 5. POLICY_NEEDS_REVIEW AND POLICY_NEEDS_REVIEW
// 6. POLICY_ALLOW AND POLICY_ALLOW
func TestLicensePolicyUsageConjunctionsANDCombinations(t *testing.T) {
	// Set the policy file to the reduced, 3-entry policy file used to test the 3 policy states
	err := loadHashCustomPolicyFile(POLICY_FILE_GOOD_BAD_MAYBE)
	if err != nil {
		t.Errorf(err.Error())
	}

	// 1. POLICY_DENY AND POLICY_ALLOW
	EXP := "Bad AND Good"
	EXPECTED_USAGE_POLICY := POLICY_DENY
	parsedExpression, err := parseExpression(EXP)
	if err != nil {
		t.Errorf(err.Error())
	}
	resolvedPolicy := parsedExpression.CompoundUsagePolicy
	if resolvedPolicy != EXPECTED_USAGE_POLICY {
		t.Errorf("parseExpression(): \"%s\" returned: `%s`; expected: `%s`", EXP, resolvedPolicy, EXPECTED_USAGE_POLICY)
	}

	// 2. POLICY_DENY AND POLICY_NEEDS_REVIEW
	EXP = "Bad AND Maybe"
	EXPECTED_USAGE_POLICY = POLICY_DENY
	parsedExpression, err = parseExpression(EXP)
	if err != nil {
		t.Errorf(err.Error())
	}
	resolvedPolicy = parsedExpression.CompoundUsagePolicy
	if resolvedPolicy != EXPECTED_USAGE_POLICY {
		t.Errorf("parseExpression(): \"%s\" returned: `%s`; expected: `%s`", EXP, resolvedPolicy, EXPECTED_USAGE_POLICY)
	}

	// 3. POLICY_DENY AND POLICY_DENY
	EXP = "Bad AND Bad"
	EXPECTED_USAGE_POLICY = POLICY_DENY
	parsedExpression, err = parseExpression(EXP)
	if err != nil {
		t.Errorf(err.Error())
	}
	resolvedPolicy = parsedExpression.CompoundUsagePolicy
	if resolvedPolicy != EXPECTED_USAGE_POLICY {
		t.Errorf("parseExpression(): \"%s\" returned: `%s`; expected: `%s`", EXP, resolvedPolicy, EXPECTED_USAGE_POLICY)
	}

	// 4. POLICY_NEEDS_REVIEW AND POLICY_ALLOW
	EXP = "Maybe AND Good"
	EXPECTED_USAGE_POLICY = POLICY_NEEDS_REVIEW
	parsedExpression, err = parseExpression(EXP)
	if err != nil {
		t.Errorf(err.Error())
	}
	resolvedPolicy = parsedExpression.CompoundUsagePolicy
	if resolvedPolicy != EXPECTED_USAGE_POLICY {
		t.Errorf("parseExpression(): \"%s\" returned: `%s`; expected: `%s`", EXP, resolvedPolicy, EXPECTED_USAGE_POLICY)
	}

	// 5. POLICY_NEEDS_REVIEW AND POLICY_NEEDS_REVIEW
	EXP = "Maybe AND Maybe"
	EXPECTED_USAGE_POLICY = POLICY_NEEDS_REVIEW
	parsedExpression, err = parseExpression(EXP)
	if err != nil {
		t.Errorf(err.Error())
	}
	resolvedPolicy = parsedExpression.CompoundUsagePolicy
	if resolvedPolicy != EXPECTED_USAGE_POLICY {
		t.Errorf("parseExpression(): \"%s\" returned: `%s`; expected: `%s`", EXP, resolvedPolicy, EXPECTED_USAGE_POLICY)
	}

	// 6. POLICY_ALLOW AND POLICY_ALLOW
	EXP = "Good AND Good"
	EXPECTED_USAGE_POLICY = POLICY_ALLOW
	parsedExpression, err = parseExpression(EXP)
	if err != nil {
		t.Errorf(err.Error())
	}
	resolvedPolicy = parsedExpression.CompoundUsagePolicy
	if resolvedPolicy != EXPECTED_USAGE_POLICY {
		t.Errorf("parseExpression(): \"%s\" returned: `%s`; expected: `%s`", EXP, resolvedPolicy, EXPECTED_USAGE_POLICY)
	}

	// !!! IMPORTANT !!! restore default policy file to default for all other tests
	loadHashCustomPolicyFile(utils.GlobalFlags.ConfigLicensePolicyFile)
}

// The policy config. has 3 states: { "allow", "deny", "needs-review" }; n=3
// which are always paired with a conjunctions; r=2
// and for evaluation, we do not care about order.  This means we have to
// account for 6 combinations with unique results (policy determinations)
// 1. POLICY_ALLOW OR POLICY_DENY
// 2. POLICY_ALLOW OR POLICY_NEEDS_REVIEW
// 3. POLICY_ALLOW OR POLICY_ALLOW
// 4. POLICY_NEEDS_REVIEW OR POLICY_DENY
// 5. POLICY_NEEDS_REVIEW OR POLICY_NEEDS_REVIEW
// 6. POLICY_DENY OR POLICY_DENY
func TestLicensePolicyUsageConjunctionsORCombinations(t *testing.T) {
	// Set the policy file to the reduced, 3-entry policy file used to test the 3 policy states
	err := loadHashCustomPolicyFile(POLICY_FILE_GOOD_BAD_MAYBE)

	if err != nil {
		t.Errorf(err.Error())
	}

	// 1. POLICY_ALLOW OR POLICY_DENY
	EXP := "Good OR Bad"
	EXPECTED_USAGE_POLICY := POLICY_ALLOW
	parsedExpression, err := parseExpression(EXP)
	if err != nil {
		t.Errorf(err.Error())
	}
	resolvedPolicy := parsedExpression.CompoundUsagePolicy
	if resolvedPolicy != EXPECTED_USAGE_POLICY {
		t.Errorf("parseExpression(): \"%s\" returned: `%s`; expected: `%s`", EXP, resolvedPolicy, EXPECTED_USAGE_POLICY)
	}

	// 2. POLICY_ALLOW OR POLICY_NEEDS_REVIEW
	EXP = "Good OR Maybe"
	EXPECTED_USAGE_POLICY = POLICY_ALLOW
	parsedExpression, err = parseExpression(EXP)
	if err != nil {
		t.Errorf(err.Error())
	}
	resolvedPolicy = parsedExpression.CompoundUsagePolicy
	if resolvedPolicy != EXPECTED_USAGE_POLICY {
		t.Errorf("parseExpression(): \"%s\" returned: `%s`; expected: `%s`", EXP, resolvedPolicy, EXPECTED_USAGE_POLICY)
	}

	// 3. POLICY_ALLOW OR POLICY_ALLOW
	EXP = "Good OR Good"
	EXPECTED_USAGE_POLICY = POLICY_ALLOW
	parsedExpression, err = parseExpression(EXP)
	if err != nil {
		t.Errorf(err.Error())
	}
	resolvedPolicy = parsedExpression.CompoundUsagePolicy
	if resolvedPolicy != EXPECTED_USAGE_POLICY {
		t.Errorf("parseExpression(): \"%s\" returned: `%s`; expected: `%s`", EXP, resolvedPolicy, EXPECTED_USAGE_POLICY)
	}

	// 4. POLICY_NEEDS_REVIEW OR POLICY_DENY
	EXP = "Maybe OR Bad"
	EXPECTED_USAGE_POLICY = POLICY_NEEDS_REVIEW
	parsedExpression, err = parseExpression(EXP)
	if err != nil {
		t.Errorf(err.Error())
	}
	resolvedPolicy = parsedExpression.CompoundUsagePolicy
	if resolvedPolicy != EXPECTED_USAGE_POLICY {
		t.Errorf("parseExpression(): \"%s\" returned: `%s`; expected: `%s`", EXP, resolvedPolicy, EXPECTED_USAGE_POLICY)
	}

	// 5. POLICY_NEEDS_REVIEW OR POLICY_NEEDS_REVIEW
	EXP = "Maybe OR Maybe"
	EXPECTED_USAGE_POLICY = POLICY_NEEDS_REVIEW
	parsedExpression, err = parseExpression(EXP)
	if err != nil {
		t.Errorf(err.Error())
	}
	resolvedPolicy = parsedExpression.CompoundUsagePolicy
	if resolvedPolicy != EXPECTED_USAGE_POLICY {
		t.Errorf("parseExpression(): \"%s\" returned: `%s`; expected: `%s`", EXP, resolvedPolicy, EXPECTED_USAGE_POLICY)
	}

	// 6. POLICY_DENY OR POLICY_DENY
	EXP = "Bad OR Bad"
	EXPECTED_USAGE_POLICY = POLICY_DENY
	parsedExpression, err = parseExpression(EXP)
	if err != nil {
		t.Errorf(err.Error())
	}
	resolvedPolicy = parsedExpression.CompoundUsagePolicy
	if resolvedPolicy != EXPECTED_USAGE_POLICY {
		t.Errorf("parseExpression(): \"%s\" returned: `%s`; expected: `%s`", EXP, resolvedPolicy, EXPECTED_USAGE_POLICY)
	}

	// !!! IMPORTANT !!! restore default policy file to default for all other tests
	loadHashCustomPolicyFile(utils.GlobalFlags.ConfigLicensePolicyFile)
}

//--------------------------------------------------------------
// Custom policy file tests (i.e., loads non-default policy files)
//--------------------------------------------------------------

// Use test file "test/policy/license-policy-family-name-usage-conflict.json"
// TODO: to confirm this conflict is caught at hash time (not load time)
func TestLicensePolicyFamilyUsagePolicyConflict(t *testing.T) {
	// Load custom policy file that contains a license usage policy conflict
	err := loadHashCustomPolicyFile(POLICY_FILE_FAMILY_NAME_USAGE_CONFLICT)

	// Note: the conflict is only encountered on the "hash"; load only loads what policies are defined in the config.
	if err != nil {
		t.Errorf(err.Error())
	}

	// !!! IMPORTANT !!! restore default policy file to default for all other tests
	loadHashCustomPolicyFile(utils.GlobalFlags.ConfigLicensePolicyFile)
}

func TestLicensePolicyList(t *testing.T) {
	// Set the license (policy) configuration to our test file and load it
	err := loadHashCustomPolicyFile(POLICY_FILE_GOOD_BAD_MAYBE)

	// Note: the conflict is only encountered on the "hash"; load only loads what policies are defined in the config.
	if err != nil {
		t.Errorf(err.Error())
	}

	// Declare an output outputBuffer/outputWriter to use used during tests
	var outputBuffer bytes.Buffer
	var outputWriter = bufio.NewWriter(&outputBuffer)

	// Test the actual list function
	errDisplay := DisplayLicensePoliciesTabbedText(outputWriter)
	if errDisplay != nil {
		t.Errorf(errDisplay.Error())
	}

	// The list routine uses other "writers" and flushes them
	// we must flush our "backing" writer (in this case to our byte buffer)
	// BEFORE testing the buffer contents
	outputWriter.Flush()

	// verify entries (by default sorted by license family name) are correct
	listing := outputBuffer.String()
	values := strings.Split(listing, "\n")
	// Debug list output:
	// getLogger().Debugf("values: %v", strings.Join(values, "\n"))

	// Skip over list entries titles and separator rows in
	// TODO: actually test all titles are present (in a dyn. loop)
	if value := values[0]; !strings.Contains(value, POLICY_LIST_TITLES[0]) {
		t.Errorf("DisplayLicensePolicies(): returned entry: %s; expected it to contain: `%s`", value, POLICY_LIST_TITLES[0])
	}

	if value := values[1]; !strings.Contains(value, REPORT_LIST_TITLE_ROW_SEPARATOR) {
		t.Errorf("DisplayLicensePolicies(): returned entry: %s; expected it to contain: `%s`", value, REPORT_LIST_TITLE_ROW_SEPARATOR)
	}

	// validate policy rows listing (i.e., indexes 0 and 1)
	if value := values[2]; !strings.Contains(value, LICENSE_ID_BAD) || !strings.Contains(value, POLICY_DENY) {
		t.Errorf("DisplayLicensePolicies(): returned entry: %s; expected ID and policy: `%s`, `%s`", value, LICENSE_ID_BAD, POLICY_DENY)
	}
	if value := values[3]; !strings.Contains(value, LICENSE_ID_GOOD) || !strings.Contains(value, POLICY_ALLOW) {
		t.Errorf("DisplayLicensePolicies(): returned entry: %s; expected ID and policy: `%s`, `%s`", value, LICENSE_ID_GOOD, POLICY_ALLOW)
	}
	if value := values[4]; !strings.Contains(value, LICENSE_ID_MAYBE) || !strings.Contains(value, POLICY_NEEDS_REVIEW) {
		t.Errorf("DisplayLicensePolicies(): returned entry: %s; expected ID and policy: `%s`, `%s`", value, LICENSE_ID_MAYBE, POLICY_NEEDS_REVIEW)
	}

	// !!! IMPORTANT !!! restore default policy file to default for all other tests
	loadHashCustomPolicyFile(utils.GlobalFlags.ConfigLicensePolicyFile)
}

//------------------------------------------------------
// Policy Find: by ID tests
// - NOTE: uses the default policy file (license.json)
//------------------------------------------------------

func TestLicensePolicyMatchByIdAllow(t *testing.T) {
	ID := "Apache-2.0"
	EXPECTED_POLICY := POLICY_ALLOW

	value, policy := FindPolicyBySpdxId(ID)

	if value != EXPECTED_POLICY {
		t.Errorf("FindPolicyBySpdxId(): id: %s, returned: %v; expected: %v", ID, value, EXPECTED_POLICY)
	} else {
		getLogger().Tracef("FindPolicyBySpdxId(): id: %s (%s), policy: %s\n", ID, policy.Name, value)
	}
}

func TestLicensePolicyMatchByIdDeny(t *testing.T) {
	ID := "CC-BY-NC-1.0"
	EXPECTED_POLICY := POLICY_DENY

	value, policy := FindPolicyBySpdxId(ID)

	if value != EXPECTED_POLICY {
		t.Errorf("FindPolicyBySpdxId(): id: %s, returned: %v; expected: %v", ID, value, EXPECTED_POLICY)
	} else {
		getLogger().Tracef("FindPolicyBySpdxId(): id: %s (%s), policy: %s\n", ID, policy.Name, value)
	}
}

func TestLicensePolicyMatchByIdFailureEmpty(t *testing.T) {
	ID := ""
	EXPECTED_POLICY := POLICY_UNDEFINED

	value, policy := FindPolicyBySpdxId(ID)

	if value != EXPECTED_POLICY {
		t.Errorf("FindPolicyBySpdxId(): id: %s, returned: %v; expected: %v", ID, value, EXPECTED_POLICY)
	} else {
		getLogger().Tracef("FindPolicyBySpdxId(): id: %s (%s), policy: %s\n", ID, policy.Name, value)
	}
}

func TestLicensePolicyMatchByIdFailureFoo(t *testing.T) {
	ID := "Foo"
	EXPECTED_POLICY := POLICY_UNDEFINED

	value, policy := FindPolicyBySpdxId(ID)

	if value != EXPECTED_POLICY {
		t.Errorf("FindPolicyBySpdxId(): id: %s, returned: %v; expected: %v", ID, value, EXPECTED_POLICY)
	} else {
		getLogger().Tracef("FindPolicyBySpdxId(): id: %s (%s), policy: %s\n", ID, policy.Name, value)
	}
}

//------------------------------------------------------
// Policy Find: by Family Name tests
// - NOTE: uses the default policy file (license.json)
//------------------------------------------------------

func TestLicensePolicyMatchByFamilyNameBadExpression(t *testing.T) {
	// Assure OR appearance results in UNDEFINED
	NAME := "CC-BY-NC-1.0 OR Apache-2.0"
	EXPECTED_POLICY := POLICY_UNDEFINED

	value, policy := FindPolicyByFamilyName(NAME)
	getLogger().Tracef("policy: %v", policy)

	if value != EXPECTED_POLICY {
		t.Errorf("FindPolicyByFamilyName(): contains expression: %s, returned: %v; expected: %v", NAME, value, EXPECTED_POLICY)
	} else {
		getLogger().Tracef("FindPolicyByFamilyName(): contains expression: %s, policy: %s\n", NAME, value)
	}

	// Assure AND appearance results in UNDEFINED
	NAME = "CC-BY-NC-1.0 AND Apache-2.0"
	value, policy = FindPolicyByFamilyName(NAME)
	getLogger().Tracef("policy: %v", policy)

	if value != EXPECTED_POLICY {
		t.Errorf("FindPolicyByFamilyName(): contains expression: %s, returned: %v; expected: %v", NAME, value, EXPECTED_POLICY)
	} else {
		getLogger().Tracef("FindPolicyByFamilyName(): contains expression: %s, policy: %s\n", NAME, value)
	}

	// Assure WITH appearance results in UNDEFINED
	NAME = "CC-BY-NC-1.0 WITH some-clause"
	value, policy = FindPolicyByFamilyName(NAME)
	getLogger().Tracef("policy: %v", policy)

	if value != EXPECTED_POLICY {
		t.Errorf("FindPolicyByFamilyName(): contains expression: %s, returned: %v; expected: %v", NAME, value, EXPECTED_POLICY)
	} else {
		getLogger().Tracef("FindPolicyByFamilyName(): contains expression: %s, policy: %s\n", NAME, value)
	}
}

//---------------------------------------------------------
// Policy "list" command tests (using default policy file)
//---------------------------------------------------------

func TestLicensePolicyListTextNoWrap(t *testing.T) {
	lti := NewLicensePolicyTestInfoBasic(FORMAT_TEXT, true)
	lti.ResultExpectedLineCount = 250 // title and data rows
	innerTestLicensePolicyList(t, lti)
}

func TestLicensePolicyListTextWrap(t *testing.T) {
	lti := NewLicensePolicyTestInfoBasic(FORMAT_TEXT, true)
	lti.ResultExpectedLineCount = 402 // title and data rows
	utils.GlobalFlags.LicenseFlags.ListLineWrap = true
	innerTestLicensePolicyList(t, lti)
}

func TestLicensePolicyListTextFirstEntry0BSD(t *testing.T) {
	lti := NewLicensePolicyTestInfoBasic(FORMAT_TEXT, true)
	lti.ResultExpectedAtLineNum = 2
	lti.ResultContainsValues = []string{"0BSD"}
	innerTestLicensePolicyList(t, lti)
}
