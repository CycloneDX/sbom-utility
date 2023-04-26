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
	// TODO: to confirm this conflict is caught as part of "license policy" command
	// TODO: to confirm this conflict is caught as part of "license list" command (with AND/OR as well)
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
	//lti := NewLicenseTestInfo("", format, "", false, false, "", LTI_DEFAULT_LINE_COUNT, nil)
	lti := NewLicenseTestInfoBasic("", format, TI_LIST_SUMMARY_FALSE)
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

	// Load and hash the specified license policy file ONLY FOR THIS TEST!
	if testInfo.PolicyFile != "" && testInfo.PolicyFile != DEFAULT_LICENSE_POLICIES {
		// !!! IMPORTANT !!! restore default policy file to default for all other tests
		loadHashCustomPolicyFile(testInfo.PolicyFile)
	}

	// Use the test data to set the BOM input file and output format
	utils.GlobalFlags.InputFile = testInfo.InputFile
	utils.GlobalFlags.OutputFormat = testInfo.ListFormat

	// Invoke the actual List command (API)
	err = ListLicensePolicies(outputWriter, whereFilters)

	// Restore default license policy file for subsequent tests
	if testInfo.PolicyFile != "" && testInfo.PolicyFile != DEFAULT_LICENSE_POLICIES {
		// !!! IMPORTANT !!! restore default policy file to default for all other tests
		loadHashCustomPolicyFile(DEFAULT_LICENSE_POLICIES)
	}

	return
}

func innerTestLicensePolicyList(t *testing.T, testInfo *LicenseTestInfo) (outputBuffer bytes.Buffer, err error) {

	// Parse out --where filters and exit out if error detected
	whereFilters, err := prepareWhereFilters(t, &testInfo.CommonTestInfo)
	if err != nil {
		return
	}

	// Perform the test with buffered output
	outputBuffer, err = innerTestLicensePolicyListCustomAndBuffered(t, testInfo, whereFilters)

	// Run all common tests against "result" values in the CommonTestInfo struct
	err = innerRunReportResultTests(t, &testInfo.CommonTestInfo, outputBuffer, err)

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

func TestLicensePolicyExpressionBSD3OrMIT(t *testing.T) {

	EXP := "BSD-3-Clause OR MIT"
	EXPECTED_POLICY := POLICY_ALLOW

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

// NOTE: we need more tests that verify support of multiple conjunctions without
// parenthetical groups
func TestLicensePolicyExpressionMultipleConjunctions(t *testing.T) {
	EXP := "BSD-3-Clause OR MIT AND GPL"
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

	EXP = "BSD-3-Clause OR MIT OR GPL"
	EXPECTED_POLICY = POLICY_ALLOW

	expressionTree, err = parseExpression(EXP)

	if err != nil {
		t.Errorf(err.Error())
	}

	getLogger().Tracef("Parsed expression:\n%v", expressionTree)
	resolvedPolicy = expressionTree.CompoundUsagePolicy

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

func TestLicensePolicyListGoodBadMaybe(t *testing.T) {
	lti := NewLicensePolicyTestInfoBasic(FORMAT_TEXT, true)
	lti.PolicyFile = POLICY_FILE_GOOD_BAD_MAYBE
	// Assure all titles appear in output
	lti.ResultLineContainsValues = POLICY_LIST_TITLES
	lti.ResultLineContainsValuesAtLineNum = 0

	outputBuffer, err := innerTestLicensePolicyList(t, lti)

	if err != nil {
		t.Errorf(err.Error())
		return
	}

	// test for sep. row
	TEST_LINE_NUM := 1
	TEST_VALUES := []string{REPORT_LIST_TITLE_ROW_SEPARATOR}
	matchFoundLine, matchFound := lineContainsValues(outputBuffer, TEST_LINE_NUM, TEST_VALUES...)
	if !matchFound {
		t.Errorf("policy file does not contain expected values: `%v` at line: %v\n", TEST_VALUES, TEST_LINE_NUM)
		return
	} else {
		getLogger().Tracef("policy file contains expected values: `%v` at line: %v\n", TEST_VALUES, matchFoundLine)
	}

	// Assure "bad" policy has usage "deny"
	TEST_LINE_NUM = 2
	TEST_VALUES = []string{LICENSE_ID_BAD, POLICY_DENY}
	matchFoundLine, matchFound = lineContainsValues(outputBuffer, TEST_LINE_NUM, TEST_VALUES...)
	if !matchFound {
		t.Errorf("policy file does not contain expected values: `%v` at line: %v\n", TEST_VALUES, TEST_LINE_NUM)
		return
	} else {
		getLogger().Tracef("policy file contains expected values: `%v` at line: %v\n", TEST_VALUES, matchFoundLine)
	}

	// Assure "good" policy has usage "allow"
	TEST_LINE_NUM = 3
	TEST_VALUES = []string{LICENSE_ID_GOOD, POLICY_ALLOW}
	matchFoundLine, matchFound = lineContainsValues(outputBuffer, TEST_LINE_NUM, TEST_VALUES...)
	if !matchFound {
		t.Errorf("policy file does not contain expected values: `%v` at line: %v\n", TEST_VALUES, TEST_LINE_NUM)
		return
	} else {
		getLogger().Tracef("policy file contains expected values: `%v` at line: %v\n", TEST_VALUES, matchFoundLine)
	}

	// Assure "maybe" policy has usage "needs-review"
	TEST_LINE_NUM = 4
	TEST_VALUES = []string{LICENSE_ID_MAYBE, POLICY_NEEDS_REVIEW}
	matchFoundLine, matchFound = lineContainsValues(outputBuffer, TEST_LINE_NUM, TEST_VALUES...)
	if !matchFound {
		t.Errorf("policy file does not contain expected values: `%v` at line: %v\n", TEST_VALUES, TEST_LINE_NUM)
		return
	} else {
		getLogger().Tracef("policy file contains expected values: `%v` at line: %v\n", TEST_VALUES, matchFoundLine)
	}
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

//-----------------------------------------------------------------------------
// Test --wrap flag
// i.e., wraps policy (lines) where mult. URLs, Notes or Annotations are found
//-----------------------------------------------------------------------------

func TestLicensePolicyListBasicTextWrapFalse(t *testing.T) {
	lti := NewLicensePolicyTestInfoBasic(FORMAT_TEXT, true)
	lti.ResultExpectedLineCount = 250 // title and data rows
	// Verify first data row has expected values
	// sanity (spot) check row values
	lti.ResultLineContainsValuesAtLineNum = 2
	lti.ResultLineContainsValues = []string{"0BSD", POLICY_ALLOW}
	innerTestLicensePolicyList(t, lti)
}

func TestLicensePolicyListTextWrapTrue(t *testing.T) {
	lti := NewLicensePolicyTestInfoBasic(FORMAT_TEXT, true)
	lti.ResultExpectedLineCount = 402 // title and data rows
	utils.GlobalFlags.LicenseFlags.ListLineWrap = true
	// sanity (spot) check row values
	lti.ResultLineContainsValuesAtLineNum = 2
	lti.ResultLineContainsValues = []string{"0BSD", POLICY_ALLOW}
	innerTestLicensePolicyList(t, lti)
}

//--------------------------------------------------------------
//  --where tests (using custom good|bad|maybe policy file)
//--------------------------------------------------------------

// Test using custom policy file with just 3 entries: good|bad|maybe
func TestLicensePolicyListWhereTestUsagePolicyAllow(t *testing.T) {
	lti := NewLicensePolicyTestInfoBasic(FORMAT_TEXT, true)
	lti.PolicyFile = POLICY_FILE_GOOD_BAD_MAYBE
	lti.WhereClause = "usage-policy=allow"
	lti.ResultExpectedLineCount = 3
	innerTestLicensePolicyList(t, lti)
}

// Test using custom policy file with just 3 entries: good|bad|maybe
func TestLicensePolicyListWhereTestUsagePolicyDeny(t *testing.T) {
	lti := NewLicensePolicyTestInfoBasic(FORMAT_TEXT, true)
	lti.PolicyFile = POLICY_FILE_GOOD_BAD_MAYBE
	lti.WhereClause = "usage-policy=deny"
	lti.ResultExpectedLineCount = 3
	innerTestLicensePolicyList(t, lti)
}

// Test using custom policy file with just 3 entries: good|bad|maybe
func TestLicensePolicyListWhereTestUsagePolicyNeedsReview(t *testing.T) {
	lti := NewLicensePolicyTestInfoBasic(FORMAT_TEXT, true)
	lti.PolicyFile = POLICY_FILE_GOOD_BAD_MAYBE
	lti.WhereClause = "usage-policy=needs-review"
	lti.ResultExpectedLineCount = 3
	innerTestLicensePolicyList(t, lti)
}

// Test using custom policy file with just 3 entries: good|bad|maybe
func TestLicensePolicyListCSVWhereTestUsagePolicyAllow(t *testing.T) {
	lti := NewLicensePolicyTestInfoBasic(FORMAT_CSV, true)
	lti.PolicyFile = POLICY_FILE_GOOD_BAD_MAYBE
	lti.WhereClause = "usage-policy=allow"
	lti.ResultExpectedLineCount = 2
	innerTestLicensePolicyList(t, lti)
}

// Test using custom policy file with just 3 entries: good|bad|maybe
func TestLicensePolicyListMarkdownWhereTestUsagePolicyAllow(t *testing.T) {
	lti := NewLicensePolicyTestInfoBasic(FORMAT_MARKDOWN, true)
	lti.PolicyFile = POLICY_FILE_GOOD_BAD_MAYBE
	lti.WhereClause = "usage-policy=allow"
	lti.ResultExpectedLineCount = 3
	innerTestLicensePolicyList(t, lti)
}

//--------------------------------------------------------------
//  --where tests (using default policy file)
//--------------------------------------------------------------

func TestLicensePolicyListTextBasicWhereId0BSD(t *testing.T) {
	lti := NewLicensePolicyTestInfoBasic(FORMAT_TEXT, false)
	lti.WhereClause = "id=0B"
	lti.ResultLineContainsValuesAtLineNum = 3
	lti.ResultExpectedLineCount = 3
	innerTestLicensePolicyList(t, lti)
}

func TestLicensePolicyListWhereUsagePolicyDeny(t *testing.T) {
	lti := NewLicensePolicyTestInfoBasic(FORMAT_TEXT, true)
	lti.WhereClause = "usage-policy=deny"
	lti.ResultExpectedLineCount = 5
	innerTestLicensePolicyList(t, lti)
}

func TestLicensePolicyListWhereAnnotationNeedsIPApproval(t *testing.T) {
	lti := NewLicensePolicyTestInfoBasic(FORMAT_TEXT, true)
	lti.WhereClause = "annotations=NEEDS-IP"
	lti.ResultExpectedLineCount = 17
	// sanity (spot) check row values
	lti.ResultLineContainsValuesAtLineNum = 2
	lti.ResultLineContainsValues = []string{"BSD-2-Clause", POLICY_NEEDS_REVIEW}
	innerTestLicensePolicyList(t, lti)
}

func TestLicensePolicyListWhereAnnotation0BSDNeedsIPApproval(t *testing.T) {
	lti := NewLicensePolicyTestInfoBasic(FORMAT_TEXT, true)
	lti.WhereClause = "annotations=NEEDS-IP,id=BSD-4"
	lti.ResultExpectedLineCount = 6
	// sanity (spot) check row values
	lti.ResultLineContainsValuesAtLineNum = 2
	lti.ResultLineContainsValues = []string{"BSD-4-Clause", POLICY_NEEDS_REVIEW}
	innerTestLicensePolicyList(t, lti)
}
