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
	"testing"

	"github.com/CycloneDX/sbom-utility/common"
	"github.com/CycloneDX/sbom-utility/log"
	"github.com/CycloneDX/sbom-utility/schema"
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

func NewLicensePolicyTestInfoBasic(format string, listLineWrap bool) *LicenseTestInfo {
	lti := NewLicenseTestInfoBasic("", format, TI_LIST_SUMMARY_FALSE)
	lti.ListLineWrap = listLineWrap
	return lti
}

func LoadCustomPolicyFile(policyFile string) (customPolicyConfig *schema.LicensePolicyConfig, err error) {
	// Do not pass a default file, it should fail if custom policy cannot be loaded
	if policyFile != "" {
		customPolicyConfig = new(schema.LicensePolicyConfig)
		err = customPolicyConfig.LoadHashPolicyConfigurationFile(policyFile, "")
		if err != nil {
			getLogger().Warningf("unable to load policy configuration file: %v", err.Error())
			return
		}
	}
	return
}

func innerTestLicensePolicyListCustomAndBuffered(t *testing.T, testInfo *LicenseTestInfo, whereFilters []common.WhereFilter) (outputBuffer bytes.Buffer, err error) {
	// Declare an output outputBuffer/outputWriter to use used during tests
	var outputWriter = bufio.NewWriter(&outputBuffer)
	// ensure all data is written to buffer before further validation
	defer outputWriter.Flush()

	// Use the test data to set the BOM input file and output format
	utils.GlobalFlags.ConfigLicensePolicyFile = testInfo.PolicyFile
	utils.GlobalFlags.PersistentFlags.InputFile = testInfo.InputFile
	utils.GlobalFlags.PersistentFlags.OutputFormat = testInfo.OutputFormat
	utils.GlobalFlags.LicenseFlags.Summary = testInfo.ListSummary

	// TODO: pass GlobalConfig to every Command to allow per-instance changes for tests
	// !!! IMPORTANT MUST explicitly set the global value for every single test
	utils.GlobalFlags.LicenseFlags.ListLineWrap = testInfo.ListLineWrap

	// set license policy config. per-test
	var policyConfig *schema.LicensePolicyConfig = LicensePolicyConfig
	if testInfo.PolicyFile != "" && testInfo.PolicyFile != DEFAULT_LICENSE_POLICY_CONFIG {
		policyConfig = new(schema.LicensePolicyConfig)
		err = policyConfig.LoadHashPolicyConfigurationFile(testInfo.PolicyFile, "")
		if err != nil {
			getLogger().Warningf("unable to load policy configuration file: %v", err.Error())
			return
		}
	}

	// Invoke the actual List command (API)
	err = ListLicensePolicies(outputWriter, policyConfig,
		utils.GlobalFlags.PersistentFlags, utils.GlobalFlags.LicenseFlags,
		whereFilters)

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

//------------------------------------------------------
// Policy Expression: test 3-state logic combinations
// NOTE: uses a custom policy file with min. number
//       of entries to represent the 3 supported states
//------------------------------------------------------

// The policy config. has 3 states: { "allow", "deny", "needs-review" }; n=3
// which are always paired with a conjunctions; r=2
// and for evaluation, we do not care about order.  This means we have to
// account for 6 combinations with unique results (policy determinations)
// 1. schema.POLICY_DENY AND schema.POLICY_ALLOW
// 2. schema.POLICY_DENY AND schema.POLICY_NEEDS_REVIEW
// 3. schema.POLICY_DENY AND schema.POLICY_DENY
// 4. schema.POLICY_NEEDS_REVIEW AND schema.POLICY_ALLOW
// 5. schema.POLICY_NEEDS_REVIEW AND schema.POLICY_NEEDS_REVIEW
// 6. schema.POLICY_ALLOW AND schema.POLICY_ALLOW
func TestLicensePolicyUsageConjunctionsANDCombinations(t *testing.T) {
	// Set the policy file to the reduced, 3-entry policy file used to test the 3 policy states
	testPolicyConfig, err := LoadCustomPolicyFile(POLICY_FILE_GOOD_BAD_MAYBE)
	if err != nil {
		t.Errorf(err.Error())
	}

	// 1. schema.POLICY_DENY AND schema.POLICY_ALLOW
	EXP := "Bad AND Good"
	EXPECTED_USAGE_POLICY := schema.POLICY_DENY
	parsedExpression, err := schema.ParseExpression(testPolicyConfig, EXP)
	if err != nil {
		t.Errorf(err.Error())
	}
	resolvedPolicy := parsedExpression.CompoundUsagePolicy
	if resolvedPolicy != EXPECTED_USAGE_POLICY {
		t.Errorf("schema.ParseExpression(): \"%s\" returned: `%s`; expected: `%s`", EXP, resolvedPolicy, EXPECTED_USAGE_POLICY)
	}

	// 2. schema.POLICY_DENY AND schema.POLICY_NEEDS_REVIEW
	EXP = "Bad AND Maybe"
	EXPECTED_USAGE_POLICY = schema.POLICY_DENY
	parsedExpression, err = schema.ParseExpression(testPolicyConfig, EXP)
	if err != nil {
		t.Errorf(err.Error())
	}
	resolvedPolicy = parsedExpression.CompoundUsagePolicy
	if resolvedPolicy != EXPECTED_USAGE_POLICY {
		t.Errorf("schema.ParseExpression(): \"%s\" returned: `%s`; expected: `%s`", EXP, resolvedPolicy, EXPECTED_USAGE_POLICY)
	}

	// 3. schema.POLICY_DENY AND schema.POLICY_DENY
	EXP = "Bad AND Bad"
	EXPECTED_USAGE_POLICY = schema.POLICY_DENY
	parsedExpression, err = schema.ParseExpression(testPolicyConfig, EXP)
	if err != nil {
		t.Errorf(err.Error())
	}
	resolvedPolicy = parsedExpression.CompoundUsagePolicy
	if resolvedPolicy != EXPECTED_USAGE_POLICY {
		t.Errorf("schema.ParseExpression(): \"%s\" returned: `%s`; expected: `%s`", EXP, resolvedPolicy, EXPECTED_USAGE_POLICY)
	}

	// 4. schema.POLICY_NEEDS_REVIEW AND schema.POLICY_ALLOW
	EXP = "Maybe AND Good"
	EXPECTED_USAGE_POLICY = schema.POLICY_NEEDS_REVIEW
	parsedExpression, err = schema.ParseExpression(testPolicyConfig, EXP)
	if err != nil {
		t.Errorf(err.Error())
	}
	resolvedPolicy = parsedExpression.CompoundUsagePolicy
	if resolvedPolicy != EXPECTED_USAGE_POLICY {
		t.Errorf("schema.ParseExpression(): \"%s\" returned: `%s`; expected: `%s`", EXP, resolvedPolicy, EXPECTED_USAGE_POLICY)
	}

	// 5. schema.POLICY_NEEDS_REVIEW AND schema.POLICY_NEEDS_REVIEW
	EXP = "Maybe AND Maybe"
	EXPECTED_USAGE_POLICY = schema.POLICY_NEEDS_REVIEW
	parsedExpression, err = schema.ParseExpression(testPolicyConfig, EXP)
	if err != nil {
		t.Errorf(err.Error())
	}
	resolvedPolicy = parsedExpression.CompoundUsagePolicy
	if resolvedPolicy != EXPECTED_USAGE_POLICY {
		t.Errorf("schema.ParseExpression(): \"%s\" returned: `%s`; expected: `%s`", EXP, resolvedPolicy, EXPECTED_USAGE_POLICY)
	}

	// 6. schema.POLICY_ALLOW AND schema.POLICY_ALLOW
	EXP = "Good AND Good"
	EXPECTED_USAGE_POLICY = schema.POLICY_ALLOW
	parsedExpression, err = schema.ParseExpression(testPolicyConfig, EXP)
	if err != nil {
		t.Errorf(err.Error())
	}
	resolvedPolicy = parsedExpression.CompoundUsagePolicy
	if resolvedPolicy != EXPECTED_USAGE_POLICY {
		t.Errorf("schema.ParseExpression(): \"%s\" returned: `%s`; expected: `%s`", EXP, resolvedPolicy, EXPECTED_USAGE_POLICY)
	}
}

// The policy config. has 3 states: { "allow", "deny", "needs-review" }; n=3
// which are always paired with a conjunctions; r=2
// and for evaluation, we do not care about order.  This means we have to
// account for 6 combinations with unique results (policy determinations)
// 1. schema.POLICY_ALLOW OR schema.POLICY_DENY
// 2. schema.POLICY_ALLOW OR schema.POLICY_NEEDS_REVIEW
// 3. schema.POLICY_ALLOW OR schema.POLICY_ALLOW
// 4. schema.POLICY_NEEDS_REVIEW OR schema.POLICY_DENY
// 5. schema.POLICY_NEEDS_REVIEW OR schema.POLICY_NEEDS_REVIEW
// 6. schema.POLICY_DENY OR schema.POLICY_DENY
func TestLicensePolicyUsageConjunctionsORCombinations(t *testing.T) {
	// Set the policy file to the reduced, 3-entry policy file used to test the 3 policy states
	testPolicyConfig, err := LoadCustomPolicyFile(POLICY_FILE_GOOD_BAD_MAYBE)
	if err != nil {
		t.Errorf(err.Error())
	}

	// 1. schema.POLICY_ALLOW OR schema.POLICY_DENY
	EXP := "Good OR Bad"
	EXPECTED_USAGE_POLICY := schema.POLICY_ALLOW
	parsedExpression, err := schema.ParseExpression(testPolicyConfig, EXP)
	if err != nil {
		t.Errorf(err.Error())
	}
	resolvedPolicy := parsedExpression.CompoundUsagePolicy
	if resolvedPolicy != EXPECTED_USAGE_POLICY {
		t.Errorf("schema.ParseExpression(): \"%s\" returned: `%s`; expected: `%s`", EXP, resolvedPolicy, EXPECTED_USAGE_POLICY)
	}

	// 2. schema.POLICY_ALLOW OR schema.POLICY_NEEDS_REVIEW
	EXP = "Good OR Maybe"
	EXPECTED_USAGE_POLICY = schema.POLICY_ALLOW
	parsedExpression, err = schema.ParseExpression(testPolicyConfig, EXP)
	if err != nil {
		t.Errorf(err.Error())
	}
	resolvedPolicy = parsedExpression.CompoundUsagePolicy
	if resolvedPolicy != EXPECTED_USAGE_POLICY {
		t.Errorf("schema.ParseExpression(): \"%s\" returned: `%s`; expected: `%s`", EXP, resolvedPolicy, EXPECTED_USAGE_POLICY)
	}

	// 3. schema.POLICY_ALLOW OR schema.POLICY_ALLOW
	EXP = "Good OR Good"
	EXPECTED_USAGE_POLICY = schema.POLICY_ALLOW
	parsedExpression, err = schema.ParseExpression(testPolicyConfig, EXP)
	if err != nil {
		t.Errorf(err.Error())
	}
	resolvedPolicy = parsedExpression.CompoundUsagePolicy
	if resolvedPolicy != EXPECTED_USAGE_POLICY {
		t.Errorf("schema.ParseExpression(): \"%s\" returned: `%s`; expected: `%s`", EXP, resolvedPolicy, EXPECTED_USAGE_POLICY)
	}

	// 4. schema.POLICY_NEEDS_REVIEW OR schema.POLICY_DENY
	EXP = "Maybe OR Bad"
	EXPECTED_USAGE_POLICY = schema.POLICY_NEEDS_REVIEW
	parsedExpression, err = schema.ParseExpression(testPolicyConfig, EXP)
	if err != nil {
		t.Errorf(err.Error())
	}
	resolvedPolicy = parsedExpression.CompoundUsagePolicy
	if resolvedPolicy != EXPECTED_USAGE_POLICY {
		t.Errorf("schema.ParseExpression(): \"%s\" returned: `%s`; expected: `%s`", EXP, resolvedPolicy, EXPECTED_USAGE_POLICY)
	}

	// 5. schema.POLICY_NEEDS_REVIEW OR schema.POLICY_NEEDS_REVIEW
	EXP = "Maybe OR Maybe"
	EXPECTED_USAGE_POLICY = schema.POLICY_NEEDS_REVIEW
	parsedExpression, err = schema.ParseExpression(testPolicyConfig, EXP)
	if err != nil {
		t.Errorf(err.Error())
	}
	resolvedPolicy = parsedExpression.CompoundUsagePolicy
	if resolvedPolicy != EXPECTED_USAGE_POLICY {
		t.Errorf("schema.ParseExpression(): \"%s\" returned: `%s`; expected: `%s`", EXP, resolvedPolicy, EXPECTED_USAGE_POLICY)
	}

	// 6. schema.POLICY_DENY OR schema.POLICY_DENY
	EXP = "Bad OR Bad"
	EXPECTED_USAGE_POLICY = schema.POLICY_DENY
	parsedExpression, err = schema.ParseExpression(testPolicyConfig, EXP)
	if err != nil {
		t.Errorf(err.Error())
	}
	resolvedPolicy = parsedExpression.CompoundUsagePolicy
	if resolvedPolicy != EXPECTED_USAGE_POLICY {
		t.Errorf("schema.ParseExpression(): \"%s\" returned: `%s`; expected: `%s`", EXP, resolvedPolicy, EXPECTED_USAGE_POLICY)
	}
}

//--------------------------------------------------------------
// Custom policy file tests (i.e., loads non-default policy files)
//--------------------------------------------------------------

// Use test file "test/policy/license-policy-family-name-usage-conflict.json"
// TODO: to confirm this conflict is caught at hash time (not load time)
func TestLicensePolicyFamilyUsagePolicyConflict(t *testing.T) {
	// Load custom policy file that contains a license usage policy conflict
	_, err := LoadCustomPolicyFile(POLICY_FILE_FAMILY_NAME_USAGE_CONFLICT)

	// Note: the conflict is only encountered on the "hash"; load only loads what policies are defined in the config.
	if err != nil {
		t.Errorf(err.Error())
	}
}

func TestLicensePolicyCustomListGoodBadMaybe(t *testing.T) {
	lti := NewLicensePolicyTestInfoBasic(FORMAT_TEXT, true)
	lti.PolicyFile = POLICY_FILE_GOOD_BAD_MAYBE

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
	TEST_VALUES = []string{LICENSE_ID_BAD, schema.POLICY_DENY}
	matchFoundLine, matchFound = lineContainsValues(outputBuffer, TEST_LINE_NUM, TEST_VALUES...)
	if !matchFound {
		t.Errorf("policy file does not contain expected values: `%v` at line: %v\n", TEST_VALUES, TEST_LINE_NUM)
		return
	} else {
		getLogger().Tracef("policy file contains expected values: `%v` at line: %v\n", TEST_VALUES, matchFoundLine)
	}

	// Assure "good" policy has usage "allow"
	TEST_LINE_NUM = 3
	TEST_VALUES = []string{LICENSE_ID_GOOD, schema.POLICY_ALLOW}
	matchFoundLine, matchFound = lineContainsValues(outputBuffer, TEST_LINE_NUM, TEST_VALUES...)
	if !matchFound {
		t.Errorf("policy file does not contain expected values: `%v` at line: %v\n", TEST_VALUES, TEST_LINE_NUM)
		return
	} else {
		getLogger().Tracef("policy file contains expected values: `%v` at line: %v\n", TEST_VALUES, matchFoundLine)
	}

	// Assure "maybe" policy has usage "needs-review"
	TEST_LINE_NUM = 4
	TEST_VALUES = []string{LICENSE_ID_MAYBE, schema.POLICY_NEEDS_REVIEW}
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
	EXPECTED_POLICY := schema.POLICY_ALLOW

	value, policy, err := LicensePolicyConfig.FindPolicyBySpdxId(ID)
	if err != nil {
		t.Error(err)
	}

	if value != EXPECTED_POLICY {
		t.Errorf("FindPolicyBySpdxId(): id: %s, returned: %v; expected: %v", ID, value, EXPECTED_POLICY)
	} else {
		getLogger().Tracef("FindPolicyBySpdxId(): id: %s (%s), policy: %s\n", ID, policy.Name, value)
	}
}

func TestLicensePolicyMatchByIdDeny(t *testing.T) {
	ID := "CC-BY-NC-1.0"
	EXPECTED_POLICY := schema.POLICY_DENY

	value, policy, err := LicensePolicyConfig.FindPolicyBySpdxId(ID)
	if err != nil {
		t.Error(err)
	}

	if value != EXPECTED_POLICY {
		t.Errorf("FindPolicyBySpdxId(): id: %s, returned: %v; expected: %v", ID, value, EXPECTED_POLICY)
	} else {
		getLogger().Tracef("FindPolicyBySpdxId(): id: %s (%s), policy: %s\n", ID, policy.Name, value)
	}
}

func TestLicensePolicyMatchByIdFailureEmpty(t *testing.T) {
	ID := ""
	EXPECTED_POLICY := schema.POLICY_UNDEFINED

	value, policy, err := LicensePolicyConfig.FindPolicyBySpdxId(ID)
	if err != nil {
		t.Error(err)
	}

	if value != EXPECTED_POLICY {
		t.Errorf("FindPolicyBySpdxId(): id: %s, returned: %v; expected: %v", ID, value, EXPECTED_POLICY)
	} else {
		getLogger().Tracef("FindPolicyBySpdxId(): id: %s (%s), policy: %s\n", ID, policy.Name, value)
	}
}

func TestLicensePolicyMatchByIdFailureFoo(t *testing.T) {
	ID := "Foo"
	EXPECTED_POLICY := schema.POLICY_UNDEFINED

	value, policy, err := LicensePolicyConfig.FindPolicyBySpdxId(ID)
	if err != nil {
		t.Error(err)
	}

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
	EXPECTED_POLICY := schema.POLICY_UNDEFINED

	value, policy, err := LicensePolicyConfig.FindPolicyByFamilyName(NAME)
	if err != nil {
		t.Error(err)
	}
	getLogger().Tracef("policy: %v", policy)

	if value != EXPECTED_POLICY {
		t.Errorf("FindPolicyByFamilyName(): contains expression: %s, returned: %v; expected: %v", NAME, value, EXPECTED_POLICY)
	} else {
		getLogger().Tracef("FindPolicyByFamilyName(): contains expression: %s, policy: %s\n", NAME, value)
	}

	// Assure AND appearance results in UNDEFINED
	NAME = "CC-BY-NC-1.0 AND Apache-2.0"
	value, policy, err = LicensePolicyConfig.FindPolicyByFamilyName(NAME)
	if err != nil {
		t.Error(err)
	}
	getLogger().Tracef("policy: %v", policy)

	if value != EXPECTED_POLICY {
		t.Errorf("FindPolicyByFamilyName(): contains expression: %s, returned: %v; expected: %v", NAME, value, EXPECTED_POLICY)
	} else {
		getLogger().Tracef("FindPolicyByFamilyName(): contains expression: %s, policy: %s\n", NAME, value)
	}

	// Assure WITH appearance results in UNDEFINED
	NAME = "CC-BY-NC-1.0 WITH some-clause"
	value, policy, err = LicensePolicyConfig.FindPolicyByFamilyName(NAME)
	if err != nil {
		t.Error(err)
	}
	getLogger().Tracef("policy: %v", policy)

	if value != EXPECTED_POLICY {
		t.Errorf("FindPolicyByFamilyName(): contains expression: %s, returned: %v; expected: %v", NAME, value, EXPECTED_POLICY)
	} else {
		getLogger().Tracef("FindPolicyByFamilyName(): contains expression: %s, policy: %s\n", NAME, value)
	}
}

//-----------------------------------------------------------------------------
// Test --wrap flag
// i.e., wraps policy (lines) where multiple URLs, Notes or Annotations are found
//-----------------------------------------------------------------------------

func TestLicensePolicyListWrapFalse(t *testing.T) {
	lti := NewLicensePolicyTestInfoBasic(FORMAT_TEXT, false)
	lti.ResultExpectedLineCount = 249 // title and data rows
	// Verify first data row has expected values
	// sanity (spot) check row values
	lti.ResultLineContainsValuesAtLineNum = 2
	lti.ResultLineContainsValues = []string{"0BSD", schema.POLICY_ALLOW}
	innerTestLicensePolicyList(t, lti)
}

func TestLicensePolicyListWrapTrue(t *testing.T) {
	lti := NewLicensePolicyTestInfoBasic(FORMAT_TEXT, true)
	lti.ResultExpectedLineCount = 376 // title and data rows
	// sanity (spot) check row values
	lti.ResultLineContainsValuesAtLineNum = 2
	lti.ResultLineContainsValues = []string{"0BSD", schema.POLICY_ALLOW}
	innerTestLicensePolicyList(t, lti)
}

//--------------------------------------------------------------
//  --where tests (using custom good|bad|maybe policy file)
//--------------------------------------------------------------

// Test using custom policy file with just 3 entries: good|bad|maybe
func TestLicensePolicyCustomListWhereTestUsagePolicyAllow(t *testing.T) {
	lti := NewLicensePolicyTestInfoBasic(FORMAT_TEXT, false)
	lti.PolicyFile = POLICY_FILE_GOOD_BAD_MAYBE
	lti.WhereClause = "usage-policy=allow"
	lti.ResultExpectedLineCount = 3
	innerTestLicensePolicyList(t, lti)
}

// Test using custom policy file with just 3 entries: good|bad|maybe
func TestLicensePolicyListCustomWhereTestUsagePolicyDeny(t *testing.T) {
	lti := NewLicensePolicyTestInfoBasic(FORMAT_TEXT, false)
	lti.PolicyFile = POLICY_FILE_GOOD_BAD_MAYBE
	lti.WhereClause = "usage-policy=deny"
	lti.ResultExpectedLineCount = 3
	innerTestLicensePolicyList(t, lti)
}

// Test using custom policy file with just 3 entries: good|bad|maybe
func TestLicensePolicyListCustomWhereTestUsagePolicyNeedsReview(t *testing.T) {
	lti := NewLicensePolicyTestInfoBasic(FORMAT_TEXT, false)
	lti.PolicyFile = POLICY_FILE_GOOD_BAD_MAYBE
	lti.WhereClause = "usage-policy=needs-review"
	lti.ResultExpectedLineCount = 3
	innerTestLicensePolicyList(t, lti)
}

// Test using custom policy file with just 3 entries: good|bad|maybe
func TestLicensePolicyListCustomCSVWhereTestUsagePolicyAllow(t *testing.T) {
	lti := NewLicensePolicyTestInfoBasic(FORMAT_CSV, false)
	lti.PolicyFile = POLICY_FILE_GOOD_BAD_MAYBE
	lti.WhereClause = "usage-policy=allow"
	lti.ResultExpectedLineCount = 2
	innerTestLicensePolicyList(t, lti)
}

// Test using custom policy file with just 3 entries: good|bad|maybe
func TestLicensePolicyListCustomMarkdownWhereTestUsagePolicyAllow(t *testing.T) {
	lti := NewLicensePolicyTestInfoBasic(FORMAT_MARKDOWN, false)
	lti.PolicyFile = POLICY_FILE_GOOD_BAD_MAYBE
	lti.WhereClause = "usage-policy=allow"
	lti.ResultExpectedLineCount = 3
	innerTestLicensePolicyList(t, lti)
}

//--------------------------------------------------------------
//  --where tests (using default policy file)
//--------------------------------------------------------------

func TestLicensePolicyListTextWhereId0BSD(t *testing.T) {
	lti := NewLicensePolicyTestInfoBasic(FORMAT_TEXT, false)
	lti.WhereClause = "id=0B"
	lti.ResultLineContainsValuesAtLineNum = 3
	lti.ResultExpectedLineCount = 3
	innerTestLicensePolicyList(t, lti)
}

func TestLicensePolicyListWhereUsagePolicyDeny(t *testing.T) {
	lti := NewLicensePolicyTestInfoBasic(FORMAT_TEXT, false)
	lti.WhereClause = "usage-policy=deny"
	lti.ResultExpectedLineCount = 5
	innerTestLicensePolicyList(t, lti)
}

func TestLicensePolicyListWhereAnnotationNeedsIPApproval(t *testing.T) {
	lti := NewLicensePolicyTestInfoBasic(FORMAT_TEXT, false)
	lti.WhereClause = "annotations=NEEDS-IP"
	lti.ResultExpectedLineCount = 22
	// sanity (spot) check row values
	lti.ResultLineContainsValuesAtLineNum = 2
	lti.ResultLineContainsValues = []string{"BSD-2-Clause", schema.POLICY_NEEDS_REVIEW}
	_, err := innerTestLicensePolicyList(t, lti)
	if err != nil {
		s, _ := log.FormatStruct(lti)
		fmt.Printf(">>> %s\n", s)
	}
}

func TestLicensePolicyListWhereAnnotation0BSDNeedsIPApproval(t *testing.T) {
	lti := NewLicensePolicyTestInfoBasic(FORMAT_TEXT, false)
	lti.WhereClause = "annotations=NEEDS-IP,id=BSD-4"
	lti.ResultExpectedLineCount = 6
	// sanity (spot) check row values
	lti.ResultLineContainsValuesAtLineNum = 2
	lti.ResultLineContainsValues = []string{"BSD-4-Clause", schema.POLICY_NEEDS_REVIEW}
	_, err := innerTestLicensePolicyList(t, lti)
	if err != nil {
		s, _ := log.FormatStruct(lti)
		fmt.Printf(">>> %s\n", s)
	}
}

func TestLicensePolicyListWhereFamilyApache(t *testing.T) {
	lti := NewLicensePolicyTestInfoBasic(FORMAT_TEXT, false)
	lti.WhereClause = "family=Apache"
	lti.ResultExpectedLineCount = 5
	// sanity (spot) check row values
	lti.ResultLineContainsValuesAtLineNum = 2
	lti.ResultLineContainsValues = []string{"Apache v1.0", schema.POLICY_ALLOW}
	innerTestLicensePolicyList(t, lti)
}

func TestLicensePolicyListWhereAliases(t *testing.T) {
	lti := NewLicensePolicyTestInfoBasic(FORMAT_TEXT, false)
	lti.WhereClause = "aliases=Apache"
	lti.ResultExpectedLineCount = 3
	innerTestLicensePolicyList(t, lti)
}

func TestLicensePolicyListWhereDeprecatedTrue(t *testing.T) {
	lti := NewLicensePolicyTestInfoBasic(FORMAT_TEXT, false)
	lti.WhereClause = "deprecated=true"
	lti.ResultExpectedLineCount = 17 // 15 matches + 2 title rows
	innerTestLicensePolicyList(t, lti)
}

//------------------------------------------------
// Policy Expression: parser & usage policy tests
//------------------------------------------------

func TestLicensePolicyMatchByExpFailureInvalidRightExp(t *testing.T) {

	EXP := "(Apache-1.0 OR Apache-1.1) AND Foobar"
	EXPECTED_POLICY := schema.POLICY_UNDEFINED

	expressionTree, err := schema.ParseExpression(LicensePolicyConfig, EXP)

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
	EXPECTED_POLICY := schema.POLICY_UNDEFINED

	expressionTree, err := schema.ParseExpression(LicensePolicyConfig, EXP)

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
	EXPECTED_POLICY := schema.POLICY_ALLOW

	expressionTree, err := schema.ParseExpression(LicensePolicyConfig, EXP)

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
	EXPECTED_POLICY := schema.POLICY_UNDEFINED

	expressionTree, err := schema.ParseExpression(LicensePolicyConfig, EXP)

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
	EXPECTED_POLICY = schema.POLICY_ALLOW

	expressionTree, err = schema.ParseExpression(LicensePolicyConfig, EXP)

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
