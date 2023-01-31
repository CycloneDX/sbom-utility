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

func TestLicensePolicyInvalidFamilyLowerCase2(t *testing.T) {
	value := "conflict"
	if IsValidFamilyKey(value) {
		t.Errorf("isValidUsagePolicy(): returned: %t; expected: %t", true, false)
	}
}

func TestLicensePolicyMatchByIdAllow(t *testing.T) {
	ID := "Apache-2.0"
	EXPECTED_POLICY := POLICY_ALLOW

	value, policy := FindPolicyBySpdxId(ID)

	if value != EXPECTED_POLICY {
		t.Errorf("FindPolicyBySpdxId(): id: %s, returned: %v; expected: %v", ID, value, EXPECTED_POLICY)
	} else {
		getLogger().Tracef("FindPolicyBySpdxId(): id: %s (%s), policy: %s, ", ID, policy.Name, value)
	}
}

func TestLicensePolicyMatchByIdDeny(t *testing.T) {
	ID := "CC-BY-NC-1.0"
	EXPECTED_POLICY := POLICY_DENY

	value, policy := FindPolicyBySpdxId(ID)

	if value != EXPECTED_POLICY {
		t.Errorf("FindPolicyBySpdxId(): id: %s, returned: %v; expected: %v", ID, value, EXPECTED_POLICY)
	} else {
		getLogger().Tracef("FindPolicyBySpdxId(): id: %s (%s), policy: %s, ", ID, policy.Name, value)
	}
}

func TestLicensePolicyMatchByIdFailureEmpty(t *testing.T) {
	ID := ""
	EXPECTED_POLICY := POLICY_UNDEFINED

	value, policy := FindPolicyBySpdxId(ID)

	if value != EXPECTED_POLICY {
		t.Errorf("FindPolicyBySpdxId(): id: %s, returned: %v; expected: %v", ID, value, EXPECTED_POLICY)
	} else {
		getLogger().Tracef("FindPolicyBySpdxId(): id: %s (%s), policy: %s, ", ID, policy.Name, value)
	}
}

func TestLicensePolicyMatchByIdFailureFoo(t *testing.T) {
	ID := "Foo"
	EXPECTED_POLICY := POLICY_UNDEFINED

	value, policy := FindPolicyBySpdxId(ID)

	if value != EXPECTED_POLICY {
		t.Errorf("FindPolicyBySpdxId(): id: %s, returned: %v; expected: %v", ID, value, EXPECTED_POLICY)
	} else {
		getLogger().Tracef("FindPolicyBySpdxId(): id: %s (%s), policy: %s, ", ID, policy.Name, value)
	}
}

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
		getLogger().Tracef("FindPolicyBySpdxId(): id: %s, policy: %s, ", EXP, resolvedPolicy)
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
		getLogger().Tracef("FindPolicyBySpdxId(): id: %s, policy: %s, ", EXP, resolvedPolicy)
	}
}

func TestLicensePolicyList(t *testing.T) {
	// Reset the license (policy) configuration to our test file and load it
	licensePolicyConfig = new(LicenseComplianceConfig)
	errPolicies := licensePolicyConfig.LoadLicensePolicies(POLICY_FILE_GOOD_BAD_MAYBE)
	if errPolicies != nil {
		t.Errorf(errPolicies.Error())
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

	// Skip over list entries titles and separator rows in
	// TODO: actually test all titles are present (in a dyn. loop)
	if value := values[0]; !strings.Contains(value, LICENSE_POLICY_SUMMARY_TITLES[0]) {
		t.Errorf("DisplayLicensePolicies(): returned entry: %s; expected it to contain: `%s`", value, LICENSE_POLICY_SUMMARY_TITLES[0])
	}

	if value := values[1]; !strings.Contains(value, LICENSE_LIST_TITLE_ROW_SEPARATOR) {
		t.Errorf("DisplayLicensePolicies(): returned entry: %s; expected it to contain: `%s`", value, LICENSE_LIST_TITLE_ROW_SEPARATOR)
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
}

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
	// Reset the license (policy) configuration to our test file and load it
	licensePolicyConfig = new(LicenseComplianceConfig)
	errPolicies := licensePolicyConfig.LoadLicensePolicies(POLICY_FILE_GOOD_BAD_MAYBE)
	if errPolicies != nil {
		t.Errorf(errPolicies.Error())
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
	// Reset the license (policy) configuration to our test file and load it
	licensePolicyConfig = new(LicenseComplianceConfig)
	errPolicies := licensePolicyConfig.LoadLicensePolicies(POLICY_FILE_GOOD_BAD_MAYBE)
	if errPolicies != nil {
		t.Errorf(errPolicies.Error())
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
}

// Use test file "test/policy/license-policy-family-name-usage-conflict.json"
// TODO: to confirm this conflict is caught at has time AND
// TODO: to confirm this conflict is caught as part of "license list" command
func TestLicensePolicyFamilyUsagePolicyConflict(t *testing.T) {
	// Reset the license (policy) configuration to our test file and load it
	licensePolicyConfig = new(LicenseComplianceConfig)
	errPolicies := licensePolicyConfig.LoadLicensePolicies(POLICY_FILE_FAMILY_NAME_USAGE_CONFLICT)
	// Note: the conflict is only encountered on the "hash"; load only loads what policies are defined in the config.

	if errPolicies != nil {
		t.Errorf(errPolicies.Error())
	}

}

func TestLicensePolicyMatchByFamilyNameBadExpression(t *testing.T) {
	// Assure OR appearance results in UNDEFINED
	NAME := "CC-BY-NC-1.0 OR Apache-2.0"
	EXPECTED_POLICY := POLICY_UNDEFINED

	value, policy := FindPolicyByFamilyName(NAME)
	getLogger().Tracef("policy: %v", policy)

	if value != EXPECTED_POLICY {
		t.Errorf("FindPolicyByFamilyName(): contains expression: %s, returned: %v; expected: %v", NAME, value, EXPECTED_POLICY)
	} else {
		getLogger().Tracef("FindPolicyByFamilyName(): contains expression: %s, policy: %s, ", NAME, value)
	}

	// Assure AND appearance results in UNDEFINED
	NAME = "CC-BY-NC-1.0 AND Apache-2.0"
	value, policy = FindPolicyByFamilyName(NAME)
	getLogger().Tracef("policy: %v", policy)

	if value != EXPECTED_POLICY {
		t.Errorf("FindPolicyByFamilyName(): contains expression: %s, returned: %v; expected: %v", NAME, value, EXPECTED_POLICY)
	} else {
		getLogger().Tracef("FindPolicyByFamilyName(): contains expression: %s, policy: %s, ", NAME, value)
	}

	// Assure WITH appearance results in UNDEFINED
	NAME = "CC-BY-NC-1.0 WITH some-clause"
	value, policy = FindPolicyByFamilyName(NAME)
	getLogger().Tracef("policy: %v", policy)

	if value != EXPECTED_POLICY {
		t.Errorf("FindPolicyByFamilyName(): contains expression: %s, returned: %v; expected: %v", NAME, value, EXPECTED_POLICY)
	} else {
		getLogger().Tracef("FindPolicyByFamilyName(): contains expression: %s, policy: %s, ", NAME, value)
	}
}
