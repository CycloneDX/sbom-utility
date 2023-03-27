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
	"reflect"
	"testing"
)

func innerTestLicenseExpressionParsing(t *testing.T, expression string, expectedPolicy string) (parsedExpression *CompoundExpression, err error) {
	parsedExpression, err = parseExpression(expression)
	getLogger().Infof("expression:\n%v", parsedExpression)
	if parsedExpression.CompoundUsagePolicy != expectedPolicy {
		t.Errorf("License Expression: expected `%s`, actual `%s`\n",
			expectedPolicy, parsedExpression.CompoundUsagePolicy)
	}
	return
}

// TODO: Need tests that include unary operators (e.g., AFL-2.0+)
// which is an outdated concept and replaced by newer approach as seen
// with GPL (e.g., GPL-2.0-or-later) using suffixes "or-later" or "only" (restrict)

func TestLicenseExpressionTokenizerWhitespaceRemoval(t *testing.T) {
	EXP := " Apache-2.0 	AND (	MIT OR     GPL-2.0-only ) "
	VALID := []string{"Apache-2.0", "AND", "(", "MIT", "OR", "GPL-2.0-only", ")"}

	tokens := tokenizeExpression(EXP)

	if !reflect.DeepEqual(tokens, VALID) {
		t.Errorf("tokenizeExpression(): returned: %v; expected: %v", tokens, VALID)
	} else {
		getLogger().Tracef("tokenizeExpression(): returned: %v; matched expected", tokens)
	}
}

func TestLicenseExpressionTokenizerWhitespaceNewlineTabRemoval(t *testing.T) {
	EXP := "\n\tApache-2.0 	\tAND (\n	MIT OR     GPL-2.0-only )\t\n"
	VALID := []string{"Apache-2.0", "AND", "(", "MIT", "OR", "GPL-2.0-only", ")"}

	tokens := tokenizeExpression(EXP)

	if !reflect.DeepEqual(tokens, VALID) {
		t.Errorf("tokenizeExpression(): returned: %v; expected: %v", tokens, VALID)
	} else {
		getLogger().Tracef("tokenizeExpression(): returned: %v; matched expected", tokens)
	}
}

// Tests for expression parser

func TestLicenseExpressionParsingTestComplex1(t *testing.T) {
	SPDX_LICENSE_EXPRESSION_TEST1 := "Apache-2.0 AND (MIT OR GPL-2.0-only)"
	EXPECTED_POLICY := POLICY_ALLOW
	result, _ := innerTestLicenseExpressionParsing(t, SPDX_LICENSE_EXPRESSION_TEST1, EXPECTED_POLICY)
	if result.LeftUsagePolicy != POLICY_ALLOW && result.RightUsagePolicy != POLICY_ALLOW {
		t.Errorf("License Expression: expectedLeft `%s`, actualLeft `%s`, expectedRight `%s`, actualRight `%s`\n",
			POLICY_ALLOW, result.LeftUsagePolicy, POLICY_ALLOW, result.RightUsagePolicy)
	}
}

func TestLicenseExpressionParsingTestComplex2(t *testing.T) {
	SPDX_LICENSE_EXPRESSION_TEST1 := "MPL-1.0 AND (MIT AND AGPL-3.0)"
	EXPECTED_POLICY := POLICY_NEEDS_REVIEW
	result, _ := innerTestLicenseExpressionParsing(t, SPDX_LICENSE_EXPRESSION_TEST1, EXPECTED_POLICY)
	if result.LeftUsagePolicy != POLICY_ALLOW && result.RightUsagePolicy != POLICY_ALLOW {
		t.Errorf("License Expression: expectedLeft `%s`, actualLeft `%s`, expectedRight `%s`, actualRight `%s`\n",
			POLICY_ALLOW, result.LeftUsagePolicy, POLICY_ALLOW, result.RightUsagePolicy)
	}
}

func TestLicenseExpressionParsingCompoundRightSide(t *testing.T) {
	EXP := "Apache-2.0 AND (MIT OR GPL-2.0-only )"
	EXPECTED_POLICY := POLICY_ALLOW
	innerTestLicenseExpressionParsing(t, EXP, EXPECTED_POLICY)
}

func TestLicenseExpressionCompoundLeftSide(t *testing.T) {
	EXP := "(Apache-1.0 OR Apache-1.1 ) AND 0BSD"
	EXPECTED_POLICY := POLICY_ALLOW
	innerTestLicenseExpressionParsing(t, EXP, EXPECTED_POLICY)
}

// Test license expression entirely inside a logical group (i.e., outer parens)
func TestLicenseExpressionSingleCompoundAllow(t *testing.T) {
	EXP := "(MIT OR CC0-1.0)"
	EXPECTED_POLICY := POLICY_ALLOW
	innerTestLicenseExpressionParsing(t, EXP, EXPECTED_POLICY)
}

func TestLicenseExpressionSingleCompoundUndefinedBoth(t *testing.T) {
	EXP := "(FOO OR BAR)"
	EXPECTED_POLICY := POLICY_UNDEFINED
	innerTestLicenseExpressionParsing(t, EXP, EXPECTED_POLICY)
}

func TestLicenseExpressionSingleCompoundUndefinedLeft(t *testing.T) {
	EXP := "(FOO OR MIT)"
	EXPECTED_POLICY := POLICY_ALLOW
	innerTestLicenseExpressionParsing(t, EXP, EXPECTED_POLICY)
}

func TestLicenseExpressionSingleCompoundUndefinedRight(t *testing.T) {
	EXP := "(MIT OR BAR)"
	EXPECTED_POLICY := POLICY_ALLOW
	innerTestLicenseExpressionParsing(t, EXP, EXPECTED_POLICY)
}

func TestLicenseExpressionSingleCompoundInvalid(t *testing.T) {
	EXP := "()"
	EXPECTED_POLICY := POLICY_UNDEFINED
	innerTestLicenseExpressionParsing(t, EXP, EXPECTED_POLICY)
}

func TestLicenseExpressionSingleCompoundInvalidAND(t *testing.T) {
	EXP := "AND"
	EXPECTED_POLICY := POLICY_UNDEFINED
	innerTestLicenseExpressionParsing(t, EXP, EXPECTED_POLICY)
}

func TestLicenseExpressionSingleCompoundInvalidOR(t *testing.T) {
	EXP := "OR"
	EXPECTED_POLICY := POLICY_UNDEFINED
	innerTestLicenseExpressionParsing(t, EXP, EXPECTED_POLICY)
}

func TestLicenseExpressionSingleCompoundInvalidAND2(t *testing.T) {
	EXP := "AND GPL-2.0-only"
	EXPECTED_POLICY := POLICY_UNDEFINED
	innerTestLicenseExpressionParsing(t, EXP, EXPECTED_POLICY)
}

func TestLicenseExpressionSingleCompoundInvalidOR2(t *testing.T) {
	EXP := "OR GPL-2.0-only"
	EXPECTED_POLICY := POLICY_NEEDS_REVIEW
	innerTestLicenseExpressionParsing(t, EXP, EXPECTED_POLICY)
}
