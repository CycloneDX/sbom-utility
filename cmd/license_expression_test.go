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

func TestLicenseExpressionParsingTestBasic(t *testing.T) {
	SPDX_LICENSE_EXPRESSION_TEST1 := "Apache-2.0 AND (MIT OR GPL-2.0-only)"
	result, _ := parseExpression(SPDX_LICENSE_EXPRESSION_TEST1)
	json := getLogger().FormatStruct(result)
	getLogger().Infof("expression:\n%s", json)
}

func TestLicenseExpressionParsingCompoundRightSide(t *testing.T) {
	EXP := "Apache-2.0 AND (MIT OR GPL-2.0-only )"
	parsedExpression, _ := parseExpression(EXP)
	getLogger().Infof("expression:\n%v", parsedExpression)
}

func TestLicenseExpressionCompoundLeftSide(t *testing.T) {
	EXP := "(Apache-1.0 OR Apache-1.1 ) AND 0BSD"
	parsedExpression, _ := parseExpression(EXP)
	getLogger().Infof("expression:\n%v", parsedExpression)
}

// Test license expression entirely inside a logical group (i.e., outer parens)
func TestLicenseExpressionSingleCompoundAllow(t *testing.T) {
	EXP := "(MIT OR CC0-1.0)"
	parsedExpression, _ := parseExpression(EXP)
	getLogger().Infof("expression:\n%v", parsedExpression)
}

func TestLicenseExpressionSingleCompoundUndefinedBoth(t *testing.T) {
	EXP := "(FOO OR BAR)"
	parsedExpression, _ := parseExpression(EXP)
	getLogger().Infof("expression:\n%v", parsedExpression)
}

func TestLicenseExpressionSingleCompoundUndefinedLeft(t *testing.T) {
	EXP := "(FOO OR MIT)"
	parsedExpression, _ := parseExpression(EXP)
	getLogger().Infof("expression:\n%v", parsedExpression)
}

func TestLicenseExpressionSingleCompoundUndefinedRight(t *testing.T) {
	EXP := "(MIT OR BAR)"
	parsedExpression, _ := parseExpression(EXP)
	getLogger().Infof("expression:\n%v", parsedExpression)
}
