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

package schema

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

// -----------------------------------
// Usage Policy: allowed value tests
// -----------------------------------
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
