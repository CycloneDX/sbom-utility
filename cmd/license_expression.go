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
	"strings"
)

// Supported conjunctions and prepositions
const (
	AND                   string = "AND"
	OR                    string = "OR"
	WITH                  string = "WITH"
	CONJUNCTION_UNDEFINED string = ""
)

// Tokens
const (
	LEFT_PARENS                 string = "("
	RIGHT_PARENS                string = ")"
	LEFT_PARENS_WITH_SEPARATOR  string = "( "
	RIGHT_PARENS_WITH_SEPARATOR string = " )"
	PLUS_OPERATOR               string = "+"
)

type CompoundExpression struct {
	SimpleLeft          string
	SimpleLeftHasPlus   bool
	LeftPolicy          LicensePolicy
	LeftUsagePolicy     string
	SimpleRight         string
	SimpleRightHasPlus  bool
	RightPolicy         LicensePolicy
	RightUsagePolicy    string
	Conjunction         string
	PrepRight           string
	PrepLeft            string
	CompoundLeft        *CompoundExpression
	CompoundRight       *CompoundExpression
	CompoundUsagePolicy string
}

func HasLogicalConjunctionOrPreposition(value string) bool {

	if strings.Contains(value, AND) ||
		strings.Contains(value, OR) ||
		strings.Contains(value, WITH) {
		return true
	}
	return false
}

func NewCompoundExpression() *CompoundExpression {
	ce := new(CompoundExpression)
	ce.LeftUsagePolicy = POLICY_UNDEFINED
	ce.RightUsagePolicy = POLICY_UNDEFINED
	ce.CompoundUsagePolicy = POLICY_UNDEFINED
	return ce
}

func tokenizeExpression(expression string) (tokens []string) {
	// Add spaces to assure proper tokenization with whitespace bw/ tokens
	expression = strings.ReplaceAll(expression, LEFT_PARENS, LEFT_PARENS_WITH_SEPARATOR)
	expression = strings.ReplaceAll(expression, RIGHT_PARENS, RIGHT_PARENS_WITH_SEPARATOR)
	// fields are, by default, separated by whitespace
	tokens = strings.Fields(expression)
	return
}

func parseExpression(rawExpression string) (ce *CompoundExpression, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	ce = NewCompoundExpression()

	tokens := tokenizeExpression(rawExpression)
	getLogger().Debugf("Tokens: %v", tokens)

	finalIndex, err := parseCompoundExpression(ce, tokens, 0)
	getLogger().Debugf("Parsed expression (%v): %v", finalIndex, ce)

	return ce, err
}

// NOTE: This expression parser does not account for multiple (>1) conjunctions
// within a compound expression; however, this has not been endorsed by
// the specification or any known examples
func parseCompoundExpression(expression *CompoundExpression, tokens []string, index int) (i int, err error) {
	getLogger().Enter("expression:", expression)
	defer getLogger().Exit()
	var token string
	for index < len(tokens) {
		token = tokens[index]
		switch token {
		case LEFT_PARENS:
			getLogger().Debugf("[%v] LEFT_PARENS: `%v`", index, token)
			childExpression := NewCompoundExpression()

			// if we have no conjunction, this compound expression represents the "left" operand
			if expression.Conjunction == "" {
				expression.CompoundLeft = childExpression
			} else {
				// otherwise it is the "right" operand
				expression.CompoundRight = childExpression
			}

			index, err = parseCompoundExpression(childExpression, tokens, index+1)

			// retrieve the resolved policy from the child
			childPolicy := childExpression.CompoundUsagePolicy
			if expression.Conjunction == "" {
				expression.LeftUsagePolicy = childPolicy
			} else {
				// otherwise it is the "right" operand
				expression.RightUsagePolicy = childPolicy
			}

		case RIGHT_PARENS:
			getLogger().Debugf("[%v] RIGHT_PARENS: `%v`", index, token)
			err = FinalizeCompoundPolicy(expression)
			return index, err // Do NOT Increment, parent caller will do that
		case AND:
			getLogger().Debugf("[%v] AND (Conjunction): `%v`", index, token)
			expression.Conjunction = token
		case OR:
			getLogger().Debugf("[%v] OR (Conjunction): `%v`", index, token)
			expression.Conjunction = token
		case WITH:
			getLogger().Debugf("[%v] WITH (Preposition): `%v`", index, token)
			if expression.Conjunction == "" {
				expression.PrepLeft = token
			} else {
				// otherwise it is the "right" operand
				expression.PrepRight = token
			}
		default:
			getLogger().Debugf("[%v] Simple Expression: `%v`", index, token)
			// if we have no conjunction, this compound expression represents the "left" operand
			if expression.Conjunction == "" {
				if expression.PrepLeft == "" {
					expression.SimpleLeft = token
					// Also, check for the unary "plus" operator
					expression.SimpleLeftHasPlus = hasUnaryPlusOperator(token)
					// Lookup policy in hashmap
					expression.LeftUsagePolicy, expression.LeftPolicy = FindPolicyBySpdxId(token)
				} else {
					// this token is a preposition, for now overload its value
					expression.PrepLeft = token
				}
			} else {
				// otherwise it is the "right" operand
				if expression.PrepRight == "" {
					expression.SimpleRight = token
					// Also, check for the unary "plus" operator
					expression.SimpleRightHasPlus = hasUnaryPlusOperator(token)
					// Lookup policy in hashmap
					expression.RightUsagePolicy, expression.RightPolicy = FindPolicyBySpdxId(token)
				} else {
					// this token is a preposition, for now overload its value
					expression.PrepRight = token
				}
			}
		}

		index = index + 1
	}

	err = FinalizeCompoundPolicy(expression)
	return index, err
}

func FinalizeCompoundPolicy(expression *CompoundExpression) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Short-circuit of either left or right policies resolved to UNDEFINED
	if expression.LeftUsagePolicy == POLICY_UNDEFINED ||
		expression.RightUsagePolicy == POLICY_UNDEFINED {
		expression.CompoundUsagePolicy = POLICY_UNDEFINED
		return nil
	}

	// The policy config. has 3 states: { "allow", "deny", "needs-review" }; n=3
	// which are always paired with a conjunctions; r=2
	// and for evaluation, we do not care about order.  This means we have to
	// account for 6 combinations with unique results (policy determinations)
	switch expression.Conjunction {
	// The AND case, is considered "pessimistic"; that is, we want to quickly identify "negative" usage policies.
	// This means we first look for any "deny" policy as this overrides any other state's value
	// then look for any "needs-review" policy as we assume it COULD be a "deny" determination upon review
	// this leaves the remaining state which is "allow" (both sides) as the only "positive" outcome
	case AND:
		// This "deny" comparator block covers 3 of the 6 combinations:
		// 1. POLICY_DENY AND POLICY_ALLOW
		// 2. POLICY_DENY AND POLICY_NEEDS_REVIEW
		// 3. POLICY_DENY AND POLICY_DENY
		if expression.LeftUsagePolicy == POLICY_DENY ||
			expression.RightUsagePolicy == POLICY_DENY {
			expression.CompoundUsagePolicy = POLICY_DENY
		} else if expression.LeftUsagePolicy == POLICY_NEEDS_REVIEW ||
			expression.RightUsagePolicy == POLICY_NEEDS_REVIEW {
			// This "needs-review" comparator covers 2 of the 6 combinations:
			// 4. POLICY_NEEDS_REVIEW AND POLICY_ALLOW
			// 5. POLICY_NEEDS_REVIEW AND POLICY_NEEDS_REVIEW
			expression.CompoundUsagePolicy = POLICY_NEEDS_REVIEW
		} else {
			// This leaves the only remaining combination:
			// 6. POLICY_ALLOW AND POLICY_ALLOW
			expression.CompoundUsagePolicy = POLICY_ALLOW
		}
	// The OR case, is considered "optimistic"; that is, we want to quickly identify "positive" usage policies.
	// This means we first look for any "allow" policy as this overrides any other state's value
	// then look for any "needs-review" policy as we assume it COULD be an "allow" determination upon review
	// this leaves the remaining state which is "allow" (both sides) as the only "positive" outcome
	case OR:
		// This "allow" comparator block covers 3 of the 6 combinations:
		// 1. POLICY_ALLOW OR POLICY_DENY
		// 2. POLICY_ALLOW OR POLICY_NEEDS_REVIEW
		// 3. POLICY_ALLOW OR POLICY_ALLOW
		if expression.LeftUsagePolicy == POLICY_ALLOW ||
			expression.RightUsagePolicy == POLICY_ALLOW {
			expression.CompoundUsagePolicy = POLICY_ALLOW
		} else if expression.LeftUsagePolicy == POLICY_NEEDS_REVIEW ||
			expression.RightUsagePolicy == POLICY_NEEDS_REVIEW {
			// This "needs-review" comparator covers 2 of the 6 combinations:
			// 4. POLICY_NEEDS_REVIEW OR POLICY_DENY
			// 5. POLICY_NEEDS_REVIEW OR POLICY_NEEDS_REVIEW
			expression.CompoundUsagePolicy = POLICY_NEEDS_REVIEW
		} else {
			// This leaves the only remaining combination:
			// 6. POLICY_DENY OR POLICY_DENY
			expression.CompoundUsagePolicy = POLICY_DENY
		}
	default:
		expression.CompoundUsagePolicy = POLICY_UNDEFINED
		return getLogger().Errorf("%s: %s: `%s`",
			MSG_LICENSE_INVALID_EXPRESSION,
			MSG_LICENSE_EXPRESSION_INVALID_CONJUNCTION,
			expression.Conjunction)

	}
	getLogger().Debugf("(%s (%s) %s %s (%s)) == %s",
		expression.SimpleLeft,
		expression.LeftUsagePolicy,
		expression.Conjunction,
		expression.SimpleRight,
		expression.RightUsagePolicy,
		expression.CompoundUsagePolicy)

	return nil
}

func hasUnaryPlusOperator(simpleExpression string) bool {
	getLogger().Enter()
	defer getLogger().Exit()
	return strings.HasSuffix(simpleExpression, PLUS_OPERATOR)
}
