// SPDX-License-Identifier: Apache-2.0
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

package common

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/CycloneDX/sbom-utility/utils"
)

// Named tokens
const (
	QUERY_TOKEN_WILDCARD       = "*"
	QUERY_FROM_CLAUSE_SEP      = "."
	QUERY_SELECT_CLAUSE_SEP    = ","
	QUERY_WHERE_EXPRESSION_SEP = ","
	QUERY_WHERE_OPERAND_EQUALS = "="
)

// ==================================================================
// QueryRequest
// ==================================================================

// query JSON map and return selected subset using SQL-like syntax:
// SELECT: <key.1>, <key.2>, ... // "firstname, lastname, email" || * (default)
// FROM: <key path>              // "product.customers"
// WHERE: <key.X> == <value>     // "country='Germany'"
// ORDERBY: <key.N>              // "lastname"
// e.g.,SELECT * FROM product.customers WHERE country="Germany";
type QueryRequest struct {
	selectKeysRaw      string
	selectKeys         []string
	fromPathsRaw       string
	fromPathSelectors  []string
	wherePredicatesRaw string
	wherePredicates    []string
	whereFilters       []WhereFilter
	orderByKeysRaw     string
	//orderByKeys       []string // TODO
}

// Implement the Stringer interface for QueryRequest
func (qr *QueryRequest) String() string {
	buffer, _ := utils.EncodeAnyToIndentedJSON(qr, utils.DEFAULT_JSON_INDENT_STRING)
	return buffer.String()
}

func (qr *QueryRequest) StringAsParameters() string {
	sb := new(strings.Builder)
	sb.WriteString(fmt.Sprintf("--select: %s\n", qr.selectKeysRaw))
	sb.WriteString(fmt.Sprintf("--from: %s\n", qr.fromPathsRaw))
	sb.WriteString(fmt.Sprintf("--where: %s\n", qr.wherePredicatesRaw))
	sb.WriteString(fmt.Sprintf("--orderby: %s\n", qr.orderByKeysRaw))
	return sb.String()
}

func NewQueryRequest() (qr *QueryRequest) {
	qr = new(QueryRequest)
	return
}

func NewQueryRequestSelectFromWhere(rawSelect string, rawFrom string, rawWhere string) (qr *QueryRequest, err error) {
	qr = new(QueryRequest)
	qr.selectKeysRaw = rawSelect
	qr.fromPathsRaw = rawFrom
	qr.wherePredicatesRaw = rawWhere
	err = qr.parseQueryClauses()
	return
}

func NewQueryRequestSelectFrom(rawSelect string, rawFrom string) (qr *QueryRequest, err error) {
	return NewQueryRequestSelectFromWhere(rawSelect, rawFrom, "")
}

func NewQueryRequestSelectWildcardFrom(rawFrom string) (qr *QueryRequest, err error) {
	return NewQueryRequestSelectFromWhere(QUERY_TOKEN_WILDCARD, rawFrom, "")
}

func NewQueryRequestSelectWildcardFromWhere(rawFrom string, rawWhere string) (qr *QueryRequest, err error) {
	return NewQueryRequestSelectFromWhere(QUERY_TOKEN_WILDCARD, rawFrom, rawWhere)
}

// ------------
// SELECT
// ------------

// parse out field (keys) from raw '--select' flag's value
func ParseSelectKeys(rawSelectKeys string) (selectKeys []string) {
	if rawSelectKeys != "" {
		selectKeys = strings.Split(rawSelectKeys, QUERY_SELECT_CLAUSE_SEP)
	}
	//getLogger().Tracef("SELECT keys: %v\n", selectKeys)
	return
}

func (qr *QueryRequest) SetRawSelectKeys(rawSelectKeys string) []string {
	qr.selectKeysRaw = rawSelectKeys
	// Note: it is an intentional side-effect to update the parsed, slice version
	qr.selectKeys = ParseSelectKeys(rawSelectKeys)
	return qr.selectKeys
}

func (qr *QueryRequest) GetSelectKeys() []string {
	return qr.selectKeys
}

// ------------
// FROM
// ------------

// parse out field (keys) from raw '--select' flag's value
func ParseFromPaths(rawFromPaths string) (fromPaths []string) {
	if rawFromPaths != "" {
		fromPaths = strings.Split(rawFromPaths, QUERY_FROM_CLAUSE_SEP)
	}
	//getLogger().Tracef("FROM paths: %v\n", fromPaths)
	return
}

func (qr *QueryRequest) SetRawFromPaths(rawFromPaths string) []string {
	qr.fromPathsRaw = rawFromPaths
	// Note: it is an intentional side-effect to update the parsed, slice version
	qr.fromPathSelectors = ParseFromPaths(rawFromPaths)
	return qr.fromPathSelectors
}

func (qr *QueryRequest) GetFromKeys() []string {
	return qr.fromPathSelectors
}

// ------------
// WHERE
// ------------

// parse out `key=<regex>` predicates from the raw `--where` flag's value
func ParseWherePredicates(rawWherePredicates string) (wherePredicates []string) {
	if rawWherePredicates != "" {
		wherePredicates = strings.Split(rawWherePredicates, QUERY_WHERE_EXPRESSION_SEP)
	}
	//getLogger().Tracef("WHERE predicates: %v\n", wherePredicates)
	return
}

func ParseWhereFilters(wherePredicates []string) (whereFilters []WhereFilter, err error) {
	if len(wherePredicates) == 0 {
		return
	}

	var filter *WhereFilter
	for _, predicate := range wherePredicates {

		filter = ParseWhereFilter(predicate)

		if filter == nil {
			err = NewQueryWhereClauseError(nil, predicate)
			return
		}

		whereFilters = append(whereFilters, *filter)
	}

	return
}

// TODO: generate more specific error messages on why parsing failed
func ParseWhereFilter(rawExpression string) (pWhereSelector *WhereFilter) {

	if rawExpression == "" {
		return // nil
	}

	tokens := strings.Split(rawExpression, QUERY_WHERE_OPERAND_EQUALS)

	if len(tokens) != 2 {
		return // nil
	}

	var whereFilter = WhereFilter{}
	whereFilter.Operand = QUERY_WHERE_OPERAND_EQUALS
	whereFilter.Key = tokens[0]
	whereFilter.Value = tokens[1]

	if whereFilter.Value == "" {
		return // nil
	}

	var errCompile error
	whereFilter.ValueRegEx, errCompile = utils.CompileRegex(whereFilter.Value)
	//getLogger().Debugf(">> Regular expression: `%v`...", whereFilter.ValueRegEx)

	if errCompile != nil {
		return // nil
	}

	return &whereFilter
}

func (qr *QueryRequest) GetWhereFilters() ([]WhereFilter, error) {
	if len(qr.wherePredicates) == 0 && qr.wherePredicatesRaw != "" {
		// TODO: consider if we really need error handling
		err := qr.parseWhereFilterClauses()
		if err != nil {
			return nil, err
		}
	}
	return qr.whereFilters, nil
}

func (qr *QueryRequest) SetRawWherePredicates(rawWherePredicates string) []WhereFilter {
	qr.wherePredicatesRaw = rawWherePredicates
	// Note: it is an intentional side-effect to update the parsed, slice versions
	// of the predicates as well as the  subsequent filters.
	qr.wherePredicates = ParseWherePredicates(qr.wherePredicatesRaw)
	// TODO: implement a getLogger() and log (and perhaps return) the parsing error
	qr.whereFilters, _ = ParseWhereFilters(qr.wherePredicates)
	return qr.whereFilters
}

// --------------
// Other helpers
// --------------

// Parse command-line flag values including:
// --select <clause> --from <clause> and --where <clause>
func (qr *QueryRequest) parseQueryClauses() (err error) {
	qr.selectKeys = ParseSelectKeys(qr.selectKeysRaw)
	qr.fromPathSelectors = ParseFromPaths(qr.fromPathsRaw)
	qr.wherePredicates = ParseWherePredicates(qr.wherePredicatesRaw)
	qr.whereFilters, err = ParseWhereFilters(qr.wherePredicates)
	return
}

// Parse/validate each key=<regex> expression found on WHERE clause
func (qr *QueryRequest) parseWhereFilterClauses() (err error) {
	if len(qr.wherePredicates) == 0 {
		return NewQueryWhereClauseError(qr, qr.wherePredicatesRaw)
	}

	var filter *WhereFilter
	for _, predicate := range qr.wherePredicates {

		filter = ParseWhereFilter(predicate)

		if filter == nil {
			err = NewQueryWhereClauseError(qr, predicate)
			return
		}

		qr.whereFilters = append(qr.whereFilters, *filter)
	}

	return
}

// ==================================================================
// QueryResponse
// ==================================================================
type QueryResponse struct {
	resultMap map[string]interface{}
}

// Implement the Stringer interface for QueryRequest
func (qr *QueryResponse) String() string {
	buffer, _ := utils.EncodeAnyToIndentedJSON(qr, utils.DEFAULT_JSON_INDENT_STRING)
	return buffer.String()
}

func NewQueryResponse() *QueryResponse {
	qr := new(QueryResponse)
	qr.resultMap = make(map[string]interface{})
	return qr
}

// ==================================================================
// WhereFilter
// ==================================================================
type WhereFilter struct {
	Key        string
	Operand    string
	Value      string
	ValueRegEx *regexp.Regexp
}

// Implement the Stringer interface for QueryRequest
func (filter *WhereFilter) String() string {
	buffer, _ := utils.EncodeAnyToIndentedJSON(filter, utils.DEFAULT_JSON_INDENT_STRING)
	return buffer.String()
}

// Note: Used to normalize key lookups in maps accounting for changes in
// key names on CDX structures created from annotations during JSON unmarshal
// TODO: unused as of now, as we opted to use CycloneDX keys as they appear
// in schema (for now)
func (filter *WhereFilter) GetNormalizedMapKey() (normalizedKey string) {
	normalizedKey = strings.ToLower(filter.Key)
	// Note: accounts for changes in JSON annotations (e.g., "bom-ref", etc.)
	normalizedKey = strings.Replace(normalizedKey, "-", "", -1)
	return
}
