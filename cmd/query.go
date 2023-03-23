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
	"bytes"
	"encoding/gob"
	"fmt"
	"regexp"
	"strings"

	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/CycloneDX/sbom-utility/utils"
	"github.com/spf13/cobra"
)

// Query command flags
const (
	FLAG_OUTPUT_FORMAT  = "format"
	FLAG_QUERY_SELECT   = "select"
	FLAG_QUERY_FROM     = "from"
	FLAG_QUERY_WHERE    = "where"
	FLAG_QUERY_ORDER_BY = "orderby"
)

// Query command flag help messages
const (
	FLAG_QUERY_OUTPUT_FORMAT_HELP = "format output using the specified type"
	FLAG_QUERY_SELECT_HELP        = "comma-separated list of JSON key names used to select fields within the object designated by the FROM flag" +
		"\n- the wildcard character `*` can be used to denote inclusion of all found key-values"
	FLAG_QUERY_FROM_HELP = "dot-separated list of JSON key names used to dereference into the JSON document" +
		"\n - if not present, the query assumes document \"root\" as the `--from` object"
	FLAG_QUERY_WHERE_HELP    = "comma-separated list of key=<regex> used to filter the SELECT result set"
	FLAG_QUERY_ORDER_BY_HELP = "key name that appears in the SELECT result set used to order the result records"
)

// Named tokens
const (
	QUERY_TOKEN_WILDCARD       = "*"
	QUERY_FROM_CLAUSE_SEP      = "."
	QUERY_SELECT_CLAUSE_SEP    = ","
	QUERY_WHERE_EXPRESSION_SEP = ","
	QUERY_WHERE_OPERAND_EQUALS = "="
)

var QUERY_SUPPORTED_FORMATS = MSG_SUPPORTED_OUTPUT_FORMATS_HELP +
	strings.Join([]string{FORMAT_JSON}, ", ")

// query JSON map and return selected subset
// SELECT
//    <key.1>, <key.2>, ... // "firstname, lastname, email" || * (default)
// FROM
//    <key path>            // "product.customers"
// WHERE
//    <key.X> == <value>    // "country='Germany'"
// ORDER BY
//    <key.N>               // "lastname"
//
// e.g.,SELECT * FROM product.customers WHERE country="Germany";
type QueryRequest struct {
	selectFieldsRaw     string
	selectFields        []string
	fromObjectsRaw      string
	fromObjectSelectors []string
	whereValuesRaw      string
	whereExpressions    []string
	whereFilters        []WhereFilter
	orderByKeysRaw      string
	//orderByKeys       []string // TODO
	isFromObjectAMap    bool
	isFromObjectAnArray bool
}

type WhereFilter struct {
	key        string
	Operand    string
	Value      string
	ValueRegEx *regexp.Regexp
}

func (filter *WhereFilter) GetNormalizeKey() (normalizedKey string) {
	normalizedKey = strings.ToLower(filter.key)
	normalizedKey = strings.Replace(normalizedKey, "-", "", -1)
	return
}

// Implement the Stringer interface for QueryRequest
func (qr *QueryRequest) String() string {
	sb := new(strings.Builder)
	sb.WriteString(fmt.Sprintf("--select: %s\n", qr.selectFieldsRaw))
	sb.WriteString(fmt.Sprintf("--from: %s\n", qr.fromObjectsRaw))
	sb.WriteString(fmt.Sprintf("--where: %s\n", qr.whereValuesRaw))
	sb.WriteString(fmt.Sprintf("--orderby: %s\n", qr.orderByKeysRaw))
	return sb.String()
}

type QueryResponse struct {
	resultMap map[string]interface{}
}

func NewQueryResponse() *QueryResponse {
	qr := new(QueryResponse)
	qr.resultMap = make(map[string]interface{})
	return qr
}

func NewCommandQuery() *cobra.Command {
	var command = new(cobra.Command)
	command.Use = CMD_USAGE_QUERY
	command.Short = "Query objects and key-values from SBOM (JSON) document"
	command.Long = "SQL-like query (i.e. SELECT x,y FROM a.b.c WHERE x=<regex>) of JSON objects and specified fields from SBOM (JSON) document."
	command.RunE = queryCmdImpl
	command.PreRunE = func(cmd *cobra.Command, args []string) error {
		return preRunTestForInputFile(cmd, args)
	}
	initCommandQuery(command)
	return command
}

func initCommandQuery(command *cobra.Command) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Add local flags to command
	command.PersistentFlags().StringVar(&utils.GlobalFlags.OutputFormat, FLAG_OUTPUT_FORMAT, FORMAT_JSON,
		FLAG_QUERY_OUTPUT_FORMAT_HELP+QUERY_SUPPORTED_FORMATS)
	command.Flags().StringP(FLAG_QUERY_SELECT, "", QUERY_TOKEN_WILDCARD, FLAG_QUERY_SELECT_HELP)
	// NOTE: TODO: There appears to be a bug in Cobra where the type of the `from`` flag is `--from` (i.e., not string)
	// This bug does not exhibit on any other flags
	command.Flags().StringP(FLAG_QUERY_FROM, "", "", FLAG_QUERY_FROM_HELP)
	command.Flags().StringP(FLAG_QUERY_WHERE, "", "", FLAG_QUERY_WHERE_HELP)
	command.Flags().StringP(FLAG_QUERY_ORDER_BY, "", "", FLAG_QUERY_ORDER_BY_HELP)
}

// TODO: Support the --output <file> flag
// TODO: are there other output formats besides JSON (default)?
func queryCmdImpl(cmd *cobra.Command, args []string) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	// Parse flags into a query request struct
	var queryRequest *QueryRequest = new(QueryRequest)
	err = queryRequest.readQueryFlags(cmd)
	if err != nil {
		return
	}

	err = queryRequest.parseQueryClauses()
	if err != nil {
		return
	}

	// allocate the result structure
	var queryResult *QueryResponse = new(QueryResponse)

	// Query using the request/response structures
	result, errQuery := query(queryRequest, queryResult)

	if errQuery != nil {
		return errQuery
	}

	// Convert query results to formatted JSON for output
	fResult, errFormat := utils.ConvertMapToJson(result)

	if errFormat != nil {
		return errFormat
	}

	// Always, output the (JSON) formatted data directly to stdout (for now)
	// NOTE: This output is NOT subject to log-level settings; use `fmt` package
	// TODO: support --output to file
	fmt.Printf("%s\n", fResult)

	return
}

func (qr *QueryRequest) readQueryFlags(cmd *cobra.Command) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Read '--from` flag first as its result is required for any other field to operate on
	qr.fromObjectsRaw, err = cmd.Flags().GetString(FLAG_QUERY_FROM)
	if err != nil {
		getLogger().Tracef("Query: '%s' flag NOT found", FLAG_QUERY_FROM)
	} else {
		getLogger().Tracef("Query: '%s' flag found: %s", FLAG_QUERY_FROM, qr.fromObjectsRaw)
	}

	// Read '--select' flag second as it is the next highly likely field (used to
	// reduce the result set from querying the "FROM" JSON object)
	qr.selectFieldsRaw, err = cmd.Flags().GetString(FLAG_QUERY_SELECT)
	if err != nil {
		getLogger().Tracef("Query: '%s' flag NOT found", FLAG_QUERY_SELECT)
	} else {
		getLogger().Tracef("Query: '%s' flag found: %s", FLAG_QUERY_SELECT, qr.selectFieldsRaw)
	}

	// Read '--where' flag second as it is the next likely field
	// (used to further reduce the set of results from field value "matches"
	// as part of the SELECT processing)
	qr.whereValuesRaw, err = cmd.Flags().GetString(FLAG_QUERY_WHERE)
	if err != nil {
		getLogger().Tracef("Query: '%s' flag NOT found", FLAG_QUERY_WHERE)
	} else {
		getLogger().Tracef("Query: '%s' flag found: %s", FLAG_QUERY_WHERE, qr.whereValuesRaw)
	}

	// Read '--orderby' flag to be used to order by field (keys) data in the "output" phase
	qr.orderByKeysRaw, err = cmd.Flags().GetString(FLAG_QUERY_ORDER_BY)
	if err != nil {
		getLogger().Tracef("Query: '%s' flag NOT found", FLAG_QUERY_ORDER_BY)
	} else {
		getLogger().Tracef("Query: '%s' flag found: %s", FLAG_QUERY_ORDER_BY, qr.orderByKeysRaw)
	}

	return
}

func (qr *QueryRequest) parseQueryClauses() (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// parse out path (selectors) to JSON object from raw '--from' flag's value
	if qr.fromObjectsRaw != "" {
		qr.fromObjectSelectors = strings.Split(qr.fromObjectsRaw, QUERY_FROM_CLAUSE_SEP)
		getLogger().Tracef("FROM json object (path): %v\n", qr.fromObjectSelectors)
	}

	// parse out field (keys) from raw '--select' flag's value
	if qr.selectFieldsRaw != "" {
		qr.selectFields = strings.Split(qr.selectFieldsRaw, QUERY_SELECT_CLAUSE_SEP)
		getLogger().Tracef("SELECT keys (fields): %v\n", qr.selectFields)
	}

	// parse out `key=<regex>` filters from raw `-where` flag's value
	if qr.whereValuesRaw != "" {
		qr.whereExpressions = strings.Split(qr.whereValuesRaw, QUERY_WHERE_EXPRESSION_SEP)
		getLogger().Tracef("WHERE selectors (key=value): %v\n", qr.whereExpressions)
		err = qr.parseWhereFilterExpressions()
		// NOTE: we return here on error as more logic may follow for orderby
		if err != nil {
			return
		}
	}

	return
}

// Parse/validate each key=<regex> expression found on WHERE clause
func (qr *QueryRequest) parseWhereFilterExpressions() (err error) {

	if len(qr.whereExpressions) == 0 {
		return NewQueryWhereClauseError(qr, qr.whereValuesRaw)
	}

	var filter *WhereFilter
	for _, clause := range qr.whereExpressions {

		filter = parseWhereFilter(clause)

		if filter == nil {
			err = NewQueryWhereClauseError(qr, clause)
			return
		}

		qr.whereFilters = append(qr.whereFilters, *filter)
	}

	return
}

// TODO: generate more specific error messages on why parsing failed
func parseWhereFilter(rawExpression string) (pWhereSelector *WhereFilter) {

	if rawExpression == "" {
		return // nil
	}

	tokens := strings.Split(rawExpression, QUERY_WHERE_OPERAND_EQUALS)

	if len(tokens) != 2 {
		return // nil
	}

	var whereFilter = WhereFilter{}
	whereFilter.Operand = QUERY_WHERE_OPERAND_EQUALS
	whereFilter.key = tokens[0]
	whereFilter.Value = tokens[1]

	if whereFilter.Value == "" {
		return // nil
	}

	var errCompile error
	whereFilter.ValueRegEx, errCompile = compileRegex(whereFilter.Value)
	getLogger().Debugf(">> Regular expression: `%v`...", whereFilter.ValueRegEx)

	if errCompile != nil {
		return // nil
	}

	return &whereFilter
}

func processQueryResults(err error) {
	if err != nil {
		getLogger().Error(err)
	}
}

// query JSON map and return selected subset
// i.e., use QueryRequest (syntax) to implement the query into the JSON document
func query(request *QueryRequest, response *QueryResponse) (resultJson interface{}, err error) {
	getLogger().Enter()
	defer getLogger().Exit()
	// use function closure to assure consistent error output based upon error type
	defer func() {
		if err != nil {
			processQueryResults(err)
		}
	}()

	// Note: returns error if either file load or unmarshal to JSON map fails
	var document *schema.Sbom
	document, err = LoadInputSbomFileAndDetectSchema()

	if err != nil {
		return
	}

	// At this time, fail SPDX format SBOMs as "unsupported"
	if !document.FormatInfo.IsCycloneDx() {
		err = schema.NewUnsupportedFormatForCommandError(
			document.GetFilename(),
			document.FormatInfo.CanonicalName,
			CMD_QUERY, FORMAT_ANY)
		return
	}

	// Assure we have a map to dereference
	if document.GetJSONMap() == nil {
		err = fmt.Errorf(ERR_TYPE_INVALID_JSON_MAP)
		return
	}

	// Validate we have query request/response structs
	if request == nil {
		err = fmt.Errorf(MSG_QUERY_INVALID_REQUEST)
		return
	}

	if response == nil {
		err = fmt.Errorf(MSG_QUERY_INVALID_RESPONSE)
		return
	}

	// Query set of FROM objects
	// if a FROM select object is not provided, assume "root" search
	if len(request.fromObjectSelectors) == 0 {
		getLogger().Tracef("request object FROM selector empty; assume query uses document \"root\".")
	}

	resultJson, err = findFromObject(request, document.GetJSONMap())
	if err != nil {
		return
	}

	// SELECT specific fields from the FROM object(s)
	// logic varies depending on data type of FROM object (i.e., map or slice)
	switch t := resultJson.(type) {
	case map[string]interface{}:
		// TODO: return this (map) output instead of the one from the "find" stage
		resultJson, err = selectFieldsFromMap(request, resultJson.(map[string]interface{}))
		if err != nil {
			return
		}
		// Warn WHERE clause cannot be applied; still return values (for now)
		if request.whereValuesRaw != "" {
			getLogger().Warningf("Cannot apply WHERE filter to a singleton FROM object (%s)",
				request.fromObjectsRaw)
		}
	case []interface{}:
		fromObjectSlice, _ := resultJson.([]interface{})
		// TODO: resultJson, err = selectFieldsFromSlice(request, findObject)
		resultJson, err = selectFieldsFromSlice(request, fromObjectSlice)
	default:
		// NOTE: this SHOULD never be invoked as the FROM logic should have caught this already
		err = NewQueryFromClauseError(request,
			fmt.Sprintf("%s: %T", MSG_QUERY_INVALID_DATATYPE, t))
		return
	}

	if err != nil {
		//getLogger().Debugf("%v, %v", pJsonData, err)
		return
	}

	return
}

func findFromObject(request *QueryRequest, jsonMap map[string]interface{}) (pResults interface{}, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// initialize local map pointer and return value to starting JSON map
	var tempMap map[string]interface{} = jsonMap
	pResults = jsonMap
	request.isFromObjectAMap = true

	getLogger().Tracef("Finding JSON object using path key(s): %v\n", request.fromObjectSelectors)

	for i, key := range request.fromObjectSelectors {
		pResults = tempMap[key]

		// if we find a nil value, this means we failed to find the object
		if pResults == nil {
			err = NewQueryError(
				request,
				MSG_QUERY_INVALID_FROM_CLAUSE,
				fmt.Sprintf("%s: (%s)", MSG_QUERY_ERROR_FROM_KEY_NOT_FOUND, key))
			return
		}

		switch t := pResults.(type) {
		case map[string]interface{}:
			// If the resulting value is indeed another map type, we expect for a Json Map
			// we preserve that pointer for the next iteration
			request.isFromObjectAMap = true
			tempMap = pResults.(map[string]interface{})
		case []interface{}:
			// TODO: We only support an array (i.e., []interface{}) as the last selector
			// in theory, we could support arrays (perhaps array notation) in the FROM clause
			// at any point (e.g., "metadata.component.properties[0]").
			// we should still be able to support implicit arrays as well.
			request.isFromObjectAnArray = true
			// We no longer have a map to dereference into
			// So if there are more keys left as selectors it is an error
			if len(request.fromObjectSelectors) > i+1 {
				err = NewQueryFromClauseError(request,
					fmt.Sprintf("%s: (%s)", MSG_QUERY_ERROR_FROM_KEY_SLICE_DEREFERENCE, key))
				return
			}
		default:
			getLogger().Debugf("Invalid datatype of query: key: %s (%t)", key, t)
			err = NewQueryError(
				request,
				MSG_QUERY_INVALID_DATATYPE,
				fmt.Sprintf("%s: (%s)", MSG_QUERY_ERROR_FROM_KEY_INVALID_OBJECT, key))
			return
		}
	}
	return
}

// NOTE: it is the caller's responsibility to convert to other output formats
// based upon other flag values
func selectFieldsFromMap(request *QueryRequest, jsonMap map[string]interface{}) (mapSelectedFields map[string]interface{}, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	selectors := request.selectFields

	// Default to wildcard behavior
	// NOTE: The default set by the CLI framework SHOULD be QUERY_TOKEN_WILDCARD
	if len(selectors) == 0 {
		return jsonMap, nil
	}

	// Check for wildcard; if it is the only selector, return
	if len(selectors) == 1 && selectors[0] == QUERY_TOKEN_WILDCARD {
		return jsonMap, nil
	}

	// allocate map to hold selected fields
	mapSelectedFields = make(map[string]interface{})

	// copy selected fields into output map
	for _, fieldKey := range selectors {
		// validate wildcard not used with other fields; if so, that is a conflict
		if fieldKey == QUERY_TOKEN_WILDCARD {
			err = NewQueryError(
				request,
				MSG_QUERY_INVALID_SELECT_CLAUSE,
				MSG_QUERY_ERROR_SELECT_WILDCARD)
			getLogger().Trace(err)
			return
		}

		mapSelectedFields[fieldKey] = jsonMap[fieldKey]
	}

	return
}

// NOTE: it is the caller's responsibility to convert to other output formats
// based upon other flag values
func selectFieldsFromSlice(request *QueryRequest, jsonSlice []interface{}) (sliceSelectedFields []interface{}, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	whereFilters := request.whereFilters
	getLogger().Debugf("whereFilters: %v", whereFilters)

	for _, iObject := range jsonSlice {
		mapObject, ok := iObject.(map[string]interface{})

		if !ok {
			err = getLogger().Errorf("Unable to convert object: %v, to map[string]interface{}", iObject)
			return
		}

		match, errMatch := whereFilterMatch(mapObject, whereFilters)

		if errMatch != nil {
			err = errMatch
			return
		}

		// If ALL WHERE filters matched the regexp. provided,
		// add the entirety of the matching object to the (selected) result set
		if match {
			mapObject, err = selectFieldsFromMap(request, mapObject)
			// Reduce result object to only the requested SELECT fields
			sliceSelectedFields = append(sliceSelectedFields, mapObject)
		}
	}

	return
}

// Note: Golang supports the RE2 regular exp. engine which does not support many
// features such as lookahead, lookbehind, etc.
// See: https://en.wikipedia.org/wiki/Comparison_of_regular_expression_engines
func whereFilterMatch(mapObject map[string]interface{}, whereFilters []WhereFilter) (match bool, err error) {
	var buf bytes.Buffer
	var key string

	// create a byte encoder
	enc := gob.NewEncoder(&buf)

	for _, filter := range whereFilters {

		key = filter.key
		value, present := mapObject[key]
		getLogger().Tracef("testing object map[%s]: `%v`", key, value)

		if !present {
			match = false
			err = getLogger().Errorf("key `%s` not found ib object map", key)
			break
		}

		// Reset the encoder'a byte buffer on each iteration and
		// convert the value (an interface{}) to []byte we can use on regex. eval.
		buf.Reset()
		err = enc.Encode(value)

		if err != nil {
			err = getLogger().Errorf("Unable to convert value: `%v`, to []byte", value)
			return
		}

		// Test that the field value matches the regex supplied in the current filter
		// Note: the regex compilation is performed during command param. processing
		if match = filter.ValueRegEx.Match(buf.Bytes()); !match {
			break
		}
	}

	return
}
