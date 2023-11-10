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
	"io"
	"strconv"
	"strings"

	"github.com/CycloneDX/sbom-utility/common"
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
	FLAG_QUERY_WHERE_HELP    = "comma-separated list of key=<regex> of clauses used to filter the SELECT result set"
	FLAG_QUERY_ORDER_BY_HELP = "key name that appears in the SELECT result set used to order the result records"
)

var QUERY_SUPPORTED_FORMATS = MSG_SUPPORTED_OUTPUT_FORMATS_HELP +
	strings.Join([]string{FORMAT_JSON}, ", ")

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
	command.PersistentFlags().StringVar(&utils.GlobalFlags.PersistentFlags.OutputFormat, FLAG_OUTPUT_FORMAT, FORMAT_JSON,
		FLAG_QUERY_OUTPUT_FORMAT_HELP+QUERY_SUPPORTED_FORMATS)
	command.Flags().StringP(FLAG_QUERY_SELECT, "", common.QUERY_TOKEN_WILDCARD, FLAG_QUERY_SELECT_HELP)
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

	// Create output writer
	outputFilename := utils.GlobalFlags.PersistentFlags.OutputFile
	outputFile, writer, err := createOutputFile(outputFilename)
	getLogger().Tracef("outputFile: `%v`; writer: `%v`", outputFilename, writer)

	// use function closure to assure consistent error output based upon error type
	defer func() {
		// always close the output file
		if outputFile != nil {
			outputFile.Close()
			getLogger().Infof("Closed output file: `%s`", outputFilename)
		}
	}()

	// Parse flags into a query request struct
	var queryRequest *common.QueryRequest
	queryRequest, err = readQueryFlags(cmd)
	if err != nil {
		return
	}

	// allocate the result structure
	var queryResult *common.QueryResponse = new(common.QueryResponse)

	// Query using the request/response structures
	_, errQuery := Query(writer, queryRequest, queryResult)

	if errQuery != nil {
		return errQuery
	}

	return
}

func readQueryFlags(cmd *cobra.Command) (qr *common.QueryRequest, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Read '--select' flag second as it is the next highly likely field (used to
	// reduce the result set from querying the "FROM" JSON object)
	rawSelect, errGetString := cmd.Flags().GetString(FLAG_QUERY_SELECT)
	getLogger().Tracef("Query: '%s' flag: %s, err: %s", FLAG_QUERY_SELECT, rawSelect, errGetString)

	// Read '--from` flag first as its result is required for any other field to operate on
	rawFrom, errGetString := cmd.Flags().GetString(FLAG_QUERY_FROM)
	getLogger().Tracef("Query: '%s' flag: %s, err: %s", FLAG_QUERY_FROM, rawFrom, errGetString)

	// Read '--where' flag second as it is the next likely field
	// (used to further reduce the set of results from field value "matches"
	// as part of the SELECT processing)
	rawWhere, errGetString := cmd.Flags().GetString(FLAG_QUERY_WHERE)
	getLogger().Tracef("Query: '%s' flag: %s, err: %s", FLAG_QUERY_WHERE, rawWhere, errGetString)

	// TODO: Read '--orderby' flag to be used to order by field (keys) data in the "output" phase
	//rawOrderBy, errGetString := cmd.Flags().GetString(FLAG_QUERY_ORDER_BY)
	//getLogger().Tracef("Query: '%s' flag: %s, err: %s", FLAG_QUERY_ORDER_BY, rawOrderBy, errGetString)

	qr, err = common.NewQueryRequestSelectFromWhere(rawSelect, rawFrom, rawWhere)

	return
}

func processQueryResults(err error) {
	if err != nil {
		getLogger().Error(err)
	}
}

// Query JSON map and return selected subset
// i.e., use QueryRequest (syntax) to implement the Query into the JSON document
func Query(writer io.Writer, request *common.QueryRequest, response *common.QueryResponse) (resultJson interface{}, err error) {
	getLogger().Enter()
	defer getLogger().Exit()
	// use function closure to assure consistent error output based upon error type
	defer func() {
		if err != nil {
			processQueryResults(err)
		}
	}()

	// Note: returns error if either file load or unmarshal to JSON map fails
	var document *schema.BOM
	document, err = LoadInputBOMFileAndDetectSchema()

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
	if len(request.GetFromKeys()) == 0 {
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
		whereFilters, _ := request.GetWhereFilters()
		if len(whereFilters) > 0 {
			getLogger().Warningf("Cannot apply WHERE filter (%v) to a singleton FROM object (%v)",
				whereFilters,
				request.GetFromKeys())
		}
	case []interface{}:
		fromObjectSlice, _ := resultJson.([]interface{})
		resultJson, err = selectFieldsFromSlice(request, fromObjectSlice)
	default:
		// NOTE: this SHOULD never be invoked as the FROM logic should have caught this already
		err = common.NewQueryFromClauseError(request,
			fmt.Sprintf("%s: %T", MSG_QUERY_INVALID_DATATYPE, t))
		return
	}

	if err != nil {
		return
	}

	// Convert query results to formatted JSON for output
	// TODO: we MAY want to use a JSON Encoder to avoid unicode encoding
	fResult, err := utils.MarshalAnyToFormattedJsonString(resultJson)
	if err != nil {
		getLogger().Tracef("error: %s", err)
		return
	}

	// Use the selected output device (e.g., default stdout or the specified --output-file)
	fmt.Fprintf(writer, "%s\n", fResult)

	return
}

func QueryJSONMap(jsonMap map[string]interface{}, request *common.QueryRequest) (resultJson interface{}, err error) {
	// Query set of FROM objects
	// if a FROM select object is not provided, assume "root" search
	if len(request.GetFromKeys()) == 0 {
		getLogger().Tracef("request object FROM selector empty; assume query uses document \"root\".")
	}

	resultJson, err = findFromObject(request, jsonMap)
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
		// Warn WHERE clause cannot be applied to a single map object; it was
		// intended only for slices of objects... still return values (for now)
		whereFilters, _ := request.GetWhereFilters()
		if len(whereFilters) > 0 {
			getLogger().Warningf("Cannot apply WHERE filter (%v) to a singleton FROM object (%v)",
				whereFilters,
				request.GetFromKeys())
		}
	case []interface{}:
		fromObjectSlice, _ := resultJson.([]interface{})
		resultJson, err = selectFieldsFromSlice(request, fromObjectSlice)
		if err != nil {
			return
		}
	default:
		// NOTE: this SHOULD never be invoked as the FROM logic should have caught this already
		err = common.NewQueryFromClauseError(request,
			fmt.Sprintf("%s: %T", MSG_QUERY_INVALID_DATATYPE, t))
		return
	}

	if err != nil {
		getLogger().Tracef("error: %s", err)
		return
	}
	return
}

func findFromObject(request *common.QueryRequest, jsonMap map[string]interface{}) (pResults interface{}, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// initialize local map pointer and return value to starting JSON map
	var tempMap map[string]interface{} = jsonMap
	pResults = jsonMap

	getLogger().Tracef("Finding JSON object using path key(s): %v\n", request.GetFromKeys())

	for i, key := range request.GetFromKeys() {
		pResults = tempMap[key]

		// if we find a nil value, this means we failed to find the object
		if pResults == nil {
			err = common.NewQueryFromClauseError(
				request,
				fmt.Sprintf("%s: (%s)", MSG_QUERY_ERROR_FROM_KEY_NOT_FOUND, key))
			return
		}

		switch t := pResults.(type) {
		case map[string]interface{}:
			// If the resulting value is indeed another map type, we expect for a Json Map
			// we preserve that pointer for the next iteration
			tempMap = pResults.(map[string]interface{})
		case []interface{}:
			// TODO: We only support an array (i.e., []interface{}) as the last selector
			// in theory, we could support arrays (perhaps array notation) in the FROM clause
			// at any point (e.g., "metadata.component.properties[0]").
			// we should still be able to support implicit arrays as well.

			// We no longer have a map to dereference into
			// So if there are more keys left as selectors it is an error
			if len(request.GetFromKeys()) > i+1 {
				err = common.NewQueryFromClauseError(request,
					fmt.Sprintf("%s: (%s)", MSG_QUERY_ERROR_FROM_KEY_SLICE_DEREFERENCE, key))
				return
			}
		default:
			getLogger().Debugf("Invalid datatype of query: key: %s (%t)", key, t)
			err = common.NewQueryFromClauseError(request,
				fmt.Sprintf("%s: %T", MSG_QUERY_INVALID_DATATYPE, t))
			return
		}
	}
	return
}

// NOTE: it is the caller's responsibility to convert to other output formats
// based upon other flag values
func selectFieldsFromMap(request *common.QueryRequest, jsonMap map[string]interface{}) (mapSelectedFields map[string]interface{}, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	selectors := request.GetSelectKeys()

	// Default to wildcard behavior
	// NOTE: The default set by the CLI framework SHOULD be QUERY_TOKEN_WILDCARD
	if len(selectors) == 0 {
		return jsonMap, nil
	}

	// Check for wildcard; if it is the only selector, return the original map
	if len(selectors) == 1 && selectors[0] == common.QUERY_TOKEN_WILDCARD {
		return jsonMap, nil
	}

	// allocate map to hold selected fields
	mapSelectedFields = make(map[string]interface{})

	// Copy selected fields into output map
	// NOTE: wildcard "short-circuit" returns original map above
	for _, fieldKey := range selectors {
		// validate wildcard not used with other fields; if so, that is a conflict
		if fieldKey == common.QUERY_TOKEN_WILDCARD {
			err = common.NewQuerySelectClauseError(
				request,
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
func selectFieldsFromSlice(request *common.QueryRequest, jsonSlice []interface{}) (sliceSelectedFields []interface{}, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	var whereFilters []common.WhereFilter
	whereFilters, err = request.GetWhereFilters()
	getLogger().Debugf("whereFilters: %v", whereFilters)
	if err != nil {
		return
	}

	// See if
	var match bool
	for _, iObject := range jsonSlice {
		mapObject, ok := iObject.(map[string]interface{})

		if !ok {
			err = getLogger().Errorf("Unable to convert object: %v, to map[string]interface{}", iObject)
			return
		}

		// If where filters exist, apply them to the map object
		// to see if it should be included in the result
		if whereFilters != nil {
			match, err = whereFilterMatch(mapObject, whereFilters)
			if err != nil {
				return
			}
		}

		// If no WHERE filters were provided OR we matched all the regex comparisons,
		// against the original map object, then add a new map object with only the
		// SELECT(ed) fields requested.
		if whereFilters == nil || match {
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
func whereFilterMatch(mapObject map[string]interface{}, whereFilters []common.WhereFilter) (match bool, err error) {
	var buf bytes.Buffer
	var key string

	// create a byte encoder
	enc := gob.NewEncoder(&buf)

	for _, filter := range whereFilters {

		key = filter.Key
		value, present := mapObject[key]
		getLogger().Debugf("testing object map[%s]: `%v`", key, value)

		if !present {
			match = false
			err = getLogger().Errorf("key `%s` not found ib object map", key)
			break
		}

		// Reset the encoder'a byte buffer on each iteration and
		// convert the value (an interface{}) to []byte we can use on regex. eval.
		buf.Reset()

		// Do not encode nil pointer values; replace with empty string
		if value == nil {
			value = ""
		}

		// Handle non-string data types in the map by converting them to string
		switch data := value.(type) {
		case bool:
			value = strconv.FormatBool(data)
		case int:
			value = strconv.Itoa(data)
		}

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
