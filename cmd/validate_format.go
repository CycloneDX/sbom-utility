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

package cmd

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/CycloneDX/sbom-utility/log"
	"github.com/CycloneDX/sbom-utility/utils"
	"github.com/iancoleman/orderedmap"
	"github.com/xeipuuv/gojsonschema"
)

const (
	ERROR_DETAIL_KEY_DATA_TYPE         = "type"
	ERROR_DETAIL_KEY_FIELD             = "field"
	ERROR_DETAIL_KEY_CONTEXT           = "context"
	ERROR_DETAIL_KEY_VALUE             = "value"
	ERROR_DETAIL_KEY_VALUE_TYPE_ARRAY  = "array"
	ERROR_DETAIL_KEY_VALUE_INDEX       = "index"
	ERROR_DETAIL_KEY_VALUE_ITEM        = "item"
	ERROR_DETAIL_KEY_VALUE_DESCRIPTION = "description"
	ERROR_DETAIL_ARRAY_ITEM_INDEX_I    = "i"
	ERROR_DETAIL_ARRAY_ITEM_INDEX_J    = "j"
	ERROR_DETAIL_CONTEXT_EMPTY         = ""
)

const (
	ERROR_DETAIL_JSON_DEFAULT_PREFIX    = "    "
	ERROR_DETAIL_JSON_DEFAULT_INDENT    = "    "
	ERROR_DETAIL_JSON_CONTEXT_DELIMITER = "."
	ERROR_DETAIL_JSON_NEWLINE_INDENT    = "\n" + ERROR_DETAIL_JSON_DEFAULT_PREFIX
)

// JSON formatting
const (
	JSON_ARRAY_START    = "[\n"
	JSON_ARRAY_ITEM_SEP = ",\n"
	JSON_ARRAY_END      = "\n]\n"
)

// Recurring / translatable messages
const (
	MSG_INFO_FORMATTING_ERROR_RESULTS = "Formatting error results ('%s' format)..."
	MSG_INFO_SCHEMA_ERRORS_DETECTED   = "(%d) schema errors detected."
	MSG_INFO_TOO_MANY_ERRORS          = "Too many errors. Showing (%v/%v) errors."
	MSG_ERROR_FORMATTING_ERROR        = "formatting error: %s"
	MSG_WARN_INVALID_FORMAT           = "invalid format. error results not supported for '%s' format; defaulting to '%s' format..."
)

var VALIDATION_ERROR_TITLES = []string{
	ERROR_DETAIL_KEY_DATA_TYPE,
	ERROR_DETAIL_KEY_FIELD,
	ERROR_DETAIL_KEY_CONTEXT,
	ERROR_DETAIL_KEY_VALUE_DESCRIPTION,
}

// JsonContext is a linked-list of JSON key strings
type ValidationErrorResult struct {
	ResultError gojsonschema.ResultError // read only
	hashMap     *orderedmap.OrderedMap
	resultMap   *orderedmap.OrderedMap
	valuesMap   *orderedmap.OrderedMap
	Context     *gojsonschema.JsonContext `json:"context"` // resultError.Context()
}

func NewValidationErrorResult(resultError gojsonschema.ResultError) (validationErrResult *ValidationErrorResult) {
	// Prepare values that are optionally output as JSON
	validationErrResult = &ValidationErrorResult{
		ResultError: resultError,
	}
	// Prepare for JSON output by adding all required fields to our ordered map
	validationErrResult.resultMap = orderedmap.New()
	validationErrResult.resultMap.Set(ERROR_DETAIL_KEY_DATA_TYPE, resultError.Type())
	validationErrResult.resultMap.Set(ERROR_DETAIL_KEY_FIELD, resultError.Field())
	if context := resultError.Context(); context != nil {
		validationErrResult.resultMap.Set(ERROR_DETAIL_KEY_CONTEXT, resultError.Context().String())
	} else {
		validationErrResult.resultMap.Set(ERROR_DETAIL_KEY_CONTEXT, ERROR_DETAIL_CONTEXT_EMPTY)
	}
	validationErrResult.resultMap.Set(ERROR_DETAIL_KEY_VALUE_DESCRIPTION, resultError.Description())

	return
}

func (validationErrResult *ValidationErrorResult) MarshalJSON() (marshalled []byte, err error) {
	return validationErrResult.resultMap.MarshalJSON()
}

func (validationErrResult *ValidationErrorResult) HashResultError() {
	fmt.Printf("re:=%v", validationErrResult.ResultError)
	validationErrResult.hashMap.Set(ERROR_DETAIL_KEY_DATA_TYPE, validationErrResult.ResultError.Type())
	validationErrResult.hashMap.Set(ERROR_DETAIL_KEY_CONTEXT, validationErrResult.ResultError.Context().String())
	validationErrResult.hashMap.Set(ERROR_DETAIL_KEY_VALUE, validationErrResult.ResultError.Value())
}

func (result *ValidationErrorResult) MapResultError(flags utils.ValidateCommandFlags) {
	// Conditionally, add optional values as requested (via flags)
	if flags.ShowErrorValue {
		result.resultMap.Set(ERROR_DETAIL_KEY_VALUE, result.ResultError.Value())
	}
}

func (result *ValidationErrorResult) MapItemsMustBeUniqueError(flags utils.ValidateCommandFlags) {

	// For this error type, we want to reduce the information show to the end user.
	// Originally, the entire array with duplicate items was show for EVERY occurrence;
	// attempt to only show the failing item itself once (and only once)
	// TODO: deduplication (planned) will also help shrink large error output results
	// Conditionally, add optional values as requested (via flags)
	if flags.ShowErrorValue {
		details := result.ResultError.Details()
		valueType, typeFound := details[ERROR_DETAIL_KEY_DATA_TYPE]
		// verify the claimed type is an array
		if typeFound && valueType == ERROR_DETAIL_KEY_VALUE_TYPE_ARRAY {
			index, indexFound := details[ERROR_DETAIL_ARRAY_ITEM_INDEX_I]
			// if a claimed duplicate index is provided (we use the first "i" index not the 2nd "j" one)
			if indexFound {
				value := result.ResultError.Value()
				array, arrayValid := value.([]interface{})
				i, indexValid := index.(int)
				// verify the claimed item index is within range
				if arrayValid && indexValid && i < len(array) {
					// Add just the first array item to the value key
					result.valuesMap = orderedmap.New()
					result.valuesMap.Set(ERROR_DETAIL_KEY_DATA_TYPE, valueType)
					result.valuesMap.Set(ERROR_DETAIL_KEY_VALUE_INDEX, i)
					result.valuesMap.Set(ERROR_DETAIL_KEY_VALUE_ITEM, array[i])
					result.resultMap.Set(ERROR_DETAIL_KEY_VALUE, result.valuesMap)
				}
			}
		}
	}
}

func FormatSchemaErrors(writer io.Writer, schemaErrors []gojsonschema.ResultError, flags utils.ValidateCommandFlags, format string) (formattedSchemaErrors string) {

	if lenErrs := len(schemaErrors); lenErrs > 0 {
		getLogger().Infof(MSG_INFO_SCHEMA_ERRORS_DETECTED, lenErrs)
		getLogger().Infof(MSG_INFO_FORMATTING_ERROR_RESULTS, format)
		switch format {
		case FORMAT_JSON:
			DisplaySchemaErrorsJson(writer, schemaErrors, utils.GlobalFlags.ValidateFlags)
		case FORMAT_TEXT:
			DisplaySchemaErrorsText(writer, schemaErrors, utils.GlobalFlags.ValidateFlags)
		case FORMAT_CSV:
			DisplaySchemaErrorsCsv(writer, schemaErrors, utils.GlobalFlags.ValidateFlags)
		default:
			getLogger().Warningf(MSG_WARN_INVALID_FORMAT, format, FORMAT_TEXT)
			DisplaySchemaErrorsText(writer, schemaErrors, utils.GlobalFlags.ValidateFlags)
			fmt.Fprintf(writer, "%s", formattedSchemaErrors)
		}
	}

	return
}

// Custom mapping of schema error results (for formatting) based upon possible JSON schema error types
// the custom mapping handlers SHOULD adjust the fields/keys and their values within the `resultMap`
// for the respective errorResult being operated on.
func mapSchemaErrorResult(resultError gojsonschema.ResultError, flags utils.ValidateCommandFlags) (validationErrorResult *ValidationErrorResult) {

	validationErrorResult = NewValidationErrorResult(resultError)

	// The cases below represent the complete set of typed errors possible.
	// Most are commented out as placeholder for future custom format methods.
	switch errorType := resultError.(type) {
	// case *gojsonschema.AdditionalPropertyNotAllowedError:
	// case *gojsonschema.ArrayContainsError:
	// case *gojsonschema.ArrayMaxItemsError:
	// case *gojsonschema.ArrayMaxPropertiesError:
	// case *gojsonschema.ArrayMinItemsError:
	// case *gojsonschema.ArrayMinPropertiesError:
	// case *gojsonschema.ArrayNoAdditionalItemsError:
	// case *gojsonschema.ConditionElseError:
	// case *gojsonschema.ConditionThenError:
	// case *gojsonschema.ConstError:
	// case *gojsonschema.DoesNotMatchFormatError:
	// case *gojsonschema.DoesNotMatchPatternError:
	// case *gojsonschema.EnumError:
	// case *gojsonschema.FalseError:
	// case *gojsonschema.InternalError:
	// case *gojsonschema.InvalidPropertyNameError:
	// case *gojsonschema.InvalidPropertyPatternError:
	// case *gojsonschema.InvalidTypeError:
	case *gojsonschema.ItemsMustBeUniqueError:
		validationErrorResult.MapItemsMustBeUniqueError(flags)
	// case *gojsonschema.MissingDependencyError:
	// case *gojsonschema.MultipleOfError:
	// case *gojsonschema.NumberAllOfError:
	// case *gojsonschema.NumberAnyOfError:
	// case *gojsonschema.NumberGTEError:
	// case *gojsonschema.NumberGTError:
	// case *gojsonschema.NumberLTEError:
	// case *gojsonschema.NumberLTError:
	// case *gojsonschema.NumberNotError:
	// case *gojsonschema.NumberOneOfError:
	// case *gojsonschema.RequiredError:
	// case *gojsonschema.StringLengthGTEError:
	// case *gojsonschema.StringLengthLTEError:
	default:
		getLogger().Debugf("default formatting: ResultError Type: [%v]", errorType)
		validationErrorResult.MapResultError(flags)
	}

	return
}

func (result *ValidationErrorResult) formatResultMap(flags utils.ValidateCommandFlags) string {
	// format information on the failing "value" (details) with proper JSON indenting
	var formattedResult string
	var errFormatting error
	if flags.ColorizeErrorOutput {
		formattedResult, errFormatting = log.FormatIndentedInterfaceAsColorizedJson(
			result.resultMap,
			len(ERROR_DETAIL_JSON_DEFAULT_INDENT),
			ERROR_DETAIL_JSON_NEWLINE_INDENT,
		)
	} else {
		formattedResult, errFormatting = log.FormatIndentedInterfaceAsJson(
			result.resultMap,
			ERROR_DETAIL_JSON_DEFAULT_PREFIX,
			ERROR_DETAIL_JSON_DEFAULT_INDENT,
		)
	}
	if errFormatting != nil {
		return getLogger().Errorf(MSG_ERROR_FORMATTING_ERROR, errFormatting.Error()).Error()
	}

	return formattedResult
}

func DisplaySchemaErrorsJson(writer io.Writer, errs []gojsonschema.ResultError, flags utils.ValidateCommandFlags) {
	getLogger().Enter()
	defer getLogger().Exit()

	var sb strings.Builder

	if lenErrs := len(errs); lenErrs > 0 {

		// If we have more errors than the (default or user set) limit; notify user
		errLimit := flags.MaxNumErrors
		if lenErrs > errLimit {
			// notify users more errors exist
			getLogger().Infof(MSG_INFO_TOO_MANY_ERRORS, errLimit, len(errs))
		}

		// begin/open JSON array
		sb.WriteString(JSON_ARRAY_START)

		for i, resultError := range errs {
			// short-circuit if too many errors (i.e., using the error limit flag value)
			if i == errLimit {
				break
			}

			// add to the result errors
			validationErrorResult := mapSchemaErrorResult(resultError, flags)
			formattedResult := validationErrorResult.formatResultMap(flags)
			// NOTE: we must add the prefix (indent) ourselves
			// see issue: https://github.com/golang/go/issues/49261
			sb.WriteString(ERROR_DETAIL_JSON_DEFAULT_PREFIX)
			sb.WriteString(formattedResult)

			if i < (lenErrs-1) && i < (errLimit-1) {
				sb.WriteString(JSON_ARRAY_ITEM_SEP)
			}
		}

		// end/close JSON array
		sb.WriteString(JSON_ARRAY_END)
	}

	// Note: JSON data files MUST ends in a newline as this is a POSIX standard
	fmt.Fprintf(writer, "%s\n", sb.String())
}

func DisplaySchemaErrorsText(writer io.Writer, errs []gojsonschema.ResultError, flags utils.ValidateCommandFlags) {
	getLogger().Enter()
	defer getLogger().Exit()

	var sb strings.Builder
	var lineOutput string

	if lenErrs := len(errs); lenErrs > 0 {
		var errorIndex string

		// If we have more errors than the (default or user set) limit; notify user
		errLimit := flags.MaxNumErrors
		if lenErrs > errLimit {
			// notify users more errors exist
			getLogger().Infof(MSG_INFO_TOO_MANY_ERRORS, errLimit, len(errs))
		}

		for i, resultError := range errs {

			// short-circuit if too many errors (i.e., using the error limit flag value)
			if i == errLimit {
				break
			}

			// append the numbered schema error
			errorIndex = strconv.Itoa(i + 1)

			// emit formatted error result
			validationErrorResult := mapSchemaErrorResult(resultError, flags)
			formattedResult := validationErrorResult.formatResultMap(flags)

			// NOTE: we must add the prefix (indent) ourselves
			// see issue: https://github.com/golang/go/issues/49261
			lineOutput = fmt.Sprintf("%v. %s\n", errorIndex, formattedResult)
			sb.WriteString(lineOutput)
		}
	}

	fmt.Fprintf(writer, "%s", sb.String())
}

func DisplaySchemaErrorsCsv(writer io.Writer, errs []gojsonschema.ResultError, flags utils.ValidateCommandFlags) {
	getLogger().Enter()
	defer getLogger().Exit()

	var currentRow []string

	w := csv.NewWriter(writer)
	defer w.Flush()

	// Emit title row
	if err := w.Write(VALIDATION_ERROR_TITLES); err != nil {
		_ = getLogger().Errorf("error writing to output (%v): %s", VALIDATION_ERROR_TITLES, err)
		return
	}

	if lenErrs := len(errs); lenErrs > 0 {

		// If we have more errors than the (default or user set) limit; notify user
		errLimit := flags.MaxNumErrors
		if lenErrs > errLimit {
			// notify users more errors exist
			getLogger().Infof(MSG_INFO_TOO_MANY_ERRORS, errLimit, len(errs))
		}

		for i, resultError := range errs {
			currentRow = nil

			// short-circuit if too many errors (i.e., using the error limit flag value)
			if i == errLimit {
				break
			}

			// emit formatted error result
			validationErrorResult := mapSchemaErrorResult(resultError, flags)
			validationErrorResult.formatResultMap(flags)

			// Each row will contain every field of a CDX LicenseChoice object
			datatype, _ := validationErrorResult.resultMap.Get(ERROR_DETAIL_KEY_DATA_TYPE)
			field, _ := validationErrorResult.resultMap.Get(ERROR_DETAIL_KEY_FIELD)
			context, _ := validationErrorResult.resultMap.Get(ERROR_DETAIL_KEY_CONTEXT)
			description, _ := validationErrorResult.resultMap.Get(ERROR_DETAIL_KEY_VALUE_DESCRIPTION)

			currentRow = append(currentRow,
				fmt.Sprintf("%v", datatype),
				fmt.Sprintf("%v", field),
				fmt.Sprintf("%v", context),
				fmt.Sprintf("%v", description),
			)

			if errWrite := w.Write(currentRow); errWrite != nil {
				_ = getLogger().Errorf("error writing to output (%v): %s", currentRow, errWrite)
				return
			}

		}
	}
}
