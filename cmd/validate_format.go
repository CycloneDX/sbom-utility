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

// "github.com/iancoleman/orderedmap"
import (
	"fmt"
	"strings"

	"github.com/CycloneDX/sbom-utility/log"
	"github.com/CycloneDX/sbom-utility/utils"
	"github.com/iancoleman/orderedmap"
	"github.com/xeipuuv/gojsonschema"
)

const (
	ERROR_DETAIL_KEY_DATA_TYPE        = "type"
	ERROR_DETAIL_KEY_VALUE_TYPE_ARRAY = "array"
	ERROR_DETAIL_ARRAY_ITEM_INDEX_I   = "i"
	ERROR_DETAIL_ARRAY_ITEM_INDEX_J   = "j"
)

const (
	ERROR_DETAIL_JSON_DEFAULT_PREFIX = "...."
	ERROR_DETAIL_JSON_DEFAULT_INDENT = "    "
)

type ValidationResultFormatter struct {
	Results []ValidationResultFormat
}

// JsonContext is a linked-list of JSON key strings
type ValidationResultFormat struct {
	resultMap   *orderedmap.OrderedMap
	ResultError gojsonschema.ResultError
	Context     *gojsonschema.JsonContext `json:"context"` // jsonErrorMap["context"] = resultError.Context()
	//Type              string                    `json:"type"`              // jsonErrorMap["type"] = resultError.Type()
	//Field             string                    `json:"field"`             // details["field"] = err.Field()
	//Description       string                    `json:"description"`       // jsonErrorMap["description"] = resultError.Description()
	//DescriptionFormat string                    `json:"descriptionFormat"` // jsonErrorMap["descriptionFormat"] = resultError.DescriptionFormat()
	//Value             interface{}               `json:"value"`             // jsonErrorMap["value"] = resultError.Value()
	//Details           map[string]interface{}    `json:"details"`           // jsonErrorMap["details"] = resultError.Details()
}

func (validationErrResult *ValidationResultFormat) MarshalJSON() (marshalled []byte, err error) {
	return validationErrResult.resultMap.MarshalJSON()
}

func (result *ValidationResultFormat) Format(showValue bool, flags utils.ValidateCommandFlags) string {

	var sb strings.Builder

	// Conditionally, add optional values as requested
	if showValue {
		result.resultMap.Set("value", result.ResultError.Value())
	}

	// TODO: add a general JSON formatting flag
	formattedResult, err := log.FormatIndentedInterfaceAsJson(result.resultMap, ERROR_DETAIL_JSON_DEFAULT_PREFIX, ERROR_DETAIL_JSON_DEFAULT_INDENT)
	if err != nil {
		return fmt.Sprintf("formatting error: %s", err.Error())
	}
	sb.WriteString(formattedResult)

	return sb.String()
}

func (result *ValidationResultFormat) FormatItemsMustBeUniqueError(showValue bool, flags utils.ValidateCommandFlags) string {

	var sb strings.Builder

	// Conditionally, add optional values as requested
	// For this error type, we want to reduce the information show to the end user.
	// Originally, the entire array with duplicate items was show for EVERY occurrence;
	// attempt to only show the failing item itself once (and only once)
	// TODO: deduplication (planned) will also help shrink large error output
	if showValue {
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
					result.resultMap.Set(
						fmt.Sprintf("item[%v]", i),
						array[i])
				}
			}
		}
	}

	// TODO: add a general JSON formatting flag
	formattedResult, err := log.FormatIndentedInterfaceAsJson(result.resultMap, ERROR_DETAIL_JSON_DEFAULT_PREFIX, ERROR_DETAIL_JSON_DEFAULT_INDENT)
	if err != nil {
		return fmt.Sprintf("formatting error: %s", err.Error())
	}
	sb.WriteString(formattedResult)

	return sb.String()
}

func FormatSchemaErrors(schemaErrors []gojsonschema.ResultError, flags utils.ValidateCommandFlags, format string) (formattedSchemaErrors string) {

	getLogger().Infof("Formatting error results (`%s` format)...\n", format)
	switch format {
	case FORMAT_JSON:
		formattedSchemaErrors = FormatSchemaErrorsJson(schemaErrors, utils.GlobalFlags.ValidateFlags)
	case FORMAT_TEXT:
		formattedSchemaErrors = FormatSchemaErrorsText(schemaErrors, utils.GlobalFlags.ValidateFlags)
	default:
		getLogger().Warningf("error results not supported for `%s` format; defaulting to `%s` format...",
			format, FORMAT_TEXT)
		formattedSchemaErrors = FormatSchemaErrorsText(schemaErrors, utils.GlobalFlags.ValidateFlags)
	}
	return
}

func formatSchemaErrorTypes(resultError gojsonschema.ResultError, flags utils.ValidateCommandFlags) (formattedResult string) {

	validationErrorResult := NewValidationErrResult(resultError)

	switch resultError.(type) {
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
		formattedResult = validationErrorResult.FormatItemsMustBeUniqueError(true, flags)
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
		formattedResult = validationErrorResult.Format(true, flags)
	}

	return
}

func FormatSchemaErrorsJson(errs []gojsonschema.ResultError, flags utils.ValidateCommandFlags) string {
	var sb strings.Builder

	lenErrs := len(errs)
	if lenErrs > 0 {
		sb.WriteString(fmt.Sprintf("\n(%d) Schema errors detected (use `--debug` for more details):\n", lenErrs))
		errLimit := flags.MaxNumErrors

		// If we have more errors than the (default or user set) limit; notify user
		if lenErrs > errLimit {
			// notify users more errors exist
			msg := fmt.Sprintf("Too many errors. Showing (%v/%v) errors.", errLimit, len(errs))
			getLogger().Infof("%s", msg)
		}

		if lenErrs > 1 {
			sb.WriteString("[\n")
		}

		for i, resultError := range errs {
			// short-circuit if too many errors (i.e., using the error limit flag value)
			if i > errLimit {
				break
			}

			// add to the result errors
			schemaErrorText := formatSchemaErrorTypes(resultError, flags)
			// NOTE: we must add the prefix (indent) ourselves
			// see issue: https://github.com/golang/go/issues/49261
			sb.WriteString(ERROR_DETAIL_JSON_DEFAULT_PREFIX)
			sb.WriteString(schemaErrorText)

			if i < (lenErrs-1) && i < (errLimit-1) {
				sb.WriteString(",\n")
			}
		}

		if lenErrs > 1 {
			sb.WriteString("\n]")
		}
	}

	return sb.String()
}

func FormatSchemaErrorsText(errs []gojsonschema.ResultError, flags utils.ValidateCommandFlags) string {
	var sb strings.Builder

	lenErrs := len(errs)
	if lenErrs > 0 {
		errLimit := utils.GlobalFlags.ValidateFlags.MaxNumErrors
		colorize := utils.GlobalFlags.ValidateFlags.ColorizeErrorOutput
		var formattedValue string
		var description string
		var failingObject string

		sb.WriteString(fmt.Sprintf("\n(%d) Schema errors detected (use `--debug` for more details):", lenErrs))
		for i, resultError := range errs {

			// short-circuit if we have too many errors
			if i == errLimit {
				// notify users more errors exist
				msg := fmt.Sprintf("Too many errors. Showing (%v/%v) errors.", i, len(errs))
				getLogger().Infof("%s", msg)
				// always include limit message in discrete output (i.e., not turned off by --quiet flag)
				sb.WriteString("\n" + msg)
				break
			}

			// Some descriptions include very long enums; in those cases,
			// truncate to a reasonable length using an intelligent separator
			description = resultError.Description()
			// truncate output unless debug flag is used
			if !utils.GlobalFlags.Debug &&
				len(description) > DEFAULT_MAX_ERR_DESCRIPTION_LEN {
				description, _, _ = strings.Cut(description, ":")
				description = description + " ... (truncated)"
			}

			// TODO: provide flag to allow users to "turn on", by default we do NOT want this
			// as this slows down processing on SBOMs with large numbers of errors
			if colorize {
				formattedValue, _ = log.FormatInterfaceAsColorizedJson(resultError.Value())
			}
			// Indent error detail output in logs
			formattedValue = log.AddTabs(formattedValue)
			// NOTE: if we do not colorize or indent we could simply do this:
			failingObject = fmt.Sprintf("\n\tFailing object: [%v]", formattedValue)

			// truncate output unless debug flag is used
			if !utils.GlobalFlags.Debug &&
				len(failingObject) > DEFAULT_MAX_ERR_DESCRIPTION_LEN {
				failingObject = failingObject[:DEFAULT_MAX_ERR_DESCRIPTION_LEN]
				failingObject = failingObject + " ... (truncated)"
			}

			// append the numbered schema error
			schemaErrorText := fmt.Sprintf("\n\t%d. Type: [%s], Field: [%s], Description: [%s] %s",
				i+1,
				resultError.Type(),
				resultError.Field(),
				description,
				failingObject)

			sb.WriteString(schemaErrorText)
		}
	}
	return sb.String()
}
