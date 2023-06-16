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
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/CycloneDX/sbom-utility/log"
	"github.com/CycloneDX/sbom-utility/resources"
	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/CycloneDX/sbom-utility/utils"
	"github.com/spf13/cobra"
	"github.com/xeipuuv/gojsonschema"
)

const (
	VALID   = true
	INVALID = false
)

// validation flags
const (
	FLAG_VALIDATE_SCHEMA_FORCE     = "force"
	FLAG_VALIDATE_SCHEMA_VARIANT   = "variant"
	FLAG_VALIDATE_CUSTOM           = "custom" // TODO: document when no longer experimental
	FLAG_VALIDATE_ERR_LIMIT        = "error-limit"
	MSG_VALIDATE_SCHEMA_FORCE      = "force specified schema file for validation; overrides inferred schema"
	MSG_VALIDATE_SCHEMA_VARIANT    = "select named schema variant (e.g., \"strict\"); variant must be declared in configuration file (i.e., \"config.json\")"
	MSG_VALIDATE_FLAG_CUSTOM       = "perform custom validation using custom configuration settings (i.e., \"custom.json\")"
	MSG_VALIDATE_FLAG_ERR_COLORIZE = "Colorize formatted error output (true|false); default true"
	MSG_VALIDATE_FLAG_ERR_LIMIT    = "Limit number of errors output (integer); default 10"
	MSG_VALIDATE_FLAG_ERR_FORMAT   = "format error results using the specified format type"
)

var VALIDATE_SUPPORTED_ERROR_FORMATS = MSG_VALIDATE_FLAG_ERR_FORMAT +
	strings.Join([]string{FORMAT_TEXT, FORMAT_JSON}, ", ") + " (default: txt)"

// limits
const (
	DEFAULT_MAX_ERROR_LIMIT         = 10
	DEFAULT_MAX_ERR_DESCRIPTION_LEN = 128
)

// Protocol
const (
	PROTOCOL_PREFIX_FILE = "file://"
)

type ValidationErrResult struct {
	gojsonschema.ResultErrorFields
}

func NewCommandValidate() *cobra.Command {
	// NOTE: `RunE` function takes precedent over `Run` (anonymous) function if both provided
	var command = new(cobra.Command)
	command.Use = CMD_USAGE_VALIDATE
	command.Short = "Validate input file against its declared BOM schema"
	command.Long = "Validate input file against its declared BOM schema, if detectable and supported."
	command.RunE = validateCmdImpl
	command.Flags().StringVarP(&utils.GlobalFlags.OutputFormat, FLAG_FILE_OUTPUT_FORMAT, "", "",
		MSG_VALIDATE_FLAG_ERR_FORMAT+VALIDATE_SUPPORTED_ERROR_FORMATS)

	command.PreRunE = func(cmd *cobra.Command, args []string) error {

		// This command can be called with this persistent flag, but does not make sense...
		inputFile := utils.GlobalFlags.InputFile
		if inputFile != "" {
			getLogger().Warningf("Invalid flag for command: `%s` (`%s`). Ignoring...", FLAG_FILENAME_OUTPUT, FLAG_FILENAME_OUTPUT_SHORT)
		}

		return preRunTestForInputFile(cmd, args)
	}
	initCommandValidate(command)
	return command
}

// Add local flags to validate command
func initCommandValidate(command *cobra.Command) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Force a schema file to use for validation (override inferred schema)
	command.Flags().StringVarP(&utils.GlobalFlags.ValidateFlags.ForcedJsonSchemaFile, FLAG_VALIDATE_SCHEMA_FORCE, "", "", MSG_VALIDATE_SCHEMA_FORCE)
	// Optional schema "variant" of inferred schema (e.g, "strict")
	command.Flags().StringVarP(&utils.GlobalFlags.Variant, FLAG_VALIDATE_SCHEMA_VARIANT, "", "", MSG_VALIDATE_SCHEMA_VARIANT)
	command.Flags().BoolVarP(&utils.GlobalFlags.CustomValidation, FLAG_VALIDATE_CUSTOM, "", false, MSG_VALIDATE_FLAG_CUSTOM)
	// Colorize default: true (for historical reasons)
	command.Flags().BoolVarP(&utils.GlobalFlags.ValidateFlags.ColorizeJsonErrors, FLAG_COLORIZE_OUTPUT, "", true, MSG_VALIDATE_FLAG_ERR_COLORIZE)
	command.Flags().IntVarP(&utils.GlobalFlags.ValidateFlags.MaxNumErrors, FLAG_VALIDATE_ERR_LIMIT, "", DEFAULT_MAX_ERROR_LIMIT, MSG_VALIDATE_FLAG_ERR_LIMIT)
}

func validateCmdImpl(cmd *cobra.Command, args []string) error {
	getLogger().Enter()
	defer getLogger().Exit()

	// invoke validate and consistently manage exit messages and codes
	isValid, _, _, err := Validate()

	// Note: all invalid SBOMs (that fail schema validation) SHOULD result in an
	// InvalidSBOMError()
	if err != nil {
		if IsInvalidSBOMError(err) {
			os.Exit(ERROR_VALIDATION)
		}
		os.Exit(ERROR_APPLICATION)
	}

	// Note: JSON schema validation does NOT return errors so we want to
	// clearly return an invalid return code on exit
	// TODO: remove this if we can assure that we ALWAYS return an
	// IsInvalidSBOMError(err) in these cases from the Validate() method
	if !isValid {
		os.Exit(ERROR_VALIDATION)
	}

	// Note: this implies os.Exit(0) as the default from main.go (i.e., bash rc=0)
	return nil
}

// Normalize error/normalizeValidationErrorTypes from the Validate() function
func normalizeValidationErrorTypes(document *schema.Sbom, valid bool, err error) {

	// TODO: if JSON validation resulted in !valid, turn that into an
	// InvalidSBOMError and test to make sure this works in all cases

	// Consistently display errors before exiting
	if err != nil {
		switch t := err.(type) {
		case *json.UnmarshalTypeError:
			schema.DisplayJSONErrorDetails(document.GetRawBytes(), err)
		case *json.SyntaxError:
			schema.DisplayJSONErrorDetails(document.GetRawBytes(), err)
		case *InvalidSBOMError:
			// Note: InvalidSBOMError type errors include schema errors which have already
			// been added to the error type and will shown with the Error() interface
			if valid {
				getLogger().Errorf("invalid state: error (%T) returned, but SBOM valid !!!", t)
			}
			getLogger().Error(err)
		default:
			getLogger().Tracef("unhandled error type: `%v`", t)
			getLogger().Error(err)
		}
	}

	// ALWAYS output valid/invalid result (as informational)
	message := fmt.Sprintf("document `%s`: valid=[%t]", document.GetFilename(), valid)
	getLogger().Info(message)
}

func Validate() (valid bool, document *schema.Sbom, schemaErrors []gojsonschema.ResultError, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// use function closure to assure consistent error output based upon error type
	defer func() {
		if err != nil {
			normalizeValidationErrorTypes(document, valid, err)
		}
	}()

	// Attempt to load and unmarshal the input file as a Json document
	// Note: JSON syntax errors return "encoding/json.SyntaxError"
	document, err = LoadInputSbomFileAndDetectSchema()
	if err != nil {
		return INVALID, document, schemaErrors, err
	}

	// if "custom" flag exists, then assure we support the format
	if utils.GlobalFlags.CustomValidation && !document.FormatInfo.IsCycloneDx() {
		err = schema.NewUnsupportedFormatError(
			schema.MSG_FORMAT_UNSUPPORTED_COMMAND,
			document.GetFilename(),
			document.FormatInfo.CanonicalName,
			CMD_VALIDATE,
			FLAG_VALIDATE_CUSTOM)
		return valid, document, schemaErrors, err
	}

	// Create a loader for the SBOM (JSON) document
	documentLoader := gojsonschema.NewReferenceLoader(PROTOCOL_PREFIX_FILE + utils.GlobalFlags.InputFile)

	schemaName := document.SchemaInfo.File
	var schemaLoader gojsonschema.JSONLoader
	var errRead error
	var bSchema []byte

	// If caller "forced" a specific schema file (version), load it instead of
	// any SchemaInfo found in config.json
	// TODO: support remote schema load (via URL) with a flag (default should always be local file for security)
	forcedSchemaFile := utils.GlobalFlags.ValidateFlags.ForcedJsonSchemaFile
	if forcedSchemaFile != "" {
		getLogger().Infof("Validating document using forced schema (i.e., `--force %s`)", forcedSchemaFile)
		//schemaName = document.SchemaInfo.File
		schemaName = "file://" + forcedSchemaFile
		getLogger().Infof("Loading schema `%s`...", schemaName)
		schemaLoader = gojsonschema.NewReferenceLoader(schemaName)
	} else {
		// Load the matching JSON schema (format, version and variant) from embedded resources
		// i.e., using the matching schema found in config.json (as SchemaInfo)
		getLogger().Infof("Loading schema `%s`...", document.SchemaInfo.File)
		bSchema, errRead = resources.SBOMSchemaFiles.ReadFile(document.SchemaInfo.File)

		if errRead != nil {
			// we force result to INVALID as any errors from the library means
			// we could NOT actually confirm the input documents validity
			return INVALID, document, schemaErrors, errRead
		}

		schemaLoader = gojsonschema.NewBytesLoader(bSchema)
	}

	if schemaLoader == nil {
		// we force result to INVALID as any errors from the library means
		// we could NOT actually confirm the input documents validity
		return INVALID, document, schemaErrors, fmt.Errorf("unable to read schema: `%s`", schemaName)
	}

	// create a reusable schema object (TODO: validate multiple documents)
	var errLoad error = nil
	const RETRY int = 3
	var jsonSbomSchema *gojsonschema.Schema

	// we force result to INVALID as any errors from the library means
	// we could NOT actually confirm the input documents validity
	// WARNING: if schemas reference "remote" schemas which are loaded
	// over http... then there is a chance of 503 errors (as the pkg. loads
	// externally referenced schemas over network)... attempt fixed retry...
	for i := 0; i < RETRY; i++ {
		jsonSbomSchema, errLoad = gojsonschema.NewSchema(schemaLoader)

		if errLoad == nil {
			break
		}
		getLogger().Warningf("unable to load referenced schema over HTTP: \"%v\"\n retrying...", errLoad)
	}

	if errLoad != nil {
		return INVALID, document, schemaErrors, fmt.Errorf("unable to load schema: `%s`", schemaName)
	}

	getLogger().Infof("Schema `%s` loaded.", schemaName)

	// Validate against the schema and save result determination
	getLogger().Infof("Validating `%s`...", document.GetFilename())
	result, errValidate := jsonSbomSchema.Validate(documentLoader)

	// ALWAYS set the valid return parameter
	getLogger().Infof("SBOM valid against JSON schema: `%t`", result.Valid())
	valid = result.Valid()

	// Catch general errors from the validation module itself and pass them on'
	if errValidate != nil {
		// we force result to INVALID as any errors from the library means
		// we could NOT actually confirm the input documents validity
		return INVALID, document, schemaErrors, errValidate
	}

	// Note: actual schema validation errors appear in the `result` object
	// Save all schema errors found in the `result` object in an explicit, typed error
	if schemaErrors = result.Errors(); len(schemaErrors) > 0 {
		errInvalid := NewInvalidSBOMError(
			document,
			MSG_SCHEMA_ERRORS,
			nil,
			schemaErrors)

		// Format error results
		format := utils.GlobalFlags.OutputFormat
		var formattedSchemaErrors string
		getLogger().Infof("Outputting error results (`%s` format)...", format)
		switch format {
		case FORMAT_JSON:
			formattedSchemaErrors = FormatSchemaErrorsJson(schemaErrors)
		case FORMAT_TEXT:
			formattedSchemaErrors = FormatSchemaErrorsText(schemaErrors)
		default:
			getLogger().Warningf("error results not supported for `%s` format; defaulting to `%s` format...",
				format, FORMAT_TEXT)
			formattedSchemaErrors = FormatSchemaErrorsText(schemaErrors)
		}

		// Append formatted schema errors "details" to the InvalidSBOMError type
		errInvalid.Details = formattedSchemaErrors

		return INVALID, document, schemaErrors, errInvalid
	}

	// If the validated SBOM is of a known format, we can unmarshal it into
	// more convenient typed structure for simplified custom validation
	if document.FormatInfo.IsCycloneDx() {
		document.CdxBom, err = schema.UnMarshalDocument(document.GetJSONMap())
		if err != nil {
			return INVALID, document, schemaErrors, err
		}
	}

	// Perform additional validation in document composition/structure
	// and "custom" required data within specified fields
	if utils.GlobalFlags.CustomValidation {
		// Perform all custom validation
		err := validateCustomCDXDocument(document)
		if err != nil {
			// Wrap any specific validation error in a single invalid SBOM error
			if !IsInvalidSBOMError(err) {
				err = NewInvalidSBOMError(
					document,
					err.Error(),
					err,
					nil)
			}
			// an error implies it is also invalid (according to custom requirements)
			return INVALID, document, schemaErrors, err
		}
	}

	// All validation tests passed; return VALID
	return
}

func formatSchemaErrorTypes(resultError gojsonschema.ResultError, colorize bool) (formattedResult string) {

	var jsonErrorMap = make(map[string]interface{})
	jsonErrorMap["type"] = resultError.Type()
	jsonErrorMap["context"] = resultError.Context()
	jsonErrorMap["value"] = resultError.Value()
	jsonErrorMap["details"] = resultError.Details()
	jsonErrorMap["description"] = resultError.Description()
	jsonErrorMap["descriptionFormat"] = resultError.DescriptionFormat()

	switch resultError.(type) {
	case *gojsonschema.FalseError:
	case *gojsonschema.RequiredError:
	case *gojsonschema.InvalidTypeError:
	case *gojsonschema.NumberAnyOfError:
	case *gojsonschema.NumberOneOfError:
	case *gojsonschema.NumberAllOfError:
	case *gojsonschema.NumberNotError:
	case *gojsonschema.MissingDependencyError:
	case *gojsonschema.InternalError:
	case *gojsonschema.ConstError:
	case *gojsonschema.EnumError:
	case *gojsonschema.ArrayNoAdditionalItemsError:
	case *gojsonschema.ArrayMinItemsError:
	case *gojsonschema.ArrayMaxItemsError:
	case *gojsonschema.ItemsMustBeUniqueError:
		getLogger().Infof("ItemsMustBeUniqueError:")
		formattedResult, _ = log.FormatInterfaceAsJson(jsonErrorMap)
	case *gojsonschema.ArrayContainsError:
	case *gojsonschema.ArrayMinPropertiesError:
	case *gojsonschema.ArrayMaxPropertiesError:
	case *gojsonschema.AdditionalPropertyNotAllowedError:
	case *gojsonschema.InvalidPropertyPatternError:
	case *gojsonschema.InvalidPropertyNameError:
	case *gojsonschema.StringLengthGTEError:
	case *gojsonschema.StringLengthLTEError:
	case *gojsonschema.DoesNotMatchPatternError:
	case *gojsonschema.DoesNotMatchFormatError:
	case *gojsonschema.MultipleOfError:
	case *gojsonschema.NumberGTEError:
	case *gojsonschema.NumberGTError:
	case *gojsonschema.NumberLTEError:
	case *gojsonschema.NumberLTError:
	case *gojsonschema.ConditionThenError:
	case *gojsonschema.ConditionElseError:
	default:
		if colorize {
			formattedResult, _ = log.FormatInterfaceAsColorizedJson(jsonErrorMap)
		} else {
			formattedResult, _ = log.FormatInterfaceAsJson(jsonErrorMap)
		}
	}

	// err.SetDescriptionFormat(d)
	// details["field"] = err.Field()
	// if _, exists := details["context"]; !exists && context != nil {
	// 	details["context"] = context.String()
	// }
	// err.SetDescription(formatErrorDescription(err.DescriptionFormat(), details))
	return
}

func FormatSchemaErrorsJson(errs []gojsonschema.ResultError) string {
	var sb strings.Builder

	lenErrs := len(errs)
	if lenErrs > 0 {
		errLimit := utils.GlobalFlags.ValidateFlags.MaxNumErrors
		colorize := utils.GlobalFlags.ValidateFlags.ColorizeJsonErrors

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

			schemaErrorText := formatSchemaErrorTypes(resultError, colorize)

			// append the numbered schema error
			// schemaErrorText := fmt.Sprintf("\n\t%d. Type: [%s], Field: [%s], Description: [%s] %s",
			// 	i+1,
			// 	resultError.Type(),
			// 	resultError.Field(),
			// 	description,
			// 	failingObject)

			sb.WriteString(schemaErrorText)
		}
	}
	return sb.String()
}

func FormatSchemaErrorsText(errs []gojsonschema.ResultError) string {
	var sb strings.Builder

	lenErrs := len(errs)
	if lenErrs > 0 {
		errLimit := utils.GlobalFlags.ValidateFlags.MaxNumErrors
		colorize := utils.GlobalFlags.ValidateFlags.ColorizeJsonErrors
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

func schemaErrorExists(schemaErrors []gojsonschema.ResultError,
	expectedType string, expectedField string, expectedValue interface{}) bool {

	for i, resultError := range schemaErrors {
		// Some descriptions include very long enums; in those cases,
		// truncate to a reasonable length using an intelligent separator
		getLogger().Tracef(">> %d. Type: [%s], Field: [%s], Value: [%v]",
			i+1,
			resultError.Type(),
			resultError.Field(),
			resultError.Value())

		actualType := resultError.Type()
		actualField := resultError.Field()
		actualValue := resultError.Value()

		if actualType == expectedType {
			// we have matched on the type (key) field, continue to match other fields
			if expectedField != "" &&
				actualField != expectedField {
				getLogger().Tracef("expected Field: `%s`; actual Field: `%s`", expectedField, actualField)
				return false
			}

			if expectedValue != "" &&
				actualValue != expectedValue {
				getLogger().Tracef("expected Value: `%s`; actual Value: `%s`", actualValue, expectedValue)
				return false
			}
			return true
		} else {
			getLogger().Debugf("Skipping result[%d]: expected Type: `%s`; actual Type: `%s`", i, expectedType, actualType)
		}
	}
	return false
}
