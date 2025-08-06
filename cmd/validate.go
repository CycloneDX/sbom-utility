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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/CycloneDX/sbom-utility/resources"
	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/CycloneDX/sbom-utility/utils"
	"github.com/spf13/cobra"
	"github.com/xeipuuv/gojsonschema" // TODO: switch to: https://github.com/santhosh-tekuri/jsonschema
)

const (
	VALID   = true
	INVALID = false
)

// validation flags
// TODO: support a '--truncate <int>“ flag (or similar... 'err-value-truncate' <int>) used
// to truncate formatted "value" (details) to <int> bytes.
// This would replace the hardcoded "DEFAULT_MAX_ERR_DESCRIPTION_LEN" value
const (
	FLAG_VALIDATE_SCHEMA_FORCE     = "force"
	FLAG_VALIDATE_SCHEMA_VARIANT   = "variant"
	FLAG_VALIDATE_CUSTOM           = "custom" // TODO: document when no longer experimental
	FLAG_VALIDATE_ERR_LIMIT        = "error-limit"
	FLAG_VALIDATE_ERR_VALUE        = "error-value"
	MSG_VALIDATE_SCHEMA_FORCE      = "force specified schema file for validation; overrides inferred schema"
	MSG_VALIDATE_SCHEMA_VARIANT    = "select named schema variant (e.g., \"strict\"); variant must be declared in configuration file (i.e., \"config.json\")"
	MSG_VALIDATE_FLAG_CUSTOM       = "perform custom validation using a custom configuration settings (i.e., \"custom.json\")"
	MSG_VALIDATE_FLAG_ERR_COLORIZE = "Colorize formatted error output (true|false); default true"
	MSG_VALIDATE_FLAG_ERR_LIMIT    = "Limit number of errors output to specified (integer) (default 10)"
	MSG_VALIDATE_FLAG_ERR_FORMAT   = "format error results using the specified format type"
	MSG_VALIDATE_FLAG_ERR_VALUE    = "include details of failing value in error results (bool) (default: true)"
)

var VALIDATE_SUPPORTED_ERROR_FORMATS = MSG_VALIDATE_FLAG_ERR_FORMAT +
	strings.Join([]string{FORMAT_TEXT, FORMAT_JSON, FORMAT_CSV}, ", ") + " (default: txt)"

// limits
const (
	DEFAULT_MAX_ERROR_LIMIT         = 10
	DEFAULT_MAX_ERR_DESCRIPTION_LEN = 128
)

// Protocol
const (
	PROTOCOL_PREFIX_FILE = "file://"
)

func NewCommandValidate() *cobra.Command {
	// NOTE: 'RunE' function takes precedent over 'Run' (anonymous) function if both provided
	var command = new(cobra.Command)
	command.Use = CMD_USAGE_VALIDATE
	command.Short = "Validate input file against its declared BOM schema"
	command.Long = "Validate input file against its declared BOM schema, if detectable and supported."
	command.RunE = validateCmdImpl
	command.Flags().StringVarP(&utils.GlobalFlags.PersistentFlags.OutputFormat, FLAG_FILE_OUTPUT_FORMAT, "", "",
		MSG_VALIDATE_FLAG_ERR_FORMAT+VALIDATE_SUPPORTED_ERROR_FORMATS)
	command.PreRunE = func(cmd *cobra.Command, args []string) error {
		return preRunTestForInputFile(args)
	}
	initCommandValidateFlags(command)
	return command
}

// Add local flags to validate command
func initCommandValidateFlags(command *cobra.Command) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Force a schema file to use for validation (override inferred schema)
	command.Flags().StringVarP(&utils.GlobalFlags.ValidateFlags.ForcedJsonSchemaFile, FLAG_VALIDATE_SCHEMA_FORCE, "", "", MSG_VALIDATE_SCHEMA_FORCE)
	// Optional schema "variant" of inferred schema (e.g, "strict")
	command.Flags().StringVarP(&utils.GlobalFlags.ValidateFlags.SchemaVariant, FLAG_VALIDATE_SCHEMA_VARIANT, "", "", MSG_VALIDATE_SCHEMA_VARIANT)
	// command.Flags().BoolVarP(&utils.GlobalFlags.ValidateFlags.CustomValidation, FLAG_VALIDATE_CUSTOM, "", false, MSG_VALIDATE_FLAG_CUSTOM)
	command.Flags().BoolVarP(&utils.GlobalFlags.ValidateFlags.ColorizeErrorOutput, FLAG_COLORIZE_OUTPUT, "", false, MSG_VALIDATE_FLAG_ERR_COLORIZE)
	command.Flags().IntVarP(&utils.GlobalFlags.ValidateFlags.MaxNumErrors, FLAG_VALIDATE_ERR_LIMIT, "", DEFAULT_MAX_ERROR_LIMIT, MSG_VALIDATE_FLAG_ERR_LIMIT)
	command.Flags().BoolVarP(&utils.GlobalFlags.ValidateFlags.ShowErrorValue, FLAG_VALIDATE_ERR_VALUE, "", true, MSG_VALIDATE_FLAG_ERR_COLORIZE)
	command.Flags().StringVarP(&utils.GlobalFlags.ValidateFlags.ConfigCustomValidationFile, FLAG_VALIDATE_CUSTOM, "", "", MSG_VALIDATE_FLAG_CUSTOM)
}

func validateCmdImpl(cmd *cobra.Command, args []string) error {
	getLogger().Enter()
	defer getLogger().Exit()

	// Create output writer
	outputFilename := utils.GlobalFlags.PersistentFlags.OutputFile
	outputFile, writer, err := createOutputFile(outputFilename)

	// Note: all invalid BOMs (that fail schema validation) MUST result in an InvalidSBOMError()
	if err != nil {
		// TODO: assure this gets normalized
		getLogger().Error(err)
		os.Exit(ERROR_APPLICATION)
	}

	// use function closure to assure consistent error output based upon error type
	defer func() {
		// always close the output file
		if outputFile != nil {
			err = outputFile.Close()
			getLogger().Infof("Closed output file: '%s'", outputFilename)
		}
	}()

	// invoke validate and consistently manage exit messages and codes
	isValid, _, _, err := Validate(writer, utils.GlobalFlags.PersistentFlags, utils.GlobalFlags.ValidateFlags)

	// Note: all invalid BOMs (that fail schema validation) MUST result in an InvalidSBOMError()
	if err != nil {
		if IsInvalidBOMError(err) {
			os.Exit(ERROR_VALIDATION)
		}
		os.Exit(ERROR_APPLICATION)
	}

	// Note: JSON schema validation does NOT return errors so we want to
	// clearly return an invalid return code on exit
	// TODO: remove this if we can assure that we ALWAYS return an
	// IsInvalidSBOMError(err) in these cases from the Validate() method
	if !isValid {
		// TODO: if JSON validation resulted in !valid, turn that into an
		// InvalidSBOMError and test to make sure this works in all cases
		os.Exit(ERROR_VALIDATION)
	}

	// Note: this implies os.Exit(0) as the default from main.go (i.e., bash rc=0)
	return nil
}

// Normalize ErrorTypes from the Validate() function
// Note: this function name should not be changed
func validationError(document *schema.BOM, valid bool, err error) {

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
				_ = getLogger().Errorf("invalid state: error (%T) returned, but BOM valid!", t)
			}
			getLogger().Error(err)
		default:
			getLogger().Tracef("unhandled error type: '%v'", t)
			getLogger().Error(err)
		}
	}

	// ALWAYS output valid/invalid result (as informational)
	message := fmt.Sprintf("document '%s': valid=[%t]", document.GetFilename(), valid)
	getLogger().Info(message)
}

func LoadSchemaDependencies(depSchemaLoader *gojsonschema.SchemaLoader, schemas []schema.FormatSchemaInstance, schemaNames []string) (err error) {
	for _, schemaName := range schemaNames {
		formatSchemaInstance, errMatch := schema.FindMatchingFormatSchemaInstance(
			schemas, schemaName)
		if errMatch != nil {
			return fmt.Errorf("schema '%s' match not found in resources: '%s'", schemaName, schema.SCHEMA_FORMAT_COMMON)
		}
		getLogger().Debugf("Found: '%s': %v", schemaName, formatSchemaInstance)

		getLogger().Infof("Added schema '%s' to loader:...", formatSchemaInstance.File)
		err = AddDependencySchemaToLoader(depSchemaLoader, formatSchemaInstance)
		if err != nil {
			return
		}
	}
	return
}

func AddDependencySchemaToLoader(depSchemaLoader *gojsonschema.SchemaLoader, formatSchemaInstance schema.FormatSchemaInstance) (err error) {
	getLogger().Debugf("Reading schema: '%s'...", formatSchemaInstance.File)
	bSchema, errRead := resources.BOMSchemaFiles.ReadFile(formatSchemaInstance.File)

	if errRead != nil {
		return errRead
	}
	getLogger().Tracef("Adding schema: `%s` byte data to schema loader...", formatSchemaInstance.File)
	// getLogger().Tracef(">> schema byte data:\n %s", bSchema)
	sharedSchemaLoader := gojsonschema.NewBytesLoader(bSchema)
	depSchemaLoader.AddSchema(formatSchemaInstance.Url, sharedSchemaLoader)
	return
}

func LoadCompileSchemaDependencies(
	bomSchemaLoader gojsonschema.JSONLoader,
	bomSchemaInstance schema.FormatSchemaInstance,
	bomSchemaDependencies []string,
) (jsonBOMSchema *gojsonschema.Schema, err error) {

	if len(bomSchemaDependencies) > 0 {
		getLogger().Infof("Found schema dependencies: %v", bomSchemaDependencies)
		// Create a schema loader we will add all dep. schemas into
		depSchemaLoader := gojsonschema.NewSchemaLoader()

		// Load common schema from application resources
		var commonSchemas schema.FormatSchema
		commonSchemas, err = SupportedFormatConfig.FindMatchingFormatSchema(schema.SCHEMA_FORMAT_COMMON)
		if err != nil {
			return
		}
		getLogger().Tracef("Found '%s' schemas: %v", schema.SCHEMA_FORMAT_COMMON, commonSchemas)

		err = LoadSchemaDependencies(depSchemaLoader, commonSchemas.Schemas, bomSchemaDependencies)
		if err != nil {
			return
		}

		// Compile BOM schema (JSON) with the dependency schemas and return it
		getLogger().Infof("Compiling schema: '%s'...", bomSchemaInstance.File)
		jsonBOMSchema, err = depSchemaLoader.Compile(bomSchemaLoader)
		if err != nil {
			return
		}
	}
	return
}

func Validate(writer io.Writer, persistentFlags utils.PersistentCommandFlags, validateFlags utils.ValidateCommandFlags) (valid bool, bom *schema.BOM, schemaErrors []gojsonschema.ResultError, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// use function closure to assure consistent error output based upon error type
	defer func() {
		if err != nil {
			// normalize the error output to console
			validationError(bom, valid, err)
		}
	}()

	// Attempt to load and unmarshal the input file as a Json document
	// Note: JSON syntax errors return "encoding/json.SyntaxError"
	bom, err = LoadInputBOMFileAndDetectSchema()
	if err != nil {
		return INVALID, bom, schemaErrors, err
	}

	// If a custom validation file (e.g., custom.json) is provided on the `--custom` flag
	if validateFlags.ConfigCustomValidationFile != "" {
		validateFlags.CustomValidation = true
	}

	// if "custom" flag exists, then assure we support the format
	if validateFlags.CustomValidation && !bom.FormatInfo.IsCycloneDx() {
		err = schema.NewUnsupportedFormatError(
			schema.MSG_FORMAT_UNSUPPORTED_COMMAND,
			bom.GetFilename(),
			bom.FormatInfo.CanonicalName,
			CMD_VALIDATE,
			FLAG_VALIDATE_CUSTOM)
		return valid, bom, schemaErrors, err
	}

	// Create a loader for the BOM (JSON) document
	var documentLoader gojsonschema.JSONLoader
	var jsonBOMSchemaLoader gojsonschema.JSONLoader
	var errRead, errLoadCompile error
	var bSchema, bDocument []byte

	if bDocument = bom.GetRawBytes(); len(bDocument) > 0 {
		bufferTemp := new(bytes.Buffer)
		// Strip off newlines which the json Decoder dislikes at EOF (as well as extra spaces, etc.)
		if err := json.Compact(bufferTemp, bDocument); err != nil {
			fmt.Println(err)
		}
		documentLoader = gojsonschema.NewBytesLoader(bufferTemp.Bytes())
	} else {
		inputFile := persistentFlags.InputFile
		documentLoader = gojsonschema.NewReferenceLoader(PROTOCOL_PREFIX_FILE + inputFile)
	}

	if documentLoader == nil {
		return INVALID, bom, schemaErrors, fmt.Errorf("unable to load document: '%s'", bom.GetFilename())
	}

	// Regardless of how or where we load JSON schemas from the final
	// we define the overall Schema object used to validate the BOM document
	var jsonBOMSchema *gojsonschema.Schema
	schemaName := bom.SchemaInfo.File

	// If caller "forced" a specific schema file (version), load it instead of
	// any SchemaInfo found in config.json
	forcedSchemaFile := validateFlags.ForcedJsonSchemaFile
	if forcedSchemaFile != "" {
		if !isValidURIPrefix(forcedSchemaFile) {
			// attempt to load as a local file
			forcedSchemaFile = "file://" + forcedSchemaFile
			getLogger().Warningf("invalid schema URI: '%s'.  Attempting to load as a local file...", forcedSchemaFile)
		}

		_, errParseURI := url.ParseRequestURI(forcedSchemaFile)
		if errParseURI != nil {
			errSchemaURI := fmt.Errorf("invalid schema URI: '%s'. %w", forcedSchemaFile, errParseURI)
			return INVALID, bom, schemaErrors, errSchemaURI
		}

		getLogger().Infof("Loading schema from '--force' flag: '%s'...", forcedSchemaFile)
		jsonBOMSchemaLoader = gojsonschema.NewReferenceLoader(forcedSchemaFile)
		getLogger().Infof("Validating document using forced schema (i.e., '--force %s')", forcedSchemaFile)
	} else {
		// Load the matching JSON schema (format, version and variant) from embedded resources
		// i.e., using the matching schema found in config.json (as SchemaInfo)
		getLogger().Infof("Loading schema '%s'...", bom.SchemaInfo.File)
		bSchema, errRead = resources.BOMSchemaFiles.ReadFile(bom.SchemaInfo.File)

		if errRead != nil {
			// we force result to INVALID as any errors from the library means
			// we could NOT actually confirm the input documents validity
			return INVALID, bom, schemaErrors, errRead
		}

		// Create a schema loader for the primary BOM schema file
		jsonBOMSchemaLoader = gojsonschema.NewBytesLoader(bSchema)

		// If the BOM schema has $refs to other schemas, attempt to load and compile
		// them from those included as built-in resources
		jsonBOMSchema, errLoadCompile = LoadCompileSchemaDependencies(jsonBOMSchemaLoader, bom.SchemaInfo, bom.SchemaInfo.Dependencies)
		if err != nil {
			return INVALID, bom, schemaErrors, errLoadCompile
		}
	}

	// At this point we should have a BOM schema loader
	if jsonBOMSchemaLoader == nil {
		// we force result to INVALID as any errors from the library means
		// we could NOT actually confirm the input documents validity
		return INVALID, bom, schemaErrors, fmt.Errorf("unable to read schema: '%s'", schemaName)
	}

	// create a reusable schema object (TODO: validate multiple documents)
	var errLoad error = nil
	const RETRY int = 3

	// we force result to INVALID as any errors from the library means
	// we could NOT actually confirm the input documents validity
	// WARNING: if schemas reference "remote" schemas which are loaded
	// over http... then there is a chance of 503 errors (as the pkg. loads
	// externally referenced schemas over network)... attempt fixed retry...
	if jsonBOMSchema == nil {
		for i := 0; i < RETRY; i++ {
			jsonBOMSchema, errLoad = gojsonschema.NewSchema(jsonBOMSchemaLoader)

			if errLoad == nil {
				break
			}
			getLogger().Warningf("unable to load referenced schema over HTTP: \"%v\"\n retrying...", errLoad)
		}

		if errLoad != nil {
			return INVALID, bom, schemaErrors, fmt.Errorf("unable to load schema: `%s`", schemaName)
		}
	}

	getLogger().Infof("Schema '%s' loaded", schemaName)

	// Validate against the schema and save result determination
	getLogger().Infof("Validating '%s'...", bom.GetFilenameInterpolated())
	result, errValidate := jsonBOMSchema.Validate(documentLoader)

	// ALWAYS set the valid return parameter and provide user an informative message
	valid = result.Valid()
	getLogger().Infof("BOM valid against JSON schema: '%t'", valid)

	// Catch general errors from the validation package/library itself and display them
	if errValidate != nil {
		// we force result to INVALID as any errors from the library means
		// we could NOT actually confirm the input documents validity
		return INVALID, bom, schemaErrors, errValidate
	}

	// Note: actual schema validation errors appear in the 'result' object
	// Save all schema errors found in the 'result' object in an explicit, typed error
	if schemaErrors = result.Errors(); len(schemaErrors) > 0 {
		errInvalid := NewInvalidSBOMError(
			bom,
			MSG_SCHEMA_ERRORS,
			nil,
			schemaErrors)

		// TODO: de-duplicate errors (e.g., array item not "unique"...)
		format := persistentFlags.OutputFormat
		switch format {
		case FORMAT_JSON:
			fallthrough
		case FORMAT_CSV:
			fallthrough
		case FORMAT_TEXT:
			// Note: we no longer add the formatted errors to the actual error "detail" field;
			// since BOMs can have large numbers of errors.  The new method is to allow
			// the user to control the error result output (e.g., file, detail, etc.) via flags
			FormatSchemaErrors(writer, schemaErrors, validateFlags, format)
		default:
			// Notify caller that we are defaulting to "txt" format
			getLogger().Warningf(MSG_WARN_INVALID_FORMAT, format, FORMAT_TEXT)
			FormatSchemaErrors(writer, schemaErrors, validateFlags, FORMAT_TEXT)
		}

		return INVALID, bom, schemaErrors, errInvalid
	}

	// TODO: Perhaps factor in these errors into the JSON output as if they were actual schema errors...
	// Perform additional validation in document composition/structure
	// and "custom" required data within specified fields
	if validateFlags.CustomValidation {
		valid, err = validateCustom(bom, validateFlags, LicensePolicyConfig)
		getLogger().Infof("BOM valid against custom JSON configuration: '%s'", validateFlags.ConfigCustomValidationFile)
	}

	// All validation tests passed; return VALID
	return
}

func validateCustom(document *schema.BOM, validateFlags utils.ValidateCommandFlags, policyConfig *schema.LicensePolicyConfig) (valid bool, err error) {

	// If the validated BOM is of a known format, we can unmarshal it into
	// more convenient typed structures for simplified custom validation
	if document.FormatInfo.IsCycloneDx() {
		document.CdxBom, err = schema.UnMarshalDocument(document.GetJSONMap())
		if err != nil {
			return INVALID, err
		}
	}

	// Perform all custom validation
	// TODO Implement customValidation as an interface supported by the CDXDocument type
	// and later supported by a SPDXDocument type.
	err = validateCustomCDXDocument(document, validateFlags, policyConfig)
	if err != nil {
		// Wrap any specific validation error in a single invalid BOM error
		if !IsInvalidBOMError(err) {
			err = NewInvalidSBOMError(
				document,
				err.Error(),
				err,
				nil)
		}
		// an error implies it is also invalid (according to custom requirements)
		return INVALID, err
	}

	return VALID, nil
}

func isValidURIPrefix(str string) bool {
	// Check for common URI prefixes
	prefixes := []string{"http://", "https://", "file://"}
	for _, prefix := range prefixes {
		if strings.HasPrefix(str, prefix) {
			return true
		}
	}
	return false
}
