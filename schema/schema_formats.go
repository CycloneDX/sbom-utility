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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"

	"github.com/CycloneDX/sbom-utility/log"
	"github.com/CycloneDX/sbom-utility/utils"
)

const (
	SCHEMA_FORMAT_SPDX      = "SPDX"
	SCHEMA_FORMAT_CYCLONEDX = "CycloneDX"
)

const (
	SCHEMA_VARIANT_LATEST = "(latest)"
)

const (
	ERR_TYPE_UNSUPPORTED_FORMAT = "format not supported"
	ERR_TYPE_UNSUPPORTED_SCHEMA = "schema not supported"
	//MSG_CONFIG_SCHEMA_FORMAT_NOT_FOUND  = "schema format not found in configuration."
	MSG_FORMAT_UNSUPPORTED_UNKNOWN      = "unknown format"
	MSG_FORMAT_UNSUPPORTED_COMMAND      = "for command and/or flags"
	MSG_CONFIG_SCHEMA_VERSION_NOT_FOUND = "schema version not found in configuration"
	MSG_CONFIG_SCHEMA_VARIANT_NOT_FOUND = "schema variant not found in configuration"
)

var (
	ProjectLogger *log.MiniLogger
)

// Globals
var SupportedFormatConfig FormatSchemaConfig

func getLogger() *log.MiniLogger {
	if ProjectLogger == nil {
		// TODO: use LDFLAGS to turn on "TRACE" (and require creation of a Logger)
		// ONLY if needed to debug init() methods in the "cmd" package
		ProjectLogger = log.NewLogger(log.ERROR)

		// Attempt to read in `--args` values such as `--trace`
		// Note: if they exist, quiet mode will be overridden
		// Default to ERROR level and, turn on "Quiet mode" for tests
		// This simplifies the test output to simply RUN/PASS|FAIL messages.
		ProjectLogger.InitLogLevelAndModeFromFlags()
	}
	return ProjectLogger
}

// Representation of SBOM schema instance
// TODO: add support for schema (Hash) key if we end up having lots of entries
// e.g.,    key string
// where key: SchemaKey{ID_CYCLONEDX, VERSION_CYCLONEDX_1_3, false},
type FormatSchemaInstance struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Development string `json:"development"`
	File        string `json:"file"`
	Url         string `json:"url"`
	Default     bool   `json:"default"`
	Variant     string `json:"variant"`
	Format      string `json:"format"` // value set from parent FormatSchema's `CanonicalName`
}

// Representation of SBOM format
type FormatSchema struct {
	CanonicalName       string                 `json:"canonicalName"`
	PropertyKeyFormat   string                 `json:"propertyKeyFormat"`
	PropertyKeyVersion  string                 `json:"propertyKeyVersion"`
	PropertyValueFormat string                 `json:"propertyValueFormat"`
	Schemas             []FormatSchemaInstance `json:"schemas"`
}

// Configs
type FormatSchemaConfig struct {
	Formats []FormatSchema `json:"formats"`
}

// Format/schema error types
type UnsupportedFormatError struct {
	Type      string
	Message   string
	InputFile string
	Format    string
	Version   string
	Variant   string
	Command   string
	Flags     string
}

type UnsupportedSchemaError struct {
	UnsupportedFormatError
}

func NewUnsupportedSchemaError(m string, format string, version string, variant string) *UnsupportedSchemaError {
	var err = new(UnsupportedSchemaError)
	err.Type = ERR_TYPE_UNSUPPORTED_SCHEMA
	err.Message = m
	err.Format = format
	err.Version = version
	err.Variant = variant
	return err
}

func NewUnsupportedFormatError(msg string, f string, fmt string, cmd string, flags string) *UnsupportedFormatError {
	var err = new(UnsupportedFormatError)
	err.Type = ERR_TYPE_UNSUPPORTED_FORMAT
	err.Message = msg
	err.InputFile = f
	err.Format = fmt
	err.Command = cmd
	err.Flags = flags
	return err
}

func NewUnsupportedFormatForCommandError(f string, fmt string, cmd string, flags string) *UnsupportedFormatError {
	var err = new(UnsupportedFormatError)
	err.Type = ERR_TYPE_UNSUPPORTED_FORMAT
	err.Message = MSG_FORMAT_UNSUPPORTED_COMMAND
	err.InputFile = f
	err.Format = fmt
	err.Command = cmd
	err.Flags = flags
	return err
}

func NewUnknownFormatError(f string) *UnsupportedFormatError {
	var err = new(UnsupportedFormatError)
	err.Type = ERR_TYPE_UNSUPPORTED_FORMAT
	err.Message = MSG_FORMAT_UNSUPPORTED_UNKNOWN
	err.InputFile = f
	return err
}

func (err UnsupportedFormatError) Error() string {
	baseMessage := fmt.Sprintf("%s: %s (`%s`)", err.Type, err.Message, err.InputFile)
	if err.Format != "" {
		return fmt.Sprintf("%s: format: `%s`, command: `%s`, flags: `%s`",
			baseMessage,
			err.Format,
			err.Command,
			err.Flags)
	}
	return baseMessage
}

func (err UnsupportedSchemaError) Error() string {
	return fmt.Sprintf("%s: %s: Schema Format: `%s`, Version: `%s`, Variant: `%s` ",
		err.Type,
		err.Message,
		err.Format,
		err.Version,
		err.Variant)
}

// TODO: Add error messages as constants (for future i18n)
// TODO: Support remote schema retrieval as an optional program flag
// However, we want to default to local for performance where possible
// as well as plan for local, secure bundling of schema with this utility
// in CI build systems (towards improved security, isolated builds)
// NOTE: we have also found that standards orgs. freely move their schema files
// within SCM systems thereby being a cause for remote retrieval failures.
func LoadSchemaConfig(filename string) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()
	getLogger().Tracef("filename: `%s`...", filename)

	cfgFilename, err := utils.FindVerifyConfigFileAbsPath(getLogger(), filename)

	if err != nil {
		return fmt.Errorf("unable to find schema config file: `%s`", filename)
	}

	// Note we actively supply informative error messages to help user
	// understand exactly how the load failed
	getLogger().Tracef("Reading schema config file: `%s`...", cfgFilename)
	buffer, err := ioutil.ReadFile(cfgFilename)
	if err != nil {
		return fmt.Errorf("unable to `ReadFile`: `%s`", cfgFilename)
	}

	err = json.Unmarshal(buffer, &SupportedFormatConfig)
	if err != nil {
		return fmt.Errorf("cannot `Unmarshal`: `%s`", cfgFilename)
	}

	return
}

// Candidate SBOM document (context) information
// TODO: rename to SBOM to jive more with Go conventions;
// although it may look like a constant unless we expand the name...
type Sbom struct {
	filename    string
	absFilename string
	rawBytes    []byte
	JsonMap     map[string]interface{}
	FormatInfo  FormatSchema
	SchemaInfo  FormatSchemaInstance
	CdxBom      *CDXBom
}

func (sbom *Sbom) GetRawBytes() []byte {
	return sbom.rawBytes
}

func (format *FormatSchema) IsSpdx() bool {
	return format.CanonicalName == SCHEMA_FORMAT_SPDX
}

func (format *FormatSchema) IsCycloneDx() bool {
	return format.CanonicalName == SCHEMA_FORMAT_CYCLONEDX
}

func NewSbom(inputFile string) *Sbom {
	temp := Sbom{
		filename: inputFile,
	}
	// NOTE: the Map is allocated (i.e., using `make`) as part of `UnmarshalSBOM` method
	return &temp
}

func (sbom *Sbom) GetFilename() string {
	return sbom.filename
}

func (sbom *Sbom) GetJSONMap() map[string]interface{} {
	return sbom.JsonMap
}

func (sbom *Sbom) GetCdxBom() (cdxBom *CDXBom) {
	return sbom.CdxBom
}

func (sbom *Sbom) GetCdxMetadata() (metadata *CDXMetadata) {
	if bom := sbom.GetCdxBom(); bom != nil {
		metadata = bom.Metadata
	}
	return metadata
}

func (sbom *Sbom) GetCdxMetadataProperties() (properties []CDXProperty) {
	if metadata := sbom.GetCdxMetadata(); metadata != nil {
		properties = metadata.Properties
	}
	return properties
}

func (sbom *Sbom) GetCdxComponents() (components []CDXComponent) {
	if bom := sbom.GetCdxBom(); bom != nil {
		components = bom.Components
	}
	return components
}

func (sbom *Sbom) GetCdxServices() (services []CDXService) {
	if bom := sbom.GetCdxBom(); bom != nil {
		services = bom.Services
	}
	return services
}

func (sbom *Sbom) GetCdxMetadataComponent() (component *CDXComponent) {
	if metadata := sbom.GetCdxMetadata(); metadata != nil {
		component = &metadata.Component
	}
	return component
}

func (sbom *Sbom) GetCdxMetadataLicenses() (licenses []CDXLicenseChoice) {
	if metadata := sbom.GetCdxMetadata(); metadata != nil {
		licenses = metadata.Licenses
	}
	return licenses
}

func (sbom *Sbom) GetCdxVulnerabilities() (vulnerabilities []CDXVulnerability) {
	if bom := sbom.GetCdxBom(); bom != nil {
		vulnerabilities = bom.Vulnerabilities
	}
	return vulnerabilities
}

func (sbom *Sbom) GetKeyValueAsString(key string) (sValue string, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	getLogger().Tracef("key: `%s`", key)

	if (sbom.JsonMap) == nil {
		err := fmt.Errorf("document object does not have a Map allocated")
		getLogger().Error(err)
		return "", err
	}
	value := sbom.JsonMap[key]

	if value == nil {
		getLogger().Tracef("key: `%s` not found in document map", key)
		return "", nil
	}

	getLogger().Tracef("value: `%v` (%T)", value, value)
	return value.(string), nil
}

func (sbom *Sbom) UnmarshalSBOMAsJsonMap() error {
	getLogger().Enter()
	defer getLogger().Exit()

	// validate filename
	if len(sbom.filename) == 0 {
		return fmt.Errorf("schema: invalid SBOM filename: `%s`", sbom.filename)
	}

	// Conditionally append working directory if no abs. path detected
	if len(sbom.filename) > 0 && !filepath.IsAbs(sbom.filename) {
		sbom.absFilename = filepath.Join(utils.GlobalFlags.WorkingDir, sbom.filename)
	} else {
		sbom.absFilename = sbom.filename
	}

	// Open our jsonFile
	jsonFile, errOpen := os.Open(sbom.absFilename)

	// if input file cannot be opened, log it and terminate
	if errOpen != nil {
		getLogger().Error(errOpen)
		return errOpen
	}

	// defer the closing of our jsonFile
	defer jsonFile.Close()

	// read our opened jsonFile as a byte array.
	var errReadAll error
	sbom.rawBytes, errReadAll = ioutil.ReadAll(jsonFile)
	if errReadAll != nil {
		getLogger().Error(errReadAll)
	}
	getLogger().Tracef("read data from: `%s`", sbom.filename)
	getLogger().Tracef("\n  >> rawBytes[:100]=[%s]", sbom.rawBytes[:100])

	// Attempt to unmarshal the prospective JSON document to a map
	sbom.JsonMap = make(map[string]interface{})
	errUnmarshal := json.Unmarshal(sbom.rawBytes, &(sbom.JsonMap))
	if errUnmarshal != nil {
		getLogger().Trace(errUnmarshal)
		if syntaxError, ok := errUnmarshal.(*json.SyntaxError); ok {
			line, character := CalcLineAndCharacterPos(sbom.rawBytes, syntaxError.Offset)
			getLogger().Tracef("syntax error found at line,char=[%d,%d]", line, character)
		}
		return errUnmarshal
	}

	// Print the data type of result variable
	getLogger().Tracef("sbom.jsonMap(%s)", reflect.TypeOf(sbom.JsonMap))

	return nil
}

func (sbom *Sbom) UnmarshalCDXSbom() (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Unmarshal as a JSON Map if not done already
	if sbom.JsonMap == nil {
		if err = sbom.UnmarshalSBOMAsJsonMap(); err != nil {
			return
		}
	}

	// Use the JSON Map to unmarshal to CDX-specific types
	sbom.CdxBom, err = UnMarshalDocument(sbom.JsonMap)
	if err != nil {
		return
	}

	return
}

func (sbom *Sbom) FindFormatAndSchema() (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Iterate over known formats to see if SBOM document contains a known value
	for _, format := range SupportedFormatConfig.Formats {

		// See if the format identifier key exists and is a known value
		formatValue, _ := sbom.GetKeyValueAsString(format.PropertyKeyFormat)

		if formatValue == format.PropertyValueFormat {
			version, _ := sbom.GetKeyValueAsString(format.PropertyKeyVersion)

			// Copy format info into Sbom context
			sbom.FormatInfo = format
			err = sbom.findSchemaVersionWithVariant(format, version, utils.GlobalFlags.Variant)
			return
		}
	}

	// if we reach here, we did not find the format in our configuration (list)
	err = NewUnknownFormatError(utils.GlobalFlags.InputFile)
	return
}

// There are multiple variants possible within a given version
func (sbom *Sbom) findSchemaVersionWithVariant(format FormatSchema, version string, variant string) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()
	var versionExists bool

	// Iterate over known schema versions to see if SBOM's version is supported
	for _, schema := range format.Schemas {
		// Compare requested version to current schema version AND make sure variant matches
		getLogger().Tracef("Comparing SBOM version: `%s` to schema.version: `%s`...", version, schema.Version)
		if version == schema.Version {

			// Make note that we did find a viable matching schema and version
			getLogger().Tracef("Match found for SBOM version: `%s`", version)
			versionExists = true

			// If a variant is also requested, see if we can find one for that criteria
			// Note: the default value for "variant" is an empty string
			if utils.GlobalFlags.Variant == schema.Variant {
				getLogger().Tracef("Match found for requested schema variant: `%s`",
					FormatSchemaVariant(utils.GlobalFlags.Variant))
				sbom.SchemaInfo = schema
				return
			}
		}
	}

	// Inform user we could not find a schema in config. to use for validation
	errSchema := NewUnsupportedSchemaError(
		MSG_CONFIG_SCHEMA_VERSION_NOT_FOUND,
		format.CanonicalName,
		version,
		variant)

	// Specifically, we found the (format and) version, just not the requested variant
	if versionExists {
		errSchema.Message = MSG_CONFIG_SCHEMA_VARIANT_NOT_FOUND
	}

	return errSchema
}

func DisplayJSONErrorDetails(data []byte, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	if jsonError, ok := err.(*json.SyntaxError); ok {
		line, character := CalcLineAndCharacterPos(data, jsonError.Offset)
		// Show intent to not check for error returns as there is no recovery
		_ = getLogger().Errorf("JSON Syntax error: offset: %d, line %d, character %d: %v", jsonError.Offset, line, character, jsonError.Error())

	} else if jsonError, ok := err.(*json.UnmarshalTypeError); ok {
		line, character := CalcLineAndCharacterPos(data, jsonError.Offset)
		// Show intent to not check for error returns as there is no recovery
		_ = getLogger().Errorf("JSON Unmarshal error: offset: %d, line %d, character %d: %v", jsonError.Offset, line, character, jsonError.Error())
	}
}

func CalcLineAndCharacterPos(data []byte, offset int64) (lineNum int, charNum int) {
	const LF byte = 0x0a
	lineNum = 1
	charNum = 0
	intOffset := int(offset)

	for i := 0; i < len(data) && i < intOffset; i, charNum = i+1, charNum+1 {

		if data[i] == LF {
			lineNum++
			//fmt.Printf("NEWLINE (%v): total: %d, offset: %d\n", LF, line, char)
			charNum = 0
		}
	}

	return lineNum, charNum - 1
}

func FormatSchemaVariant(variant string) (formattedVariant string) {
	var variantName string = SCHEMA_VARIANT_LATEST
	if variant != "" {
		variantName = variant
	}
	formattedVariant = variantName
	return
}

// TODO: use a Hash map to look up known schemas using the following `SchemaKey`

// Unique Identifier for an SBOM schema
// The prospective JSON document MUST include (at least) 2 identifying property names
// to be a prospective match for a known SBOM schema
// If both property names are found, then their respective values can be used
// to construct a key (i.e., the SchemaKey) into our hashmap of declared schemas
// type SchemaKey struct {
// 	formatId      string
// 	schemaVersion string
// 	strict        bool
// }

// TODO: look into creating a schema interface
// func NewSchemaKey(id string, version string, strict bool) *SchemaKey {
// 	// TODO: is it possible (or necessary) to validate id, version args.
// 	return &SchemaKey{
// 		formatId:      id,
// 		schemaVersion: version,
// 		strict:        strict,
// 	}
// }

// Struct keys, on average, provide best performance taking into
// account flexibility (based upon several documented benchmarks).
// Only concatenated keys (of same literal type) might perform better,
// but are much less idiomatic and prone to key construction errors.
// For example:
// var knownSchemas = map[SchemaKey]SchemaInstance{
// 	{ID_SPDX, VERSION_SPDX_2_2, false}: {
// 		version: VERSION_SPDX_2_2,
// 		file:    SCHEMA_SPDX_2_2_2_LOCAL,
// 		url:     SCHEMA_SPDX_2_2_2_REMOTE,
// 	},
// 	{ID_CYCLONEDX, VERSION_CYCLONEDX_1_3, false}: {
// 		version: VERSION_CYCLONEDX_1_3,
// 		file:    SCHEMA_CYCLONEDX_1_3_LOCAL,
// 		url:     SCHEMA_CYCLONEDX_1_3_REMOTE,
// 	},
// }
