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

package schema

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/CycloneDX/sbom-utility/log"
	"github.com/CycloneDX/sbom-utility/resources"
	"github.com/CycloneDX/sbom-utility/utils"
)

const (
	SCHEMA_FORMAT_SPDX      = "SPDX"
	SCHEMA_FORMAT_CYCLONEDX = "CycloneDX"
	SCHEMA_FORMAT_COMMON    = "common"
)

const (
	SCHEMA_VARIANT_LATEST = "(latest)"
)

// Input (source) reserved values
const (
	INPUT_TYPE_STDIN  = "-"
	INPUT_TYPE_STDOUT = "-"
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

func getLogger() *log.MiniLogger {
	if ProjectLogger == nil {
		// TODO: use LDFLAGS to turn on "TRACE" (and require creation of a Logger)
		// ONLY if needed to debug init() methods in the "cmd" package
		ProjectLogger = log.NewLogger(log.ERROR)

		// Attempt to read in '--args' values such as '--trace'
		// Note: if they exist, quiet mode will be overridden
		// Default to ERROR level and, turn on "Quiet mode" for tests
		// This simplifies the test output to simply RUN/PASS|FAIL messages.
		ProjectLogger.InitLogLevelAndModeFromFlags()
	}
	return ProjectLogger
}

// Configs
type BOMFormatAndSchemaConfig struct {
	loadOnce sync.Once
	Formats  []FormatSchema `json:"formats"`
}

// Representation of SBOM format
type FormatSchema struct {
	CanonicalName       string                 `json:"canonicalName"`
	PropertyKeyFormat   string                 `json:"propertyKeyFormat"`
	PropertyKeyVersion  string                 `json:"propertyKeyVersion"`
	PropertyValueFormat string                 `json:"propertyValueFormat"`
	Schemas             []FormatSchemaInstance `json:"schemas"`
}

// Representation of SBOM schema instance
// TODO: add support for schema (Hash) key if we end up having lots of entries
// e.g.,    key string
// where key: SchemaKey{ID_CYCLONEDX, VERSION_CYCLONEDX_1_3, false},
type FormatSchemaInstance struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Development  string   `json:"development"`
	File         string   `json:"file"`
	Url          string   `json:"url"`
	Default      bool     `json:"default"`
	Variant      string   `json:"variant"`
	Format       string   `json:"format"` // value set from parent FormatSchema's `CanonicalName`
	Dependencies []string `json:"dependencies"`
}

func (config *BOMFormatAndSchemaConfig) Reset() {
	config.Formats = nil
}

func (config *BOMFormatAndSchemaConfig) LoadSchemaConfigFile(filename string, defaultFilename string) (err error) {
	getLogger().Enter(filename)
	defer getLogger().Exit()

	// Only load the policy config. once
	config.loadOnce.Do(func() {
		err = config.InnerLoadSchemaConfigFile(filename, defaultFilename)
	})

	return
}

// TODO: Add error messages as constants (for future i18n)
// TODO: Support remote schema retrieval as an optional program flag
// However, we want to default to local for performance where possible
// as well as plan for local, secure bundling of schema with this utility
// in CI build systems (towards improved security, isolated builds)
// NOTE: we have also found that standards orgs. freely move their schema files
// within SCM systems thereby being a cause for remote retrieval failures.
func (config *BOMFormatAndSchemaConfig) InnerLoadSchemaConfigFile(filename string, defaultFilename string) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	var absFilename string
	var buffer []byte

	// Always reset the config if a new format and schema file is loaded
	config.Reset()

	if filename != "" {
		absFilename, err = utils.FindVerifyConfigFileAbsPath(getLogger(), filename)

		if err != nil {
			return fmt.Errorf("unable to find schema config file: '%s'", filename)
		}

		// Attempt to load user-provided config file
		getLogger().Infof("Loading schema config file: '%s'...", absFilename)
		buffer, err = os.ReadFile(absFilename)
		if err != nil {
			return fmt.Errorf("unable to read schema config file: '%s'", absFilename)
		}
	} else {
		// Attempt to load the default config file from embedded file resources
		getLogger().Infof("Loading (embedded) default schema config file: '%s'...", defaultFilename)
		buffer, err = resources.LoadConfigFile(defaultFilename)
		if err != nil {
			return fmt.Errorf("unable to read schema config file: '%s' from embedded resources: '%s'",
				defaultFilename, resources.RESOURCES_CONFIG_DIR)
		}
	}

	//err = json.Unmarshal(buffer, &SupportedFormatConfig)
	err = json.Unmarshal(buffer, config)
	if err != nil {
		return fmt.Errorf("cannot 'Unmarshal': '%s'", absFilename)
	}

	return
}

func (format *FormatSchema) IsSpdx() bool {
	return format.CanonicalName == SCHEMA_FORMAT_SPDX
}

func (format *FormatSchema) IsCycloneDx() bool {
	return format.CanonicalName == SCHEMA_FORMAT_CYCLONEDX
}

func (schemaConfig *BOMFormatAndSchemaConfig) FindFormatAndSchema(bom *BOM) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Iterate over known formats to see if SBOM document contains a known value
	for _, format := range schemaConfig.Formats {

		// See if the format identifier key exists and is a known value
		formatValue, _ := bom.GetKeyValueAsString(format.PropertyKeyFormat)

		if formatValue == format.PropertyValueFormat {
			version, _ := bom.GetKeyValueAsString(format.PropertyKeyVersion)

			// Copy format info into Sbom context
			bom.FormatInfo = format
			err = bom.findSchemaVersionWithVariant(format, version, utils.GlobalFlags.ValidateFlags.SchemaVariant)
			return // success
		}
	}

	// if we reach here, we did not find the format in our configuration (list)
	err = NewUnknownFormatError(bom.filename)
	return
}

func (schemaConfig *BOMFormatAndSchemaConfig) FindMatchingFormatSchema(name string) (formatSchema FormatSchema, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Iterate over configured schema formats to find matching name
	for _, formatSchema = range schemaConfig.Formats {
		if name == formatSchema.CanonicalName {
			return
		}
	}

	// Inform user we could not find a matching schema
	err = NewUnsupportedSchemaError(MSG_CONFIG_SCHEMA_VERSION_NOT_FOUND, name, "", "")
	return
}

func FindMatchingFormatSchemaInstance(formatSchemas []FormatSchemaInstance, schemaName string) (formatSchemaInstance FormatSchemaInstance, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Iterate over known formats to see if SBOM document contains a known value
	for _, formatSchemaInstance = range formatSchemas {
		if schemaName == formatSchemaInstance.Name {
			return
		}
	}

	// if we reach here, we did not find the format in our configuration (list)
	err = NewUnsupportedSchemaError(MSG_CONFIG_SCHEMA_VERSION_NOT_FOUND, schemaName, "", "")
	return
}

// There are multiple variants possible within a given version
func (bom *BOM) findSchemaVersionWithVariant(format FormatSchema, version string, variant string) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()
	var versionExists bool

	// Iterate over known schema versions to see if SBOM's version is supported
	for _, schema := range format.Schemas {
		// Compare requested version to current schema version AND make sure variant matches
		getLogger().Tracef("Comparing SBOM version: '%s' to schema.version: '%s'...", version, schema.Version)
		if version == schema.Version {

			// Make note that we did find a viable matching schema and version
			getLogger().Tracef("Match found for SBOM version: '%s'", version)
			versionExists = true

			// If a variant is also requested, see if we can find one for that criteria
			// Note: the default value for "variant" is an empty string
			if utils.GlobalFlags.ValidateFlags.SchemaVariant == schema.Variant {
				getLogger().Tracef("Match found for requested schema variant: '%s'",
					FormatSchemaVariant(utils.GlobalFlags.ValidateFlags.SchemaVariant))
				bom.SchemaInfo = schema
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
		line, character := utils.CalcLineAndCharacterPos(data, jsonError.Offset)
		// Show intent to not check for error returns as there is no recovery
		_ = getLogger().Errorf("JSON Syntax error: offset: %d, line %d, character %d: %v", jsonError.Offset, line, character, jsonError.Error())

	} else if jsonError, ok := err.(*json.UnmarshalTypeError); ok {
		line, character := utils.CalcLineAndCharacterPos(data, jsonError.Offset)
		// Show intent to not check for error returns as there is no recovery
		_ = getLogger().Errorf("JSON Unmarshal error: offset: %d, line %d, character %d: %v", jsonError.Offset, line, character, jsonError.Error())
	}
}

func FormatSchemaVariant(variant string) (formattedVariant string) {
	var variantName string = SCHEMA_VARIANT_LATEST
	if variant != "" {
		variantName = variant
	}
	formattedVariant = variantName
	return
}
