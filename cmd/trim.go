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
	"io"
	"strings"

	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/CycloneDX/sbom-utility/utils"
	"github.com/spf13/cobra"
)

// parent objects
const (
	SUBCOMMAND_TRIM_DOCUMENT_ROOT       = "root"
	SUBCOMMAND_TRIM_DOCUMENT_COMPONENT  = "component"  // e.g., metadata
	SUBCOMMAND_TRIM_DOCUMENT_COMPONENTS = "components" // e.g., root, tools
	SUBCOMMAND_TRIM_DOCUMENT_SERVICES   = "services"   // e.g., root, tools
	// others: license, releaseNotes, vulnerability, modelCard,
	// (componentData) contents, formula, task, step, command,
	// workspace, volume, trigger, event, inputType, outputType, condition
)

// informational decorators
const (
	SUBCOMMAND_TRIM_EXT_PROPERTIES = "properties"
	// TODO: SUBCOMMAND_TRIM_EXT_EXTERNAL_REFERENCES = "externalReferences"
)

var TRIM_LIST_OUTPUT_SUPPORTED_FORMATS = MSG_SUPPORTED_OUTPUT_FORMATS_HELP +
	strings.Join([]string{FORMAT_JSON}, ", ")

func NewCommandTrim() *cobra.Command {
	var command = new(cobra.Command)
	command.Use = CMD_USAGE_TRIM
	command.Short = "Trim elements from the BOM input file and write to output file"
	command.Long = "Trim elements from the BOM input file and write to output file"
	command.Flags().StringVarP(&utils.GlobalFlags.PersistentFlags.OutputFormat, FLAG_FILE_OUTPUT_FORMAT, "", FORMAT_TEXT,
		TRIM_LIST_OUTPUT_SUPPORTED_FORMATS)
	command.RunE = trimCmdImpl
	command.PreRunE = func(cmd *cobra.Command, args []string) (err error) {
		// Test for required flags (parameters)
		err = preRunTestForInputFile(cmd, args)
		return
	}
	return command
}

func trimCmdImpl(cmd *cobra.Command, args []string) (err error) {
	getLogger().Enter(args)
	defer getLogger().Exit()

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

	if err == nil {
		err = Trim(writer, utils.GlobalFlags.PersistentFlags, utils.GlobalFlags.TrimFlags)
	}

	return
}

// Assure all errors are logged
func processTrimResults(err error) {
	if err != nil {
		// No special processing at this time
		getLogger().Error(err)
	}
}

// NOTE: resourceType has already been validated
func Trim(writer io.Writer, persistentFlags utils.PersistentCommandFlags, trimFlags utils.TrimCommandFlags) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// use function closure to assure consistent error output based upon error type
	defer func() {
		if err != nil {
			processTrimResults(err)
		}
	}()

	// Note: returns error if either file load or unmarshal to JSON map fails
	var document *schema.BOM
	document, err = LoadInputBOMFileAndDetectSchema()
	if err != nil {
		return
	}

	// At this time, fail SPDX format SBOMs as "unsupported" (for "any" format)
	if !document.FormatInfo.IsCycloneDx() {
		err = schema.NewUnsupportedFormatForCommandError(
			document.FormatInfo.CanonicalName,
			document.GetFilename(),
			CMD_LICENSE, FORMAT_ANY)
		return
	}

	if len(trimFlags.Keys) == 0 {
		// TODO create named error type in schema package
		err = getLogger().Errorf("invalid parameter value: missing `keys` value from command")
		return
	}

	// TODO: use a parameter to obtain and normalize  object key names
	document.TrimJsonMap(trimFlags.Keys[0])

	// fully unmarshal the SBOM into named structures
	if err = document.UnmarshalCycloneDXBOM(); err != nil {
		return
	}

	// Output the "trimmed" version of the Input BOM
	format := persistentFlags.OutputFormat
	getLogger().Infof("Outputting listing (`%s` format)...", format)
	switch format {
	case FORMAT_JSON:
		document.MarshalCycloneDXBOM(writer, "", "  ")
	default:
		// Default to Text output for anything else (set as flag default)
		getLogger().Warningf("Stats not supported for `%s` format; defaulting to `%s` format...",
			format, FORMAT_TEXT)
		document.MarshalCycloneDXBOM(writer, "", "  ")
	}

	return
}
