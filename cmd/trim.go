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

// flags (do not translate)
const (
	FLAG_TRIM_PATHS = "paths"
	FLAG_TRIM_KEYS  = "keys"
)

// flag help (translate)
const (
	FLAG_TRIM_OUTPUT_FORMAT_HELP = "format output using the specified type"
	FLAG_TRIM_FROM_PATHS         = "comma-separated list of dot-separated JSON document paths used to scope where trim is applied" +
		"\n - if not present, the default `--from` path is the document \"root\""
	FLAG_TRIM_KEYS_HELP = "comma-separated list of `keys=<key1,key2,...,keyN>` that will be trimmed from the JSON document"
	MSG_TRIM_FLAG_KEYS  = "JSON map keys to trim (delete) (e.g., \"key1,key2,...,keyN\")"
)

var TRIM_OUTPUT_SUPPORTED_FORMATS = MSG_SUPPORTED_OUTPUT_FORMATS_HELP +
	strings.Join([]string{FORMAT_JSON}, ", ")

const (
	TRIM_KEYS_SEP            = ","
	TRIM_PATH_SEP            = "."
	TRIM_PATHS_SEP           = ","
	TRIM_FROM_TOKEN_WILDCARD = "*"
)

func NewCommandTrim() *cobra.Command {
	var command = new(cobra.Command)
	command.Use = CMD_USAGE_TRIM
	command.Short = "(experimental) Trim elements from the BOM input file and write to output file"
	command.Long = "(experimental) Trim elements from the BOM input file and write to output file"
	command.RunE = trimCmdImpl
	command.PreRunE = func(cmd *cobra.Command, args []string) (err error) {
		// Test for required flags (parameters)
		err = preRunTestForInputFile(cmd, args)
		return
	}
	initCommandTrimFlags(command)

	return command
}

func initCommandTrimFlags(command *cobra.Command) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	command.PersistentFlags().StringVar(&utils.GlobalFlags.PersistentFlags.OutputFormat, FLAG_OUTPUT_FORMAT, FORMAT_JSON,
		FLAG_TRIM_OUTPUT_FORMAT_HELP+TRIM_OUTPUT_SUPPORTED_FORMATS)
	command.Flags().StringVarP(&utils.GlobalFlags.TrimFlags.RawPaths, FLAG_TRIM_PATHS, "", "", FLAG_TRIM_FROM_PATHS)
	command.Flags().StringVarP(&utils.GlobalFlags.TrimFlags.RawKeys, FLAG_TRIM_KEYS, "", "", MSG_TRIM_FLAG_KEYS)
	err = command.MarkFlagRequired(FLAG_TRIM_KEYS)
	if err != nil {
		err = getLogger().Errorf("unable to mark flag `%s` as required: %s", FLAG_TRIM_KEYS, err)
	}
	return
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

	// --keys parameter
	if keys := utils.GlobalFlags.TrimFlags.RawKeys; keys != "" {
		utils.GlobalFlags.TrimFlags.Keys = strings.Split(keys, TRIM_KEYS_SEP)
		getLogger().Tracef("Trim: keys: `%v`\n", keys)
	} else {
		getLogger().Tracef("Trim: required parameter NOT found for `%s` flag", FLAG_TRIM_KEYS)
	}

	// --paths parameter
	if paths := utils.GlobalFlags.TrimFlags.RawPaths; paths != "" {
		utils.GlobalFlags.TrimFlags.Paths = strings.Split(paths, TRIM_PATHS_SEP)
		getLogger().Tracef("Trim: paths: `%v`\n", paths)
	} else {
		getLogger().Tracef("Trim: required parameter NOT found for `%s` flag", FLAG_TRIM_PATHS)
	}

	// TODO: limit the "trim" scope using Query() command parameters
	// TODO: i.e., Parse flags into a query request struct:
	// 		var queryRequest *QueryRequest = new(QueryRequest)
	// 		err = queryRequest.readQueryFlags(cmd)
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

	// validate parameters
	if len(trimFlags.Keys) == 0 {
		// TODO create named error type in schema package
		err = getLogger().Errorf("invalid parameter value: missing `keys` value from command")
		return
	}

	// TODO: use a parameter to obtain and normalize object key names
	document.TrimJsonMap(trimFlags.Keys, trimFlags.Paths)

	// fully unmarshal the SBOM into named structures
	// TODO: we should NOT need to unmarshal into BOM structures;
	// instead, see if we can simply Marshal the JSON map directly
	// NOTE: if we do want to "validate" the data at some point we MAY
	// need to unmarshal into CDX structures.
	if err = document.UnmarshalCycloneDXBOM(); err != nil {
		return
	}

	// Output the "trimmed" version of the Input BOM
	format := persistentFlags.OutputFormat
	getLogger().Infof("Outputting listing (`%s` format)...", format)
	switch format {
	case FORMAT_JSON:
		err = document.MarshalCycloneDXBOM(writer, "", "  ")
	default:
		// Default to Text output for anything else (set as flag default)
		getLogger().Warningf("Stats not supported for `%s` format; defaulting to `%s` format...",
			format, FORMAT_TEXT)
		err = document.MarshalCycloneDXBOM(writer, "", "  ")
	}

	return
}
