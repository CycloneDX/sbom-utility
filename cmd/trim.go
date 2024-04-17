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
	"io"
	"strings"

	"github.com/CycloneDX/sbom-utility/common"
	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/CycloneDX/sbom-utility/utils"
	"github.com/spf13/cobra"
)

// flags (do not translate)
const (
	FLAG_TRIM_FROM_PATHS = "from"
	FLAG_TRIM_MAP_KEYS   = "keys"
	FLAG_TRIM_NORMALIZE  = "normalize"
)

// flag help (translate)
const (
	MSG_FLAG_TRIM_FROM_PATHS = "comma-separated list of dot-separated JSON document paths used to scope where trim is applied" +
		"\n - if not present, the default `--from` path is the document \"root\""
	MSG_FLAG_TRIM_KEYS = "JSON map keys to trim (delete) (e.g., \"key1,key2,...,keyN\")"
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
	command.Short = "Trim elements from the BOM input file and write resultant BOM to output"
	command.Long = "Trim elements from the BOM input file and write resultant BOM to output"
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
		MSG_FLAG_OUTPUT_FORMAT+TRIM_OUTPUT_SUPPORTED_FORMATS)
	command.PersistentFlags().BoolVar(&utils.GlobalFlags.PersistentFlags.OutputNormalize, FLAG_OUTPUT_NORMALIZE, false, MSG_FLAG_OUTPUT_NORMALIZE)
	command.Flags().StringVarP(&utils.GlobalFlags.TrimFlags.RawPaths, FLAG_TRIM_FROM_PATHS, "", "", MSG_FLAG_TRIM_FROM_PATHS)
	command.Flags().StringVarP(&utils.GlobalFlags.TrimFlags.RawKeys, FLAG_TRIM_MAP_KEYS, "", "", MSG_FLAG_TRIM_KEYS)
	err = command.MarkFlagRequired(FLAG_TRIM_MAP_KEYS)
	if err != nil {
		err = getLogger().Errorf("unable to mark flag `%s` as required: %s", FLAG_TRIM_MAP_KEYS, err)
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
		getLogger().Tracef("Trim: required parameter NOT found for `%s` flag", FLAG_TRIM_MAP_KEYS)
	}

	// --from parameter
	if paths := utils.GlobalFlags.TrimFlags.RawPaths; paths != "" {
		utils.GlobalFlags.TrimFlags.FromPaths = common.ParseFromPaths(paths)
		getLogger().Tracef("Trim: paths: `%v`\n", paths)
	} else {
		getLogger().Tracef("Trim: required parameter NOT found for `%s` flag", FLAG_TRIM_FROM_PATHS)
	}

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
	if document, err = LoadInputBOMFileAndDetectSchema(); err != nil {
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
	if len(trimFlags.Keys) == 0 && !persistentFlags.OutputNormalize {
		// TODO create named error type in schema package
		err = getLogger().Errorf("invalid parameter value: missing `keys` value from command")
		return
	}

	// If no paths are passed, use BOM document root
	if len(trimFlags.FromPaths) == 0 {
		document.TrimBOMKeys(trimFlags.Keys)
	} else {
		// TODO: see if we can make this logic a method on BOM object
		// else, loop through document paths provided by caller
		qr := common.NewQueryRequest()
		// Use query function to obtain BOM document subsets (as JSON maps)
		// using --from path values
		for _, path := range trimFlags.FromPaths {
			qr.SetRawFromPaths(path)
			result, errQuery := QueryJSONMap(document.GetJSONMap(), qr)

			if errQuery != nil {
				getLogger().Errorf("query error: invalid path: %s", path)
				buffer, errEncode := utils.EncodeAnyToDefaultIndentedJSONStr(result)
				if errEncode != nil {
					getLogger().Tracef("result: %s", buffer.String())
				}
			}
			document.TrimEntityKeys(result, trimFlags.Keys)
		}
	}

	// TODO: Investigate if we can simply Marshal the JSON map directly (performance).
	// NOTE: Today we unmarshal() to ensure empty/zero fields are omitted via
	// the custom marshal/unmarshal functions for CycloneDX.
	// NOTE: If we do want to "validate" the BOM data at some point, we MAY
	// need to unmarshal into CDX structures regardless.
	// Fully unmarshal the SBOM into named structures
	if err = document.UnmarshalCycloneDXBOM(); err != nil {
		return
	}

	// Sort slices of BOM if "sort" flag set to true
	if persistentFlags.OutputNormalize {
		// Sort the slices of structures
		if document.GetCdxBom() != nil {
			document.GetCdxBom().Normalize()
		}
	}

	// Output the "trimmed" version of the Input BOM
	format := persistentFlags.OutputFormat
	getLogger().Infof("Writing trimmed BOM (`%s` format)...", format)
	switch format {
	case FORMAT_JSON:
		err = document.WriteAsEncodedJSONInt(writer, utils.GlobalFlags.PersistentFlags.GetOutputIndentInt())
	default:
		// Default to Text output for anything else (set as flag default)
		getLogger().Warningf("Trim not supported for `%s` format; defaulting to `%s` format...",
			format, FORMAT_JSON)
		err = document.WriteAsEncodedJSONInt(writer, utils.GlobalFlags.PersistentFlags.GetOutputIndentInt())
	}

	return
}
