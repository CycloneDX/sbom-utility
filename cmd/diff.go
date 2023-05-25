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
	"io/ioutil"
	"os"
	"strings"

	"github.com/CycloneDX/sbom-utility/utils"
	"github.com/spf13/cobra"
	"github.com/yudai/gojsondiff"
	"github.com/yudai/gojsondiff/formatter"
)

// Command help formatting
const (
	FLAG_DIFF_OUTPUT_FORMAT_HELP = "format output using the specified type"
)

var DIFF_OUTPUT_SUPPORTED_FORMATS = MSG_SUPPORTED_OUTPUT_FORMATS_HELP +
	strings.Join([]string{FORMAT_TEXT, FORMAT_JSON}, ", ")

// validation flags
const (
	FLAG_DIFF_FILENAME_REVISION       = "input-revision"
	FLAG_DIFF_FILENAME_REVISION_SHORT = "r"
	MSG_FLAG_INPUT_REVISION           = "input filename for the revised file to compare against the base file"
)

func NewCommandDiff() *cobra.Command {
	var command = new(cobra.Command)
	command.Use = CMD_USAGE_DIFF
	command.Short = "Report on differences between two BOM files using RFC 6902 format"
	command.Long = "Report on differences between two BOM files using RFC 6902 format"
	command.Flags().StringVarP(&utils.GlobalFlags.OutputFormat, FLAG_FILE_OUTPUT_FORMAT, "", FORMAT_TEXT,
		FLAG_DIFF_OUTPUT_FORMAT_HELP+DIFF_OUTPUT_SUPPORTED_FORMATS)
	command.Flags().StringVarP(&utils.GlobalFlags.DiffFlags.DeltaFile,
		FLAG_DIFF_FILENAME_REVISION,
		FLAG_DIFF_FILENAME_REVISION_SHORT,
		"", // no default value (empty)
		MSG_FLAG_INPUT_REVISION)

	command.RunE = diffCmdImpl
	//command.ValidArgs = VALID_SUBCOMMANDS_RESOURCE
	command.PreRunE = func(cmd *cobra.Command, args []string) (err error) {
		// the command requires at least 1 valid subcommand (argument)
		// if len(args) > 1 {
		// 	return getLogger().Errorf("Too many arguments provided: %v", args)
		// }

		// // Make sure (optional) subcommand is known/valid
		// if len(args) == 1 {
		// 	if !preRunTestForSubcommand(command, VALID_SUBCOMMANDS_RESOURCE, args[0]) {
		// 		return getLogger().Errorf("Subcommand provided is not valid: `%v`", args[0])
		// 	}
		// }

		// if len(args) == 0 {
		// 	getLogger().Tracef("No subcommands provided; defaulting to: `%s` subcommand", SUBCOMMAND_SCHEMA_LIST)
		// }

		// This command can be called with this persistent flag, but does not make sense...
		// inputFile := utils.GlobalFlags.InputFile
		// if inputFile != "" {
		// 	getLogger().Warningf("Invalid flag for command: `%s` (`%s`). Ignoring...", FLAG_FILENAME_OUTPUT, FLAG_FILENAME_OUTPUT_SHORT)
		// }

		// // This command can be called with this persistent flag, but does not make sense...
		// inputFile2 := utils.GlobalFlags.DiffFlags.DeltaFile
		// if inputFile2 != "" {
		// 	getLogger().Warningf("Invalid flag for command: `%s` (`%s`). Ignoring...", FLAG_FILENAME_OUTPUT, FLAG_FILENAME_OUTPUT_SHORT)
		// }

		// Test for required flags (parameters)
		//err = preRunTestForInputFile(cmd, args)
		fmt.Println("TODO: pre-run checks...")

		return
	}
	return command
}

func diffCmdImpl(cmd *cobra.Command, args []string) (err error) {
	getLogger().Enter(args)
	defer getLogger().Exit()

	// Create output writer
	outputFile, writer, err := createOutputFile(utils.GlobalFlags.OutputFile)
	getLogger().Tracef("outputFile: `%v`; writer: `%v`", outputFile, writer)

	// use function closure to assure consistent error output based upon error type
	defer func() {
		// always close the output file
		if outputFile != nil {
			outputFile.Close()
			getLogger().Infof("Closed output file: `%s`", utils.GlobalFlags.OutputFile)
		}
	}()

	format := utils.GlobalFlags.OutputFormat
	baseFilename := utils.GlobalFlags.InputFile
	deltaFilename := utils.GlobalFlags.DiffFlags.DeltaFile

	Diff(baseFilename, deltaFilename, format)

	return
}

func Diff(baseFilename string, deltaFilename string, format string) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Prepare your JSON string as `[]byte`, not `string`
	bBaseData, err := ioutil.ReadFile(baseFilename)
	if err != nil {
		fmt.Printf("Failed to open file '%s': %s\n", utils.GlobalFlags.InputFile, err.Error())
		os.Exit(2)
	}

	// Another JSON string
	bRevisedData, err := ioutil.ReadFile(deltaFilename)
	if err != nil {
		fmt.Printf("Failed to open file '%s': %s\n", utils.GlobalFlags.InputFile, err.Error())
		os.Exit(2)
	}

	// Then, compare them
	differ := gojsondiff.New()
	d, err := differ.Compare(bBaseData, bRevisedData)
	if err != nil {
		fmt.Printf("Failed to unmarshal file: %s\n", err.Error())
		os.Exit(3)
	}

	// Output the result
	var diffString string
	if d.Modified() {

		getLogger().Infof("Outputting listing (`%s` format)...", format)
		switch format {
		case FORMAT_TEXT:
			var aJson map[string]interface{}
			json.Unmarshal(bBaseData, &aJson)

			config := formatter.AsciiFormatterConfig{
				ShowArrayIndex: true,
				Coloring:       true, // TODO: use --colorize flag
			}
			formatter := formatter.NewAsciiFormatter(aJson, config)
			diffString, err = formatter.Format(d)
		case FORMAT_JSON:
			formatter := formatter.NewDeltaFormatter()
			diffString, err = formatter.Format(d)
		default:
			// Default to Text output for anything else (set as flag default)
			getLogger().Warningf("Diff output format not supported for `%s` format.", format)
		}

		fmt.Print(diffString)

	} else {
		fmt.Println("Not modified!")
	}

	return
}
