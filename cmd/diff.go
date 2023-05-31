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
	diff "github.com/mrutkows/go-jsondiff"
	"github.com/mrutkows/go-jsondiff/formatter"
	"github.com/spf13/cobra"
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
	MSG_FLAG_DIFF_COLORIZE            = "Colorize diff text output (true|false); default false"
)

func NewCommandDiff() *cobra.Command {
	var command = new(cobra.Command)
	command.Use = CMD_USAGE_DIFF
	command.Short = "Report on differences between two BOM files using RFC 6902 format"
	command.Long = "Report on differences between two BOM files using RFC 6902 format"
	command.Flags().StringVarP(&utils.GlobalFlags.OutputFormat, FLAG_FILE_OUTPUT_FORMAT, "", FORMAT_TEXT,
		FLAG_DIFF_OUTPUT_FORMAT_HELP+DIFF_OUTPUT_SUPPORTED_FORMATS)
	command.Flags().StringVarP(&utils.GlobalFlags.DiffFlags.RevisedFile,
		FLAG_DIFF_FILENAME_REVISION,
		FLAG_DIFF_FILENAME_REVISION_SHORT,
		"", // no default value (empty)
		MSG_FLAG_INPUT_REVISION)
	command.Flags().BoolVarP(&utils.GlobalFlags.DiffFlags.Colorize, FLAG_COLORIZE_OUTPUT, "", false, MSG_FLAG_DIFF_COLORIZE)
	command.RunE = diffCmdImpl
	command.PreRunE = func(cmd *cobra.Command, args []string) (err error) {
		// Test for required flags (parameters)
		err = preRunTestForFiles(cmd, args)

		return
	}
	return command
}

func preRunTestForFiles(cmd *cobra.Command, args []string) error {
	getLogger().Enter()
	defer getLogger().Exit()
	getLogger().Tracef("args: %v", args)

	// Make sure the base (input) file is present and exists
	baseFilename := utils.GlobalFlags.InputFile
	if baseFilename == "" {
		return getLogger().Errorf("Missing required argument(s): %s", FLAG_FILENAME_INPUT)
	} else if _, err := os.Stat(baseFilename); err != nil {
		return getLogger().Errorf("File not found: `%s`", baseFilename)
	}

	// Make sure the revision file is present and exists
	revisedFilename := utils.GlobalFlags.DiffFlags.RevisedFile
	if revisedFilename == "" {
		return getLogger().Errorf("Missing required argument(s): %s", FLAG_DIFF_FILENAME_REVISION)
	} else if _, err := os.Stat(revisedFilename); err != nil {
		return getLogger().Errorf("File not found: `%s`", revisedFilename)
	}

	return nil
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

	Diff(utils.GlobalFlags)

	return
}

func Diff(flags utils.CommandFlags) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// create locals
	format := utils.GlobalFlags.OutputFormat
	baseFilename := utils.GlobalFlags.InputFile
	outputFilename := utils.GlobalFlags.OutputFile
	outputFormat := utils.GlobalFlags.OutputFormat
	deltaFilename := utils.GlobalFlags.DiffFlags.RevisedFile
	deltaColorize := utils.GlobalFlags.DiffFlags.Colorize

	// Create output writer
	outputFile, output, err := createOutputFile(outputFilename)

	// use function closure to assure consistent error output based upon error type
	defer func() {
		// always close the output file
		if outputFile != nil {
			err = outputFile.Close()
			getLogger().Infof("Closed output file: `%s`", utils.GlobalFlags.OutputFile)
		}
	}()

	// JSON string as `[]byte`, not `string`
	bBaseData, err := ioutil.ReadFile(baseFilename)
	if err != nil {
		getLogger().Debugf("%v", bBaseData[:255])
		getLogger().Errorf("Failed to ReadFile '%s': %s\n", utils.GlobalFlags.InputFile, err.Error())
	}

	bRevisedData, err := ioutil.ReadFile(deltaFilename)
	if err != nil {
		getLogger().Debugf("%v", bRevisedData[:255])
		getLogger().Errorf("Failed to ReadFile '%s': %s\n", utils.GlobalFlags.InputFile, err.Error())
	}

	// Then, compare them
	differ := diff.New()
	d, err := differ.Compare(bBaseData, bRevisedData)
	if err != nil {
		getLogger().Errorf("Failed to Compare data: %s\n", err.Error())
	}

	// Output the result
	var diffString string
	if d.Modified() {

		// TODO: Enable only for debug
		deltas := d.Deltas()
		debugDeltas(deltas, "")

		getLogger().Infof("Outputting listing (`%s` format)...", format)
		switch outputFormat {
		case FORMAT_TEXT:
			var aJson map[string]interface{}
			json.Unmarshal(bBaseData, &aJson)

			config := formatter.AsciiFormatterConfig{
				ShowArrayIndex: true,
			}
			config.Coloring = deltaColorize
			formatter := formatter.NewAsciiFormatter(aJson, config)
			diffString, err = formatter.Format(d)
		case FORMAT_JSON:
			formatter := formatter.NewDeltaFormatter()
			diffString, err = formatter.Format(d)
			// Note: JSON data files MUST ends in a newline s as this is a POSIX standard
		default:
			// Default to Text output for anything else (set as flag default)
			getLogger().Warningf("Diff output format not supported for `%s` format.", format)
		}

		fmt.Fprintf(output, "%s\n", diffString)

	} else {
		getLogger().Infof("No deltas found. baseFilename: `%s`, revisedFilename=`%s` match.",
			utils.GlobalFlags.InputFile,
			utils.GlobalFlags.DiffFlags.RevisedFile)
	}

	return
}

func debugDeltas(deltas []diff.Delta, indent string) (err error) {
	for _, delta := range deltas {
		getLogger().Infof("delta: %v\n", delta)

		sim := delta.Similarity()
		getLogger().Infof("sim: %v\n", sim)

		switch pointer := delta.(type) {
		case *diff.Object:
			getLogger().Infof("diff.Object: %v, PostPosition(): %v, # Deltas: %v\n", pointer, pointer.PostPosition(), len(pointer.Deltas))
			getLogger().Infof("diff.Object: %v, PostPosition(): %v, # Deltas: %v\n", pointer, pointer.PostPosition(), len(pointer.Deltas))
			//deltaJson[d.Position.String()], err = f.formatObject(d.Deltas)
		case *diff.Array:
			getLogger().Infof("diff.Array: %v, PostPosition(): %v (Position: %s), # Deltas: %v\n", pointer, pointer.PostPosition(), pointer.Position, len(pointer.Deltas))
			//deltaJson[d.Position.String()], err = f.formatArray(d.Deltas)
		case *diff.Added:
			getLogger().Infof("Added: %v, PostPosition(): %s (Position: %s)\n", pointer, pointer.PostPosition(), pointer.Position)
			//deltaJson[d.PostPosition().String()] = []interface{}{d.Value}
		case *diff.Modified:
			getLogger().Infof("Modified: %v\n", pointer)
			//deltaJson[d.PostPosition().String()] = []interface{}{d.OldValue, d.NewValue}
		case *diff.TextDiff:
			getLogger().Infof("TextDiff: %v\n", pointer)
			//deltaJson[d.PostPosition().String()] = []interface{}{d.DiffString(), 0, DeltaTextDiff}
		case *diff.Deleted:
			getLogger().Infof("Deleted: %v, PrePosition(): %s, (Position: %s)\n", pointer, pointer.PrePosition(), pointer.Position)
			//deltaJson[d.PrePosition().String()] = []interface{}{d.Value, 0, DeltaDelete}
		case *diff.Moved:
			fmt.Println("Delta type 'Move' is not supported in objects")
		default:
			getLogger().Infof("Unknown Delta type detected: %#v", delta)
		}
	}

	return
}
