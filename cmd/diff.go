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

	err = Diff(utils.GlobalFlags)

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
	getLogger().Infof("Reading file (--input-file): `%s` ...", baseFilename)
	bBaseData, err := ioutil.ReadFile(baseFilename)
	if err != nil {
		getLogger().Debugf("%v", bBaseData[:255])
		err = getLogger().Errorf("Failed to ReadFile '%s': %s\n", utils.GlobalFlags.InputFile, err.Error())
		return
	}

	getLogger().Infof("Reading file (--input-revision): `%s` ...", deltaFilename)
	bRevisedData, err := ioutil.ReadFile(deltaFilename)
	if err != nil {
		getLogger().Debugf("%v", bRevisedData[:255])
		err = getLogger().Errorf("Failed to ReadFile '%s': %s\n", utils.GlobalFlags.InputFile, err.Error())
		return
	}

	// Then, compare them
	differ := diff.New()
	getLogger().Infof("Comparing files: `%s` (base) to `%s` (revised) ...", baseFilename, deltaFilename)
	d, err := differ.Compare(bBaseData, bRevisedData)
	if err != nil {
		err = getLogger().Errorf("Failed to Compare data: %s\n", err.Error())
	}

	// Output the result
	var diffString string
	if d.Modified() {
		getLogger().Infof("Outputting listing (`%s` format)...", format)
		switch outputFormat {
		case FORMAT_TEXT:
			var aJson map[string]interface{}
			err = json.Unmarshal(bBaseData, &aJson)

			if err != nil {
				err = getLogger().Errorf("json.Unmarshal() failed '%s': %s\n", utils.GlobalFlags.InputFile, err.Error())
				return
			}

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

// func debugDeltas(deltas []diff.Delta, indent string) (err error) {
// 	for _, delta := range deltas {
// 		//fmt.Printf("delta: %v\n", delta)
// 		//sim := delta.Similarity()
// 		//fmt.Printf("sim: %v\n", sim)
//
// 		indent2 := indent + "...."
//
// 		switch pointer := delta.(type) {
// 		case *diff.Object:
// 			fmt.Printf("%s[Object](%v): PostPosition(): \"%v\", # Deltas: %v\n", indent, pointer.Similarity(), ColorizeBackgroundCyan(pointer.PostPosition().String()), len(pointer.Deltas))
// 			debugDeltas(pointer.Deltas, indent2)
// 			//deltaJson[d.Position.String()], err = f.formatObject(d.Deltas)
// 		case *diff.Array:
// 			fmt.Printf("%s[Array](%v): PostPosition(): \"%v\", # Deltas: %v\n", indent, pointer.Similarity(), ColorizeBackgroundCyan((pointer.PostPosition()).String()), len(pointer.Deltas))
// 			debugDeltas(pointer.Deltas, indent2)
// 			//deltaJson[d.Position.String()], err = f.formatArray(d.Deltas)
// 		case *diff.Added:
// 			sValue := fmt.Sprintf("%v", pointer.Value)
// 			fmt.Printf("%s[Added](%v): Value: \"%v\", PostPosition(): \"%v\"\n", indent, pointer.Similarity(), ColorizeBackgroundGreen(sValue), ColorizeBackgroundCyan((pointer.PostPosition()).String()))
// 			//deltaJson[d.PostPosition().String()] = []interface{}{d.Value}
// 		case *diff.Modified:
// 			fmt.Printf("%s[Modified](%v): PostPosition: \"%v\", OldValue: \"%v\", NewValue: \"%v\"\n", indent, pointer.Similarity(), ColorizeBackgroundCyan((pointer.PostPosition()).String()), ColorizeBackgroundRed((pointer.OldValue).(string)), ColorizeBackgroundGreen((pointer.NewValue).(string)))
// 			//deltaJson[d.PostPosition().String()] = []interface{}{d.OldValue, d.NewValue}
// 		case *diff.TextDiff:
// 			fmt.Printf("%s[TextDiff](%v): PostPosition: \"%v\", OldValue: \"%v\", NewValue: \"%v\"\n", indent, pointer.Similarity(), ColorizeBackgroundCyan((pointer.PostPosition()).String()), ColorizeBackgroundRed((pointer.OldValue).(string)), ColorizeBackgroundGreen((pointer.NewValue).(string)))
// 			//deltaJson[d.PostPosition().String()] = []interface{}{d.DiffString(), 0, DeltaTextDiff}
// 		case *diff.Deleted:
// 			sValue := fmt.Sprintf("%v", pointer.Value)
// 			fmt.Printf("%s[Deleted](%v): Value: \"%v\", PrePosition(): \"%v\"\n", indent, pointer.Similarity(), ColorizeBackgroundRed(sValue), ColorizeBackgroundCyan(pointer.PrePosition().String()))
// 			//deltaJson[d.PrePosition().String()] = []interface{}{d.Value, 0, DeltaDelete}
// 		case *diff.Moved:
// 			sValue := fmt.Sprintf("%v", pointer.Value)
// 			fmt.Printf("%s[Moved](%v): Value: \"%v\", PrePosition(): \"%v\", PostPosition(): \"%v\"\n", indent, pointer.Similarity(), ColorizeBackgroundYellow(sValue), ColorizeBackgroundCyan(pointer.PrePosition().String()), ColorizeBackgroundCyan(pointer.PostPosition().String()))
// 			fmt.Printf("%s[ERROR] 'Move' operation NOT supported for formatting objects\n", indent)
// 		default:
// 			fmt.Printf("%sUnknown Delta type detected: \"%T\"\n", indent, delta)
// 		}
// 	}
//
// 	return
// }

// Validate value (range)
// func Colorize(color string, text string) (colorizedText string) {
// 	return color + text + Reset
// }

// func ColorizeBackgroundRed(text string) (colorizedText string) {
// 	return BG_Red + text + Reset
// }

// func ColorizeBackgroundGreen(text string) (colorizedText string) {
// 	return BG_Green + text + Reset
// }

// func ColorizeBackgroundYellow(text string) (colorizedText string) {
// 	return BG_Yellow + text + Reset
// }

// func ColorizeBackgroundCyan(text string) (colorizedText string) {
// 	return BG_Cyan + text + Reset
// }

// func ColorizeBackgroundBlue(text string) (colorizedText string) {
// 	return BG_Blue + text + Reset
// }

// // See: https://www.lihaoyi.com/post/BuildyourownCommandLinewithANSIescapecodes.html
// const (
// 	Reset         = "\033[0m"
// 	FG_Red        = "\033[31m"
// 	FG_Green      = "\033[32m"
// 	FG_Yellow     = "\033[33m"
// 	FG_Cyan       = "\033[36m"
// 	FG_Gray       = "\033[37m"
// 	FG_White      = "\033[97m"
// 	FG_LightWhite = "\033[39m"
// 	FG_Default    = FG_LightWhite // often default for terminal "white" foreground
// 	BG_Red        = "\033[41m"
// 	BG_Green      = "\033[42m"
// 	BG_Yellow     = "\033[43m"
// 	BG_Blue       = "\033[44m"
// 	BG_Magenta    = "\033[45m"
// 	BG_Cyan       = "\033[46m"
// 	BG_White      = "\033[47m"
// 	BG_Default    = "\033[49m"
// )