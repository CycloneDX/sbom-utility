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
	"os"
	"strings"

	"github.com/CycloneDX/sbom-utility/utils"
	diff "github.com/mrutkows/go-jsondiff"
	"github.com/mrutkows/go-jsondiff/formatter"
	difflib "github.com/pmezard/go-difflib/difflib"
	"github.com/spf13/cobra"
)

// Command help formatting
const (
	FLAG_DIFF_OUTPUT_FORMAT_HELP = "format output using the specified type"
)

// FORMAT_UNIFIED uses github.com/pmezard/go-difflib (BSD-3-Clause, already a transitive dep via testify).
// It pretty-prints both JSON files then produces a standard unified diff (---/+++/@@ hunks).
// The existing FORMAT_TEXT and FORMAT_JSON paths are preserved and unchanged.
var DIFF_OUTPUT_SUPPORTED_FORMATS = MSG_SUPPORTED_OUTPUT_FORMATS_HELP +
	strings.Join([]string{FORMAT_TEXT, FORMAT_JSON, FORMAT_UNIFIED}, ", ")

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
	command.Short = "(experimental) Report on differences between two similar BOM files using RFC 6902 format"
	command.Long = "(experimental) Report on differences between two similar BOM files using RFC 6902 format"
	command.Flags().StringVarP(&utils.GlobalFlags.DiffFlags.OutputFormat, FLAG_FILE_OUTPUT_FORMAT, "", FORMAT_UNIFIED,
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
		err = preRunTestForFiles(args)

		return
	}
	return command
}

func preRunTestForFiles(args []string) error {
	getLogger().Enter()
	defer getLogger().Exit()
	getLogger().Tracef("args: %v", args)

	// Make sure the base (input) file is present and exists
	baseFilename := utils.GlobalFlags.PersistentFlags.InputFile
	if baseFilename == "" {
		return getLogger().Errorf("Missing required argument(s): %s", FLAG_FILENAME_INPUT)
	} else if _, err := os.Stat(baseFilename); err != nil {
		return getLogger().Errorf("File not found: '%s'", baseFilename)
	}

	// Make sure the revision file is present and exists
	revisedFilename := utils.GlobalFlags.DiffFlags.RevisedFile
	if revisedFilename == "" {
		return getLogger().Errorf("Missing required argument(s): %s", FLAG_DIFF_FILENAME_REVISION)
	} else if _, err := os.Stat(revisedFilename); err != nil {
		return getLogger().Errorf("File not found: '%s'", revisedFilename)
	}

	return nil
}

func diffCmdImpl(cmd *cobra.Command, args []string) (err error) {
	getLogger().Enter(args)
	defer getLogger().Exit()

	// Create output writer
	outputFilename := utils.GlobalFlags.PersistentFlags.OutputFile
	outputFile, writer, err := createOutputFile(outputFilename)
	getLogger().Tracef("outputFile: '%v'; writer: '%v'", outputFile, writer)

	// use function closure to assure consistent error output based upon error type
	defer func() {
		// always close the output file
		if outputFile != nil {
			err = outputFile.Close()
			if err != nil {
				return
			}
			getLogger().Infof("Closed output file: '%s'", utils.GlobalFlags.PersistentFlags.OutputFile)
		}
	}()

	err = Diff(utils.GlobalFlags.PersistentFlags, utils.GlobalFlags.DiffFlags)
	// Note: we turn diff library panics into errors that should change exit status code
	if err != nil {
		getLogger().Errorf("diff failed: differences between files perhaps too large.")
		os.Exit(ERROR_APPLICATION)
	}
	return
}

func Diff(persistentFlags utils.PersistentCommandFlags, flags utils.DiffCommandFlags) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// create locals
	// NOTE: outputFormat is read from DiffFlags.OutputFormat (not PersistentFlags.OutputFormat)
	// to avoid the shared-pointer default-value collision across Cobra subcommands.
	// PatchCommandFlags uses the same pattern for the same reason.
	outputFormat := flags.OutputFormat
	format := outputFormat // alias used in log messages below
	inputFilename := persistentFlags.InputFile
	outputFilename := persistentFlags.OutputFile
	revisedFilename := flags.RevisedFile
	deltaColorize := flags.Colorize

	// Create output writer
	outputFile, output, err := createOutputFile(outputFilename)

	// use function closure to assure consistent error output based upon error type
	defer func() {
		// always close the output file
		if outputFile != nil {
			err = outputFile.Close()
			getLogger().Infof("Closed output file: '%s'", outputFilename)
		}
	}()

	getLogger().Infof("Reading file (--input-file): '%s' ...", inputFilename)
	// #nosec G304 (suppress warning)
	bBaseData, errReadBase := os.ReadFile(inputFilename)
	if errReadBase != nil {
		if len(bBaseData) > 255 {
			getLogger().Debugf("%v", bBaseData[:255])
		}
		err = getLogger().Errorf("Failed to ReadFile '%s': %s", inputFilename, errReadBase.Error())
		return
	}

	getLogger().Infof("Reading file (--input-revision): '%s' ...", revisedFilename)
	// #nosec G304 (suppress warning)
	bRevisedData, errReadDelta := os.ReadFile(revisedFilename)
	if errReadDelta != nil {
		if len(bRevisedData) > 255 {
			getLogger().Debugf("%v", bRevisedData[:255])
		}
		err = getLogger().Errorf("Failed to ReadFile '%s': %s", revisedFilename, errReadDelta.Error())
		return
	}

	// Compare the base with the revision
	getLogger().Infof("Comparing files: '%s' (base) to '%s' (revised) ...", inputFilename, revisedFilename)
	diffResults, errCompare := compareBinaryData(bBaseData, bRevisedData)
	if errCompare != nil {
		return errCompare
	}

	// Output the result
	var diffString string
	if diffResults.Modified() {
		getLogger().Infof("Outputting listing ('%s' format)...", format)
		switch outputFormat {
		case FORMAT_TEXT:
			var aJson map[string]interface{}
			err = json.Unmarshal(bBaseData, &aJson)

			if err != nil {
				err = getLogger().Errorf("json.Unmarshal() failed '%s': %s", inputFilename, err.Error())
				return
			}

			config := formatter.AsciiFormatterConfig{
				ShowArrayIndex: true,
			}
			config.Coloring = deltaColorize
			formatter := formatter.NewAsciiFormatter(aJson, config)
			diffString, err = formatter.Format(diffResults)
		case FORMAT_JSON:
			formatter := formatter.NewDeltaFormatter()
			diffString, err = formatter.Format(diffResults)
			// Note: JSON data files MUST ends in a newline as this is a POSIX standard

		// FORMAT_UNIFIED: standard unified diff of the pretty-printed JSON.
		// Uses github.com/pmezard/go-difflib (BSD-3-Clause).
		// The existing FORMAT_TEXT (go-jsondiff AsciiFormatter) and FORMAT_JSON (DeltaFormatter)
		// paths above are completely untouched and can be restored as default at any time.
		case FORMAT_UNIFIED:
			diffString, err = unifiedDiffJSON(bBaseData, bRevisedData, inputFilename, revisedFilename)
			if err != nil {
				err = getLogger().Errorf("unifiedDiffJSON() failed: %s", err.Error())
				return
			}
			if diffString == "" {
				// go-difflib returns an empty string when files are identical; report consistently
				getLogger().Infof("No deltas found (unified). baseFilename: '%s', revisedFilename='%s' match.",
					inputFilename, revisedFilename)
				return
			}

		default:
			// Default to Text output for anything else (set as flag default)
			getLogger().Warningf("Diff output format not supported for '%s' format.", format)
		}

		// Output complete diff in either supported format
		fmt.Fprintf(output, "%s\n", diffString)

	} else {
		getLogger().Infof("No deltas found. baseFilename: '%s', revisedFilename='%s' match.",
			inputFilename, revisedFilename)
	}

	return
}

// unifiedDiffJSON pretty-prints both JSON byte slices then computes a standard unified diff
// using github.com/pmezard/go-difflib (BSD-3-Clause licence, already a transitive dep via testify).
// Output contains ---/+++/@@ hunk headers compatible with the GUI DiffHighlighter component.
// The go-jsondiff-based FORMAT_TEXT and FORMAT_JSON paths are not affected.
func unifiedDiffJSON(bBase, bRevised []byte, fromFile, toFile string) (string, error) {
	prettyBase, err := prettyJSON(bBase)
	if err != nil {
		return "", fmt.Errorf("failed to pretty-print base JSON '%s': %w", fromFile, err)
	}
	prettyRevised, err := prettyJSON(bRevised)
	if err != nil {
		return "", fmt.Errorf("failed to pretty-print revised JSON '%s': %w", toFile, err)
	}
	return difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A:        difflib.SplitLines(prettyBase),
		B:        difflib.SplitLines(prettyRevised),
		FromFile: fromFile,
		ToFile:   toFile,
		Context:  3,
	})
}

// prettyJSON re-encodes raw JSON bytes with consistent 4-space indentation so that
// line-oriented diff is meaningful regardless of original whitespace.
func prettyJSON(b []byte) (string, error) {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "    ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func compareBinaryData(bBaseData []byte, bRevisedData []byte) (diffResults diff.Diff, err error) {
	defer func() {
		if recoveredPanic := recover(); recoveredPanic != nil {
			getLogger().Infof("ADVICE: Use the Trim command before Diff to remove highly variable data, such as: \"bom-ref\", \"hashes\" and \"properties\".")
			err = getLogger().Errorf("panic occurred: %v", recoveredPanic)
			return
		}
	}()

	differ := diff.New()
	diffResults, err = differ.Compare(bBaseData, bRevisedData)
	if err != nil {
		err = getLogger().Errorf("differ.Compare() failed: %s", err.Error())
	}
	return
}
