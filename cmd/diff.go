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
	difflib "github.com/pmezard/go-difflib/difflib"
	"github.com/spf13/cobra"
)

// Command help formatting
const (
	FLAG_DIFF_OUTPUT_FORMAT_HELP = "format output using the specified type"
)

// All diff output is produced by github.com/pmezard/go-difflib (BSD-3-Clause).
// FORMAT_TEXT:    line-prefixed (+/-/ ) view of pretty-printed JSON with optional ANSI colour.
// FORMAT_UNIFIED: standard ---/+++/@@ unified diff of pretty-printed JSON.
// FORMAT_JSON:    unified diff wrapped in a JSON envelope with base/revised/modified metadata.
var DIFF_OUTPUT_SUPPORTED_FORMATS = MSG_SUPPORTED_OUTPUT_FORMATS_HELP +
	strings.Join([]string{FORMAT_TEXT, FORMAT_UNIFIED, FORMAT_JSON}, ", ")

// diff flags
const (
	FLAG_DIFF_FILENAME_REVISION       = "input-revision"
	FLAG_DIFF_FILENAME_REVISION_SHORT = "r"
	MSG_FLAG_INPUT_REVISION           = "input filename for the revised file to compare against the base file"
	MSG_FLAG_DIFF_COLORIZE            = "Colorize diff text output (true|false); default false"
)

// ANSI escape sequences used by FORMAT_TEXT colourization.
const (
	ansiReset  = "\x1b[0m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
)

func NewCommandDiff() *cobra.Command {
	var command = new(cobra.Command)
	command.Use = CMD_USAGE_DIFF
	command.Short = "(experimental) Report on differences between two similar BOM files using RFC 6902 format"
	command.Long = "(experimental) Report on differences between two similar BOM files using RFC 6902 format"
	command.Flags().StringVarP(&utils.GlobalFlags.DiffFlags.OutputFormat, FLAG_FILE_OUTPUT_FORMAT, "", FORMAT_TEXT,
		FLAG_DIFF_OUTPUT_FORMAT_HELP+DIFF_OUTPUT_SUPPORTED_FORMATS)
	command.Flags().StringVarP(&utils.GlobalFlags.DiffFlags.RevisedFile,
		FLAG_DIFF_FILENAME_REVISION,
		FLAG_DIFF_FILENAME_REVISION_SHORT,
		"", // no default value (empty)
		MSG_FLAG_INPUT_REVISION)
	command.Flags().BoolVarP(&utils.GlobalFlags.DiffFlags.Colorize, FLAG_COLORIZE_OUTPUT, "", false, MSG_FLAG_DIFF_COLORIZE)
	command.RunE = diffCmdImpl
	command.PreRunE = func(cmd *cobra.Command, args []string) (err error) {
		err = preRunTestForFiles(args)
		return
	}
	return command
}

func preRunTestForFiles(args []string) error {
	getLogger().Enter()
	defer getLogger().Exit()
	getLogger().Tracef("args: %v", args)

	baseFilename := utils.GlobalFlags.PersistentFlags.InputFile
	if baseFilename == "" {
		return getLogger().Errorf("Missing required argument(s): %s", FLAG_FILENAME_INPUT)
	} else if _, err := os.Stat(baseFilename); err != nil { // lgtm[go/path-injection]
		return getLogger().Errorf("File not found: '%s'", baseFilename)
	}

	revisedFilename := utils.GlobalFlags.DiffFlags.RevisedFile
	if revisedFilename == "" {
		return getLogger().Errorf("Missing required argument(s): %s", FLAG_DIFF_FILENAME_REVISION)
	} else if _, err := os.Stat(revisedFilename); err != nil { // lgtm[go/path-injection]
		return getLogger().Errorf("File not found: '%s'", revisedFilename)
	}

	return nil
}

func diffCmdImpl(cmd *cobra.Command, args []string) (err error) {
	getLogger().Enter(args)
	defer getLogger().Exit()

	outputFilename := utils.GlobalFlags.PersistentFlags.OutputFile
	outputFile, writer, err := createOutputFile(outputFilename)
	getLogger().Tracef("outputFile: '%v'; writer: '%v'", outputFile, writer)

	defer func() {
		if outputFile != nil {
			err = outputFile.Close()
			if err != nil {
				return
			}
			getLogger().Infof("Closed output file: '%s'", utils.GlobalFlags.PersistentFlags.OutputFile)
		}
	}()

	err = Diff(utils.GlobalFlags.PersistentFlags, utils.GlobalFlags.DiffFlags)
	if err != nil {
		os.Exit(ERROR_APPLICATION)
	}
	return
}

func Diff(persistentFlags utils.PersistentCommandFlags, flags utils.DiffCommandFlags) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// NOTE: outputFormat is read from DiffFlags.OutputFormat (not PersistentFlags.OutputFormat)
	// to avoid the shared-pointer default-value collision across Cobra subcommands.
	outputFormat := flags.OutputFormat
	inputFilename := persistentFlags.InputFile
	outputFilename := persistentFlags.OutputFile
	revisedFilename := flags.RevisedFile
	colorize := flags.Colorize

	// Create output writer
	outputFile, output, err := createOutputFile(outputFilename)

	defer func() {
		if outputFile != nil {
			err = outputFile.Close()
			getLogger().Infof("Closed output file: '%s'", outputFilename)
		}
	}()

	getLogger().Infof("Reading file (--input-file): '%s' ...", inputFilename)
	// #nosec G304 (suppress warning)
	bBase, errBase := os.ReadFile(inputFilename)
	if errBase != nil {
		err = getLogger().Errorf("Failed to ReadFile '%s': %s", inputFilename, errBase.Error())
		return
	}

	getLogger().Infof("Reading file (--input-revision): '%s' ...", revisedFilename)
	// #nosec G304 (suppress warning)
	bRevised, errRevised := os.ReadFile(revisedFilename)
	if errRevised != nil {
		err = getLogger().Errorf("Failed to ReadFile '%s': %s", revisedFilename, errRevised.Error())
		return
	}

	getLogger().Infof("Comparing files: '%s' (base) to '%s' (revised) ...", inputFilename, revisedFilename)

	var diffString string
	switch outputFormat {
	case FORMAT_TEXT:
		diffString, err = textDiffJSON(bBase, bRevised, colorize)
		if err != nil {
			err = getLogger().Errorf("textDiffJSON() failed: %s", err.Error())
			return
		}
	case FORMAT_UNIFIED:
		diffString, err = unifiedDiffJSON(bBase, bRevised, inputFilename, revisedFilename)
		if err != nil {
			err = getLogger().Errorf("unifiedDiffJSON() failed: %s", err.Error())
			return
		}
	case FORMAT_JSON:
		diffString, err = jsonEnvelopeDiff(bBase, bRevised, inputFilename, revisedFilename)
		if err != nil {
			err = getLogger().Errorf("jsonEnvelopeDiff() failed: %s", err.Error())
			return
		}
	default:
		getLogger().Warningf("Diff output format not supported for '%s' format.", outputFormat)
	}

	if diffString == "" {
		getLogger().Infof("No deltas found. baseFilename: '%s', revisedFilename='%s' match.",
			inputFilename, revisedFilename)
		return
	}

	fmt.Fprintf(output, "%s\n", diffString)
	return
}

// textDiffJSON produces a line-prefixed (+/-/ ) view of the diff between two JSON byte
// slices, using github.com/pmezard/go-difflib's SequenceMatcher on the pretty-printed
// lines. Changed lines are prefixed with '+' (added) or '-' (removed); context lines
// with a space. When colorize is true, removed lines are wrapped in ANSI red and added
// lines in ANSI green (foreground only; terminals reset automatically after each line).
func textDiffJSON(bBase, bRevised []byte, colorize bool) (string, error) {
	prettyBase, err := prettyJSON(bBase)
	if err != nil {
		return "", fmt.Errorf("failed to pretty-print base JSON: %w", err)
	}
	prettyRevised, err := prettyJSON(bRevised)
	if err != nil {
		return "", fmt.Errorf("failed to pretty-print revised JSON: %w", err)
	}

	aLines := difflib.SplitLines(prettyBase)
	bLines := difflib.SplitLines(prettyRevised)

	matcher := difflib.NewMatcher(aLines, bLines)
	groups := matcher.GetGroupedOpCodes(3)

	if len(groups) == 0 {
		return "", nil // files are identical
	}

	var buf strings.Builder
	for _, group := range groups {
		for _, op := range group {
			switch op.Tag {
			case 'e': // equal — emit as context with a space prefix
				for _, line := range aLines[op.I1:op.I2] {
					buf.WriteString(" ")
					buf.WriteString(strings.TrimRight(line, "\n"))
					buf.WriteString("\n")
				}
			case 'd': // delete — lines only in base
				for _, line := range aLines[op.I1:op.I2] {
					stripped := strings.TrimRight(line, "\n")
					if colorize {
						fmt.Fprintf(&buf, "%s-%s%s\n", ansiRed, stripped, ansiReset)
					} else {
						buf.WriteString("-")
						buf.WriteString(stripped)
						buf.WriteString("\n")
					}
				}
			case 'i': // insert — lines only in revised
				for _, line := range bLines[op.J1:op.J2] {
					stripped := strings.TrimRight(line, "\n")
					if colorize {
						fmt.Fprintf(&buf, "%s+%s%s\n", ansiGreen, stripped, ansiReset)
					} else {
						buf.WriteString("+")
						buf.WriteString(stripped)
						buf.WriteString("\n")
					}
				}
			case 'r': // replace — show old lines as removed then new lines as added
				for _, line := range aLines[op.I1:op.I2] {
					stripped := strings.TrimRight(line, "\n")
					if colorize {
						fmt.Fprintf(&buf, "%s-%s%s\n", ansiRed, stripped, ansiReset)
					} else {
						buf.WriteString("-")
						buf.WriteString(stripped)
						buf.WriteString("\n")
					}
				}
				for _, line := range bLines[op.J1:op.J2] {
					stripped := strings.TrimRight(line, "\n")
					if colorize {
						fmt.Fprintf(&buf, "%s+%s%s\n", ansiGreen, stripped, ansiReset)
					} else {
						buf.WriteString("+")
						buf.WriteString(stripped)
						buf.WriteString("\n")
					}
				}
			}
		}
	}

	return buf.String(), nil
}

// jsonEnvelopeDiff wraps the unified diff of two JSON byte slices in a JSON object that
// includes the base/revised filenames, a boolean modified flag, and the diff text itself.
// This gives programmatic consumers a machine-readable document while keeping the single
// go-difflib dependency for all diff output formats.
//
// Output schema:
//
//	{
//	  "base":     "<path to base file>",
//	  "revised":  "<path to revised file>",
//	  "modified": true|false,
//	  "diff":     "<unified diff text, empty string when files are identical>"
//	}
func jsonEnvelopeDiff(bBase, bRevised []byte, fromFile, toFile string) (string, error) {
	diffText, err := unifiedDiffJSON(bBase, bRevised, fromFile, toFile)
	if err != nil {
		return "", err
	}
	envelope := struct {
		Base     string `json:"base"`
		Revised  string `json:"revised"`
		Modified bool   `json:"modified"`
		Diff     string `json:"diff"`
	}{
		Base:     fromFile,
		Revised:  toFile,
		Modified: diffText != "",
		Diff:     diffText,
	}
	out, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// unifiedDiffJSON pretty-prints both JSON byte slices then computes a standard unified
// diff (---/+++/@@ hunk headers) using github.com/pmezard/go-difflib (BSD-3-Clause).
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
