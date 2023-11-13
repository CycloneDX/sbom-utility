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
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/CycloneDX/sbom-utility/common"
	"github.com/CycloneDX/sbom-utility/log"
	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/CycloneDX/sbom-utility/utils"
	"github.com/spf13/cobra"
)

// Subcommand flags
// TODO: Support a new --sort <column> flag
const (
	FLAG_LICENSE_SUMMARY = "summary"
)

// License list command flag help messages
const (
	FLAG_LICENSE_LIST_OUTPUT_FORMAT_HELP = "format output using the specified format type"
	FLAG_LICENSE_LIST_SUMMARY_HELP       = "summarize licenses and component references when listing in supported formats"
)

// License list command informational messages
const (
	MSG_OUTPUT_NO_LICENSES_FOUND            = "no licenses found in BOM document"
	MSG_OUTPUT_NO_LICENSES_ONLY_NOASSERTION = "no valid licenses found in BOM document (only licenses marked NOASSERTION)"
)

// "Type", "ID/Name/Expression", "Component(s)", "BOM ref.", "Document location"
// filter keys
const (
	LICENSE_FILTER_KEY_USAGE_POLICY  = "usage-policy"
	LICENSE_FILTER_KEY_LICENSE_TYPE  = "license-type"
	LICENSE_FILTER_KEY_LICENSE       = "license"
	LICENSE_FILTER_KEY_RESOURCE_NAME = "resource-name"
	LICENSE_FILTER_KEY_BOM_REF       = "bom-ref"
	LICENSE_FILTER_KEY_BOM_LOCATION  = "bom-location"
)

var LICENSE_LIST_ROW_DATA = []ColumnFormatData{
	{LICENSE_FILTER_KEY_USAGE_POLICY, DEFAULT_COLUMN_TRUNCATE_LENGTH, REPORT_SUMMARY_DATA_TRUE, false},
	{LICENSE_FILTER_KEY_LICENSE_TYPE, DEFAULT_COLUMN_TRUNCATE_LENGTH, REPORT_SUMMARY_DATA_TRUE, false},
	{LICENSE_FILTER_KEY_LICENSE, DEFAULT_COLUMN_TRUNCATE_LENGTH, REPORT_SUMMARY_DATA_TRUE, false},
	{LICENSE_FILTER_KEY_RESOURCE_NAME, DEFAULT_COLUMN_TRUNCATE_LENGTH, REPORT_SUMMARY_DATA_TRUE, false},
	{LICENSE_FILTER_KEY_BOM_REF, DEFAULT_COLUMN_TRUNCATE_LENGTH, REPORT_SUMMARY_DATA_TRUE, false},
	{LICENSE_FILTER_KEY_BOM_LOCATION, DEFAULT_COLUMN_TRUNCATE_LENGTH, REPORT_SUMMARY_DATA_TRUE, false},
}

var LICENSE_SUMMARY_TITLES = []string{
	LICENSE_FILTER_KEY_USAGE_POLICY,
	LICENSE_FILTER_KEY_LICENSE_TYPE,
	LICENSE_FILTER_KEY_LICENSE,
	LICENSE_FILTER_KEY_RESOURCE_NAME,
	LICENSE_FILTER_KEY_BOM_REF,
	LICENSE_FILTER_KEY_BOM_LOCATION,
}

var VALID_LICENSE_FILTER_KEYS = []string{
	LICENSE_FILTER_KEY_USAGE_POLICY,
	LICENSE_FILTER_KEY_LICENSE_TYPE,
	LICENSE_FILTER_KEY_LICENSE,
	LICENSE_FILTER_KEY_RESOURCE_NAME,
	LICENSE_FILTER_KEY_BOM_REF,
	LICENSE_FILTER_KEY_BOM_LOCATION,
}

// Command help formatting
var LICENSE_LIST_SUPPORTED_FORMATS = MSG_SUPPORTED_OUTPUT_FORMATS_HELP +
	strings.Join([]string{FORMAT_JSON, FORMAT_CSV, FORMAT_MARKDOWN}, ", ") +
	" (default: json)"
var LICENSE_LIST_SUMMARY_SUPPORTED_FORMATS = MSG_SUPPORTED_OUTPUT_FORMATS_SUMMARY_HELP +
	strings.Join([]string{FORMAT_TEXT, FORMAT_CSV, FORMAT_MARKDOWN}, ", ") +
	" (default: txt)"

// Title row names for formatted lists (reports)
var LICENSE_LIST_TITLES_LICENSE_CHOICE = []string{"License.Id", "License.Name", "License.Url", "Expression", "License.Text.ContentType", "License.Text.Encoding", "License.Text.Content"}

// WARNING: Cobra will not recognize a subcommand if its `command.Use` is not a single
// word string that matches one of the `command.ValidArgs` set on the parent command
func NewCommandList() *cobra.Command {
	var command = new(cobra.Command)
	command.Use = CMD_USAGE_LICENSE_LIST
	command.Short = "List licenses found in the BOM input file"
	command.Long = "List licenses and associated policies found in the BOM input file"
	command.Flags().StringVarP(&utils.GlobalFlags.PersistentFlags.OutputFormat, FLAG_FILE_OUTPUT_FORMAT, "", "",
		FLAG_LICENSE_LIST_OUTPUT_FORMAT_HELP+
			LICENSE_LIST_SUPPORTED_FORMATS+
			LICENSE_LIST_SUMMARY_SUPPORTED_FORMATS)
	command.Flags().BoolVarP(
		&utils.GlobalFlags.LicenseFlags.Summary,
		FLAG_LICENSE_SUMMARY, "", false,
		FLAG_LICENSE_LIST_SUMMARY_HELP)
	command.Flags().StringP(FLAG_REPORT_WHERE, "", "", FLAG_REPORT_WHERE_HELP)
	command.RunE = listCmdImpl
	command.PreRunE = func(cmd *cobra.Command, args []string) (err error) {
		if len(args) != 0 {
			return getLogger().Errorf("Too many arguments provided: %v", args)
		}

		// Test for required flags (parameters)
		err = preRunTestForInputFile(cmd, args)
		return
	}
	return (command)
}

// Assure all errors are logged
func processLicenseListResults(err error) {
	if err != nil {
		getLogger().Error(err)
	}
}

func sortLicenseKeys(licenseKeys []interface{}) {
	// Sort by license key (i.e., one of `id`, `name` or `expression`)
	sort.Slice(licenseKeys, func(i, j int) bool {
		return licenseKeys[i].(string) < licenseKeys[j].(string)
	})
}

// NOTE: parm. licenseKeys is actually a string slice
func checkLicenseListEmptyOrNoAssertionOnly(licenseKeys []interface{}) (empty bool) {
	if len(licenseKeys) == 0 {
		empty = true
		getLogger().Warningf("%s\n", MSG_OUTPUT_NO_LICENSES_FOUND)
	} else if len(licenseKeys) == 1 && licenseKeys[0].(string) == LICENSE_NO_ASSERTION {
		empty = true
		getLogger().Warningf("%s\n", MSG_OUTPUT_NO_LICENSES_ONLY_NOASSERTION)
	}
	return
}

// NOTE: The license command ONLY WORKS on CDX format
// NOTE: "list" commands need not validate (only unmarshal)... only report "none found"
// TODO: Perhaps make a --validate flag to allow optional validation prior to listing
func listCmdImpl(cmd *cobra.Command, args []string) (err error) {
	getLogger().Enter(args)
	defer getLogger().Exit()

	// Create output writer
	outputFilename := utils.GlobalFlags.PersistentFlags.OutputFile
	outputFile, writer, err := createOutputFile(outputFilename)

	// use function closure to assure consistent error output based upon error type
	defer func() {
		// always close the output file
		if outputFile != nil {
			err = outputFile.Close()
			getLogger().Infof("Closed output file: `%s`", outputFilename)
		}
	}()

	// process filters supplied on the --where command flag
	whereFilters, err := processWhereFlag(cmd)
	if err != nil {
		return
	}

	// Use global license policy config. as loaded by initConfigurations() as
	// using (optional) filename passed on command line OR the default, built-in config.
	err = ListLicenses(writer, LicensePolicyConfig,
		utils.GlobalFlags.PersistentFlags, utils.GlobalFlags.LicenseFlags,
		whereFilters)

	return
}

func ListLicenses(writer io.Writer, policyConfig *schema.LicensePolicyConfig,
	persistentFlags utils.PersistentCommandFlags, LicenseFlags utils.LicenseCommandFlags,
	whereFilters []common.WhereFilter) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// use function closure to assure consistent error output based upon error type
	defer func() {
		if err != nil {
			processLicenseListResults(err)
		}
	}()

	// Note: returns error if either file load or unmarshal to JSON map fails
	var document *schema.BOM
	document, err = LoadInputBOMFileAndDetectSchema()

	if err != nil {
		return
	}

	// Find an hash all licenses within input BOM file
	getLogger().Infof("Scanning document for licenses...")
	err = loadDocumentLicenses(document, policyConfig, whereFilters)

	if err != nil {
		return
	}

	format := persistentFlags.OutputFormat

	// if `--summary` report requested
	if LicenseFlags.Summary {
		// TODO surface errors returned from "DisplayXXX" functions
		getLogger().Infof("Outputting summary (`%s` format)...", format)
		switch format {
		case FORMAT_TEXT:
			DisplayLicenseListSummaryText(document, writer)
		case FORMAT_CSV:
			err = DisplayLicenseListSummaryCSV(document, writer)
		case FORMAT_MARKDOWN:
			DisplayLicenseListSummaryMarkdown(document, writer)
		default:
			// Default to text output
			getLogger().Warningf("Summary not supported for `%s` format; defaulting to `%s` format...",
				format, FORMAT_TEXT)
			DisplayLicenseListSummaryText(document, writer)
		}
	} else {
		// TODO surface errors returned from "DisplayXXX" functions
		getLogger().Infof("Outputting listing (`%s` format)...", format)
		switch format {
		case FORMAT_JSON:
			DisplayLicenseListJson(document, writer)
		case FORMAT_CSV:
			err = DisplayLicenseListCSV(document, writer)
		case FORMAT_MARKDOWN:
			DisplayLicenseListMarkdown(document, writer)
		case FORMAT_TEXT:
			DisplayLicenseListSummaryText(document, writer)
		default:
			// Default to JSON output for anything else
			getLogger().Warningf("Listing not supported for `%s` format; defaulting to `%s` format...",
				format, FORMAT_JSON)
			DisplayLicenseListJson(document, writer)
		}
	}

	return
}

// NOTE: This list is NOT de-duplicated
// NOTE: if no license are found, the "json.Marshal" method(s) will return a value of "null"
// which is valid JSON (and not an empty array)
// TODO: Support de-duplication (flag) (which MUST be exact using deep comparison)
func DisplayLicenseListJson(bom *schema.BOM, output io.Writer) {
	getLogger().Enter()
	defer getLogger().Exit()

	var licenseInfo schema.LicenseInfo
	var lc []schema.CDXLicenseChoice

	for _, licenseName := range bom.LicenseMap.KeySet() {
		arrLicenseInfo, _ := bom.LicenseMap.Get(licenseName)

		for _, iInfo := range arrLicenseInfo {
			licenseInfo = iInfo.(schema.LicenseInfo)
			if licenseInfo.LicenseChoiceTypeValue != schema.LC_TYPE_INVALID {
				lc = append(lc, licenseInfo.LicenseChoice)
			}
		}
	}
	json, _ := log.FormatInterfaceAsJson(lc)

	// Note: JSON data files MUST ends in a newline as this is a POSIX standard
	fmt.Fprintf(output, "%s\n", json)
}

// NOTE: This list is NOT de-duplicated
func DisplayLicenseListCSV(bom *schema.BOM, output io.Writer) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	var licenseInfo schema.LicenseInfo
	var currentRow []string

	w := csv.NewWriter(output)
	defer w.Flush()

	// Emit title row
	if err = w.Write(LICENSE_LIST_TITLES_LICENSE_CHOICE); err != nil {
		return getLogger().Errorf("error writing to output (%v): %s", LICENSE_LIST_TITLES_LICENSE_CHOICE, err)
	}

	// Emit warning (confirmation) message if no licenses found in document
	licenseKeys := bom.LicenseMap.KeySet()

	// Emit no license or assertion-only warning into output
	checkLicenseListEmptyOrNoAssertionOnly(licenseKeys)

	for _, licenseName := range licenseKeys {
		arrLicenseInfo, _ := bom.LicenseMap.Get(licenseName)

		for _, iInfo := range arrLicenseInfo {
			// reset line after each iteration
			currentRow = nil
			licenseInfo = iInfo.(schema.LicenseInfo)

			if licenseInfo.LicenseChoiceTypeValue != schema.LC_TYPE_INVALID {

				lc := licenseInfo.LicenseChoice

				// Each row will contain every field of a CDX LicenseChoice object
				currentRow = append(currentRow,
					lc.License.Id,
					lc.License.Name,
					lc.License.Url,
					lc.Expression,
					lc.License.Text.ContentType,
					lc.License.Text.Encoding,
					lc.License.Text.Content)

				if errWrite := w.Write(currentRow); errWrite != nil {
					return getLogger().Errorf("error writing to output (%v): %s", currentRow, errWrite)
				}
			}
		}
	}
	return
}

// NOTE: This list is NOT de-duplicated
func DisplayLicenseListMarkdown(bom *schema.BOM, output io.Writer) {
	getLogger().Enter()
	defer getLogger().Exit()

	var licenseInfo schema.LicenseInfo

	// create title row
	titleRow := createMarkdownRow(LICENSE_LIST_TITLES_LICENSE_CHOICE)
	fmt.Fprintf(output, "%s\n", titleRow)

	alignments := createMarkdownColumnAlignment(LICENSE_LIST_TITLES_LICENSE_CHOICE)
	alignmentRow := createMarkdownRow(alignments)
	fmt.Fprintf(output, "%s\n", alignmentRow)

	// Display a warning messing in the actual output and return (short-circuit)
	licenseKeys := bom.LicenseMap.KeySet()

	// Emit no license or assertion-only warning into output
	checkLicenseListEmptyOrNoAssertionOnly(licenseKeys)

	var line []string
	var lineRow string
	var content string

	for _, licenseName := range licenseKeys {
		arrLicenseInfo, _ := bom.LicenseMap.Get(licenseName)

		for _, iInfo := range arrLicenseInfo {
			// Each row will contain every field of a CDX LicenseChoice object
			line = nil
			licenseInfo = iInfo.(schema.LicenseInfo)

			if licenseInfo.LicenseChoiceTypeValue != schema.LC_TYPE_INVALID {
				lc := licenseInfo.LicenseChoice
				content = lc.License.Text.Content

				// Truncate encoded content
				if content != "" {
					content = fmt.Sprintf("%s (truncated from %v) ...", content[0:8], len(content))
				}

				// Format line and write to output
				line = append(line,
					lc.License.Id,
					lc.License.Name,
					lc.License.Url,
					lc.Expression,
					lc.License.Text.ContentType,
					lc.License.Text.Encoding,
					content)

				lineRow = createMarkdownRow(line)
				fmt.Fprintf(output, "%s\n", lineRow)
			}

		}
	}
}

// NOTE: This list is NOT de-duplicated
// TODO: Make policy column optional
// TODO: Add a --no-title flag to skip title output
// TODO: Support a new --sort <column> flag
func DisplayLicenseListSummaryText(bom *schema.BOM, output io.Writer) {
	getLogger().Enter()
	defer getLogger().Exit()

	// initialize tabwriter
	w := new(tabwriter.Writer)
	defer w.Flush()

	// min-width, tab-width, padding, pad-char, flags
	w.Init(output, 8, 2, 2, ' ', 0)

	var licenseInfo schema.LicenseInfo

	// create title row and underline row from slices of optional and compulsory titles
	underlines := createTitleTextSeparators(LICENSE_SUMMARY_TITLES)

	// Add tabs between column titles for the tabWRiter
	fmt.Fprintf(w, "%s\n", strings.Join(LICENSE_SUMMARY_TITLES, "\t"))
	fmt.Fprintf(w, "%s\n", strings.Join(underlines, "\t"))

	// Display a warning missing in the actual output and return (short-circuit)
	licenseKeys := bom.LicenseMap.KeySet()

	// Emit no license or assertion-only warning into output
	checkLicenseListEmptyOrNoAssertionOnly(licenseKeys)

	// Sort license using identifying key (i.e., `id`, `name` or `expression`)
	sortLicenseKeys(licenseKeys)

	for _, licenseName := range licenseKeys {
		arrLicenseInfo, _ := bom.LicenseMap.Get(licenseName)

		for _, iInfo := range arrLicenseInfo {
			licenseInfo = iInfo.(schema.LicenseInfo)

			// Format line and write to output
			fmt.Fprintf(w, "%s\t%v\t%s\t%s\t%s\t%s\n",
				licenseInfo.UsagePolicy,
				licenseInfo.LicenseChoiceType,
				licenseName,
				licenseInfo.ResourceName,
				licenseInfo.BOMRef,
				licenseInfo.BOMLocation,
			)
		}
	}
}

// NOTE: This list is NOT de-duplicated
// TODO: Make policy column optional
// TODO: Add a --no-title flag to skip title output
// TODO: Support a new --sort <column> flag
func DisplayLicenseListSummaryCSV(bom *schema.BOM, output io.Writer) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// initialize writer and prepare the list of entries (i.e., the "rows")
	w := csv.NewWriter(output)
	defer w.Flush()

	var currentRow []string
	var licenseInfo schema.LicenseInfo

	// create title row and underline row
	// TODO: Make policy column optional
	if errWrite := w.Write(LICENSE_SUMMARY_TITLES); errWrite != nil {
		err = getLogger().Errorf("error writing to output (%v): %s", LICENSE_SUMMARY_TITLES, errWrite)
		return
	}

	// retrieve all hashed licenses (keys) found in the document and verify we have ones to process
	licenseKeys := bom.LicenseMap.KeySet()

	// Emit no license or assertion-only warning into output
	checkLicenseListEmptyOrNoAssertionOnly(licenseKeys)

	// Sort license using identifying key (i.e., `id`, `name` or `expression`)
	sortLicenseKeys(licenseKeys)

	// output the each license entry as a row
	for _, licenseName := range licenseKeys {
		arrLicenseInfo, _ := bom.LicenseMap.Get(licenseName)

		// An SBOM SHOULD always contain at least 1 (declared) license
		if len(arrLicenseInfo) == 0 {
			// TODO: pass in sbom document to this fx to (in turn) pass to the error constructor
			getLogger().Error(NewSbomLicenseNotFoundError(nil))
			os.Exit(ERROR_VALIDATION)
		}

		for _, iInfo := range arrLicenseInfo {
			licenseInfo = iInfo.(schema.LicenseInfo)

			// reset line after each iteration
			currentRow = nil

			// Note: For CSV files each row should be terminated by a newline
			// which is automatically done by the CSV writer
			currentRow = append(currentRow,
				licenseInfo.Policy.UsagePolicy,
				licenseInfo.LicenseChoiceType,
				licenseName.(string),
				licenseInfo.ResourceName,
				licenseInfo.BOMRef.String(),
				licenseInfo.BOMLocation,
			)

			if errWrite := w.Write(currentRow); errWrite != nil {
				err = getLogger().Errorf("csvWriter.Write(): %w", errWrite)
				return
			}
		}
	}
	return
}

// NOTE: This list is NOT de-duplicated
// TODO: Make policy column optional
// TODO: Add a --no-title flag to skip title output
// TODO: Support a new --sort <column> flag
func DisplayLicenseListSummaryMarkdown(bom *schema.BOM, output io.Writer) {
	getLogger().Enter()
	defer getLogger().Exit()

	var licenseInfo schema.LicenseInfo

	// create title row
	titleRow := createMarkdownRow(LICENSE_SUMMARY_TITLES)
	fmt.Fprintf(output, "%s\n", titleRow)

	alignments := createMarkdownColumnAlignment(LICENSE_SUMMARY_TITLES)
	alignmentRow := createMarkdownRow(alignments)
	fmt.Fprintf(output, "%s\n", alignmentRow)

	// Display a warning messing in the actual output and return (short-circuit)
	licenseKeys := bom.LicenseMap.KeySet()

	// Emit no license or assertion-only warning into output
	checkLicenseListEmptyOrNoAssertionOnly(licenseKeys)

	// Sort license using identifying key (i.e., `id`, `name` or `expression`)
	sortLicenseKeys(licenseKeys)

	var line []string
	var lineRow string

	for _, licenseName := range licenseKeys {
		arrLicenseInfo, _ := bom.LicenseMap.Get(licenseName)

		for _, iInfo := range arrLicenseInfo {
			licenseInfo = iInfo.(schema.LicenseInfo)

			// reset loop variables for new assignments
			line = nil

			// Format line and write to output
			line = append(line,
				licenseInfo.Policy.UsagePolicy,
				licenseInfo.LicenseChoiceType,
				licenseName.(string),
				licenseInfo.ResourceName,
				licenseInfo.BOMRef.String(),
				licenseInfo.BOMLocation,
			)

			lineRow = createMarkdownRow(line)
			fmt.Fprintf(output, "%s\n", lineRow)
		}
	}
}
