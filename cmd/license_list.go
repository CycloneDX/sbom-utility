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

// filter keys
const (
	LICENSE_FILTER_KEY_USAGE_POLICY  = "usage-policy"
	LICENSE_FILTER_KEY_LICENSE_TYPE  = "license-type"
	LICENSE_FILTER_KEY_LICENSE       = "license"
	LICENSE_FILTER_KEY_RESOURCE_NAME = "resource-name"
	LICENSE_FILTER_KEY_BOM_REF       = "bom-ref"
	LICENSE_FILTER_KEY_BOM_LOCATION  = "bom-location"
	LICENSE_FILTER_KEY_PURL          = "purl"
)

// var LICENSE_LIST_TITLES_LICENSE_CHOICE = []string{"License.Id", "License.Name", "License.Url", "Expression", "License.Text.ContentType", "License.Text.Encoding", "License.Text.Content"}
const (
	LICENSE_FILTER_KEY_LICENSE_ID                = "license-id"
	LICENSE_FILTER_KEY_LICENSE_NAME              = "license-name"
	LICENSE_FILTER_KEY_LICENSE_EXPRESSION        = "license-expression"
	LICENSE_FILTER_KEY_LICENSE_URL               = "license-url"
	LICENSE_FILTER_KEY_LICENSE_TEXT_ENCODING     = "license-text-encoding"
	LICENSE_FILTER_KEY_LICENSE_TEXT_CONTENT_TYPE = "license-text-content-type"
	LICENSE_FILTER_KEY_LICENSE_TEXT_CONTENT      = "license-text-content"
)

var LICENSE_LIST_ROW_DATA = []ColumnFormatData{
	*NewColumnFormatData(LICENSE_FILTER_KEY_USAGE_POLICY, REPORT_DO_NOT_TRUNCATE, REPORT_SUMMARY_DATA, false),
	*NewColumnFormatData(LICENSE_FILTER_KEY_LICENSE_TYPE, REPORT_DO_NOT_TRUNCATE, REPORT_SUMMARY_DATA, false),
	*NewColumnFormatData(LICENSE_FILTER_KEY_LICENSE, REPORT_DO_NOT_TRUNCATE, REPORT_SUMMARY_DATA, false),
	*NewColumnFormatData(LICENSE_FILTER_KEY_RESOURCE_NAME, REPORT_DO_NOT_TRUNCATE, REPORT_SUMMARY_DATA, false),
	*NewColumnFormatData(LICENSE_FILTER_KEY_BOM_REF, REPORT_DO_NOT_TRUNCATE, REPORT_SUMMARY_DATA, false),
	*NewColumnFormatData(LICENSE_FILTER_KEY_BOM_LOCATION, REPORT_DO_NOT_TRUNCATE, REPORT_SUMMARY_DATA, false),
	*NewColumnFormatData(LICENSE_FILTER_KEY_LICENSE_ID, -1, false, false),
	*NewColumnFormatData(LICENSE_FILTER_KEY_LICENSE_NAME, -1, false, false),
	*NewColumnFormatData(LICENSE_FILTER_KEY_LICENSE_EXPRESSION, -1, false, false),
	*NewColumnFormatData(LICENSE_FILTER_KEY_LICENSE_URL, -1, false, false),
	*NewColumnFormatData(LICENSE_FILTER_KEY_LICENSE_TEXT_ENCODING, -1, false, false),
	*NewColumnFormatData(LICENSE_FILTER_KEY_LICENSE_TEXT_CONTENT_TYPE, -1, false, false),
	*NewColumnFormatData(LICENSE_FILTER_KEY_LICENSE_TEXT_CONTENT, 8, false, false),
	*NewColumnFormatData(LICENSE_FILTER_KEY_PURL, REPORT_DO_NOT_TRUNCATE, false, false),
}

// Command help formatting
var LICENSE_LIST_SUPPORTED_FORMATS = MSG_SUPPORTED_OUTPUT_FORMATS_HELP +
	strings.Join([]string{FORMAT_JSON, FORMAT_CSV, FORMAT_MARKDOWN}, ", ") +
	" (default: json)"

// WARNING: Cobra will not recognize a subcommand if its `command.Use` is not a single
// word string that matches one of the `command.ValidArgs` set on the parent command
func NewCommandList() *cobra.Command {
	var command = new(cobra.Command)
	command.Use = CMD_USAGE_LICENSE_LIST
	command.Short = "List licenses found in the BOM input file"
	command.Long = "List licenses and associated policies found in the BOM input file"
	command.Flags().StringVarP(&utils.GlobalFlags.PersistentFlags.OutputFormat, FLAG_FILE_OUTPUT_FORMAT, "", "",
		FLAG_LICENSE_LIST_OUTPUT_FORMAT_HELP+
			LICENSE_LIST_SUPPORTED_FORMATS)
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
		err = preRunTestForInputFile(args)
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
			getLogger().Infof("Closed output file: '%s'", outputFilename)
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
	persistentFlags utils.PersistentCommandFlags, licenseFlags utils.LicenseCommandFlags,
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
	err = loadDocumentLicenses(document, policyConfig, whereFilters, licenseFlags)

	if err != nil {
		return
	}

	format := persistentFlags.OutputFormat
	getLogger().Infof("Outputting listing ('%s' format)...", format)
	switch format {
	case FORMAT_JSON:
		err = DisplayLicenseListJson(document, writer, licenseFlags)
	case FORMAT_CSV:
		err = DisplayLicenseListCSV(document, writer, licenseFlags)
	case FORMAT_MARKDOWN:
		err = DisplayLicenseListMarkdown(document, writer, licenseFlags)
	case FORMAT_TEXT:
		err = DisplayLicenseListText(document, writer, licenseFlags)
	default:
		// Default to JSON output for anything else
		getLogger().Warningf("Listing not supported for '%s' format; defaulting to '%s' format...",
			format, FORMAT_JSON)
		err = DisplayLicenseListJson(document, writer, licenseFlags)
	}
	return
}

// NOTE: This list is NOT de-duplicated
// NOTE: if no licenses are found, the "json.Marshal" method(s) will return a value of "null"
// which is valid JSON (and not an empty array)
// TODO: Support de-duplication (flag) (which MUST be exact using deep comparison)
func DisplayLicenseListJson(bom *schema.BOM, writer io.Writer, flags utils.LicenseCommandFlags) (err error) {
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

	// Note: JSON data files MUST ends in a newline as this is a POSIX standard
	// which is already accounted for by the JSON encoder.
	_, err = utils.WriteAnyAsEncodedJSONInt(writer, lc, utils.GlobalFlags.PersistentFlags.GetOutputIndentInt())
	return
}

// NOTE: This list is NOT de-duplicated
// TODO: Make policy column optional
// TODO: Add a --no-title flag to skip title output
// TODO: Support a new --sort <column> flag
func DisplayLicenseListText(bom *schema.BOM, writer io.Writer, flags utils.LicenseCommandFlags) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// initialize tabwriter
	w := new(tabwriter.Writer)
	defer w.Flush()

	// min-width, tab-width, padding, pad-char, flags
	w.Init(writer, 8, 2, 2, ' ', 0)

	// create title row and underline row from slices of optional and compulsory titles
	titles, underlines := prepareReportTitleData(LICENSE_LIST_ROW_DATA, flags.Summary)

	// Add tabs between column titles for the tabWRiter
	fmt.Fprintf(w, "%s\n", strings.Join(titles, "\t"))
	fmt.Fprintf(w, "%s\n", strings.Join(underlines, "\t"))

	// Display a warning missing in the actual output and return (short-circuit)
	licenseKeys := bom.LicenseMap.KeySet()

	// Emit no license or assertion-only warning into output
	checkLicenseListEmptyOrNoAssertionOnly(licenseKeys)

	// Sort license using identifying key (i.e., `id`, `name` or `expression`)
	sortLicenseKeys(licenseKeys)

	// output the each license entry as a row
	var line []string
	var licenseInfo schema.LicenseInfo
	var content string

	for _, licenseName := range licenseKeys {
		arrLicenseInfo, _ := bom.LicenseMap.Get(licenseName)

		// Format each LicenseInfo as a line and write to output
		for _, iInfo := range arrLicenseInfo {
			licenseInfo = iInfo.(schema.LicenseInfo)
			lc := licenseInfo.LicenseChoice

			// NOTE: we only truncate the content text for Text (console) output
			// TODO perhaps add flag to allow user to specify truncate length (default 8)
			// See field "DefaultTruncateLength" in ColumnFormatData struct
			if lc.License != nil && lc.License.Text != nil {
				content = lc.License.Text.GetContentTruncated(8, true)
				licenseInfo.LicenseTextContent = content
			}

			line, err = prepareReportLineData(
				licenseInfo,
				LICENSE_LIST_ROW_DATA,
				flags.Summary,
			)
			// Only emit line if no error
			if err != nil {
				return
			}
			fmt.Fprintf(w, "%s\n", strings.Join(line, "\t"))
		}
	}
	return
}

// NOTE: This list is NOT de-duplicated
// TODO: Make policy column optional
// TODO: Add a --no-title flag to skip title output
// TODO: Support a new --sort <column> flag
func DisplayLicenseListCSV(bom *schema.BOM, writer io.Writer, flags utils.LicenseCommandFlags) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// initialize writer and prepare the list of entries (i.e., the "rows")
	w := csv.NewWriter(writer)
	defer w.Flush()

	// create title row
	// TODO: Make policy column optional
	titles, _ := prepareReportTitleData(LICENSE_LIST_ROW_DATA, flags.Summary)

	if err = w.Write(titles); err != nil {
		return getLogger().Errorf("error writing to output (%v): %s", titles, err)
	}

	// retrieve all hashed licenses (keys) found in the document and verify we have ones to process
	licenseKeys := bom.LicenseMap.KeySet()

	// Emit no license or assertion-only warning into output
	checkLicenseListEmptyOrNoAssertionOnly(licenseKeys)

	// Sort license using identifying key (i.e., `id`, `name` or `expression`)
	sortLicenseKeys(licenseKeys)

	// output the each license entry as a row
	var line []string
	var licenseInfo schema.LicenseInfo

	for _, licenseName := range licenseKeys {
		arrLicenseInfo, _ := bom.LicenseMap.Get(licenseName)

		// An SBOM SHOULD always contain at least 1 (declared) license
		if len(arrLicenseInfo) == 0 {
			// TODO: pass in sbom document to this fx to (in turn) pass to the error constructor
			getLogger().Error(NewSbomLicenseNotFoundError(nil))
			os.Exit(ERROR_VALIDATION)
		}

		// Format each LicenseInfo as a line and write to output
		for _, iInfo := range arrLicenseInfo {
			licenseInfo = iInfo.(schema.LicenseInfo)
			line, err = prepareReportLineData(
				licenseInfo,
				LICENSE_LIST_ROW_DATA,
				flags.Summary,
			)
			// Only emit line if no error
			if err != nil {
				return
			}
			if err = w.Write(line); err != nil {
				err = getLogger().Errorf("csv.Write: %w", err)
			}
		}
	}
	return
}

// NOTE: This list is NOT de-duplicated
func DisplayLicenseListMarkdown(bom *schema.BOM, writer io.Writer, flags utils.LicenseCommandFlags) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	titles, _ := prepareReportTitleData(LICENSE_LIST_ROW_DATA, flags.Summary)
	titleRow := createMarkdownRow(titles)
	fmt.Fprintf(writer, "%s\n", titleRow)

	// create alignment row, include all columns that are flagged "summary" data
	alignments := createMarkdownColumnAlignmentRow(LICENSE_LIST_ROW_DATA, flags.Summary)
	alignmentRow := createMarkdownRow(alignments)
	fmt.Fprintf(writer, "%s\n", alignmentRow)

	// Display a warning messing in the actual output and return (short-circuit)
	licenseKeys := bom.LicenseMap.KeySet()

	// Emit no license or assertion-only warning into output
	checkLicenseListEmptyOrNoAssertionOnly(licenseKeys)

	// output the each license entry as a row
	var line []string
	var lineRow string
	var licenseInfo schema.LicenseInfo

	for _, licenseName := range licenseKeys {
		arrLicenseInfo, _ := bom.LicenseMap.Get(licenseName)

		// Format each LicenseInfo as a line and write to output
		for _, iInfo := range arrLicenseInfo {
			licenseInfo = iInfo.(schema.LicenseInfo)
			line, err = prepareReportLineData(
				licenseInfo,
				LICENSE_LIST_ROW_DATA,
				flags.Summary,
			)
			// Only emit line if no error
			if err != nil {
				return
			}
			lineRow = createMarkdownRow(line)
			fmt.Fprintf(writer, "%s\n", lineRow)
		}
	}
	return
}
