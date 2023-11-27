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
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/CycloneDX/sbom-utility/common"
	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/CycloneDX/sbom-utility/utils"
	"github.com/jwangsadinata/go-multimap/slicemultimap"
	"github.com/spf13/cobra"
)

const (
	SUBCOMMAND_POLICY_LIST = "list"
)

const (
	FLAG_LICENSE_POLICY_LIST_SUMMARY_HELP = "summarize licenses and policies when listing in supported formats"
)

var VALID_SUBCOMMANDS_POLICY = []string{SUBCOMMAND_POLICY_LIST}

// Subcommand flags
// TODO: Support a new --sort <column> flag
const (
	FLAG_POLICY_REPORT_LINE_WRAP = "wrap"
)

// filter keys
const (
	POLICY_FILTER_KEY_USAGE_POLICY = "usage-policy"
	POLICY_FILTER_KEY_FAMILY       = "family"
	POLICY_FILTER_KEY_SPDX_ID      = "id"
	POLICY_FILTER_KEY_NAME         = "name"
	POLICY_FILTER_KEY_OSI_APPROVED = "osi"
	POLICY_FILTER_KEY_FSF_APPROVED = "fsf"
	POLICY_FILTER_KEY_DEPRECATED   = "deprecated"
	POLICY_FILTER_KEY_REFERENCE    = "reference"
	POLICY_FILTER_KEY_ALIASES      = "aliases"
	POLICY_FILTER_KEY_ANNOTATIONS  = "annotations"
	POLICY_FILTER_KEY_NOTES        = "notes"
)

// TODO use to pre-validate --where clause keys
// var POLICY_LIST_TITLES = []string{
// 	POLICY_FILTER_KEY_USAGE_POLICY,
// 	POLICY_FILTER_KEY_FAMILY,
// 	POLICY_FILTER_KEY_SPDX_ID,
// 	POLICY_FILTER_KEY_NAME,
// 	POLICY_FILTER_KEY_OSI_APPROVED,
// 	POLICY_FILTER_KEY_FSF_APPROVED,
// 	POLICY_FILTER_KEY_DEPRECATED,
// 	POLICY_FILTER_KEY_REFERENCE,
// 	POLICY_FILTER_KEY_ALIASES,
// 	POLICY_FILTER_KEY_ANNOTATIONS,
// 	POLICY_FILTER_KEY_NOTES,
// }

// Describe the column data and their attributes and constraints used for formatting
var LICENSE_POLICY_LIST_ROW_DATA = []ColumnFormatData{
	{POLICY_FILTER_KEY_USAGE_POLICY, 16, REPORT_SUMMARY_DATA_TRUE, false},
	{POLICY_FILTER_KEY_FAMILY, 20, REPORT_SUMMARY_DATA_TRUE, false},
	{POLICY_FILTER_KEY_SPDX_ID, 20, REPORT_SUMMARY_DATA_TRUE, false},
	{POLICY_FILTER_KEY_NAME, 20, REPORT_SUMMARY_DATA_TRUE, false},
	{POLICY_FILTER_KEY_OSI_APPROVED, DEFAULT_COLUMN_TRUNCATE_LENGTH, REPORT_SUMMARY_DATA_TRUE, false},
	{POLICY_FILTER_KEY_FSF_APPROVED, DEFAULT_COLUMN_TRUNCATE_LENGTH, REPORT_SUMMARY_DATA_TRUE, false},
	{POLICY_FILTER_KEY_DEPRECATED, DEFAULT_COLUMN_TRUNCATE_LENGTH, REPORT_SUMMARY_DATA_TRUE, false},
	{POLICY_FILTER_KEY_REFERENCE, DEFAULT_COLUMN_TRUNCATE_LENGTH, REPORT_SUMMARY_DATA_TRUE, false},
	{POLICY_FILTER_KEY_ALIASES, 24, false, false},
	{POLICY_FILTER_KEY_ANNOTATIONS, 24, false, false},
	{POLICY_FILTER_KEY_NOTES, 24, false, false},
}

// TODO: remove if we always map the old field names to new ones
// var PROPERTY_MAP_FIELD_TITLE_TO_JSON_KEY = map[string]string{
// 	"usage-policy": "usagePolicy",
// 	"spdx-id":      "id",
// 	"annotations":  "annotationRefs",
// }

// Subcommand flags
const (
	FLAG_POLICY_OUTPUT_FORMAT_HELP    = "format output using the specified type"
	FLAG_POLICY_REPORT_LINE_WRAP_HELP = "toggles the wrapping of text within report column output (default: false)"
)

// License list policy command informational messages
// TODO Use only for Warning messages
const (
	MSG_OUTPUT_NO_POLICIES_FOUND = "no license policies found in BOM document"
)

// Command help formatting
var LICENSE_POLICY_SUPPORTED_FORMATS = MSG_SUPPORTED_OUTPUT_FORMATS_HELP +
	strings.Join([]string{FORMAT_TEXT, FORMAT_CSV, FORMAT_MARKDOWN}, ", ")

// WARNING: Cobra will not recognize a subcommand if its `command.Use` is not a single
// word string that matches one of the `command.ValidArgs` set on the parent command
func NewCommandPolicy() *cobra.Command {
	var command = new(cobra.Command)
	command.Use = CMD_USAGE_LICENSE_POLICY
	command.Short = "List policies associated with known licenses"
	command.Long = "List caller-supplied, \"allow/deny\"-style policies associated with known software, hardware or data licenses"
	command.Flags().StringVarP(&utils.GlobalFlags.PersistentFlags.OutputFormat, FLAG_FILE_OUTPUT_FORMAT, "", FORMAT_TEXT,
		FLAG_POLICY_OUTPUT_FORMAT_HELP+LICENSE_POLICY_SUPPORTED_FORMATS)
	command.Flags().BoolVarP(
		&utils.GlobalFlags.LicenseFlags.Summary, // re-use license flag
		FLAG_LICENSE_SUMMARY, "", false,
		FLAG_LICENSE_POLICY_LIST_SUMMARY_HELP)
	command.Flags().StringP(FLAG_REPORT_WHERE, "", "", FLAG_REPORT_WHERE_HELP)
	command.Flags().BoolVarP(
		&utils.GlobalFlags.LicenseFlags.ListLineWrap,
		FLAG_POLICY_REPORT_LINE_WRAP, "", false,
		FLAG_POLICY_REPORT_LINE_WRAP_HELP)
	command.RunE = policyCmdImpl
	command.PreRunE = func(cmd *cobra.Command, args []string) (err error) {
		// the command requires at least 1 valid subcommand (argument)
		if len(args) > 1 {
			return getLogger().Errorf("Too many arguments provided: %v", args)
		}

		// Make sure (optional) subcommand is known/valid
		if len(args) == 1 {
			if !preRunTestForSubcommand(command, VALID_SUBCOMMANDS_POLICY, args[0]) {
				return getLogger().Errorf("Subcommand provided is not valid: `%v`", args[0])
			}
		}

		if len(args) == 0 {
			getLogger().Tracef("No subcommands provided; defaulting to: `%s` subcommand", SUBCOMMAND_SCHEMA_LIST)
		}

		return
	}
	return command
}

// NOTE: The license command ONLY WORKS on CDX format
func policyCmdImpl(cmd *cobra.Command, args []string) (err error) {
	getLogger().Enter(args)
	defer getLogger().Exit()

	outputFile, writer, err := createOutputFile(utils.GlobalFlags.PersistentFlags.OutputFile)

	// use function closure to assure consistent error output based upon error type
	defer func() {
		// always close the output file
		if outputFile != nil {
			err = outputFile.Close()
			getLogger().Infof("Closed output file: `%s`", utils.GlobalFlags.PersistentFlags.OutputFile)
		}
	}()

	// process filters supplied on the --where command flag
	// TODO: validate if where clauses reference valid column names (filter keys)
	whereFilters, err := processWhereFlag(cmd)
	if err != nil {
		return
	}

	// Use global license policy config. as loaded by initConfigurations() as
	// using (optional) filename passed on command line OR the default, built-in config.
	err = ListLicensePolicies(writer, LicensePolicyConfig,
		utils.GlobalFlags.PersistentFlags, utils.GlobalFlags.LicenseFlags,
		whereFilters)

	return
}

// Assure all errors are logged
func processLicensePolicyListResults(err error) {
	if err != nil {
		getLogger().Error(err)
	}
}

func ListLicensePolicies(writer io.Writer, policyConfig *schema.LicensePolicyConfig,
	persistentFlags utils.PersistentCommandFlags, licenseFlags utils.LicenseCommandFlags,
	whereFilters []common.WhereFilter) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// use function closure to assure consistent error output based upon error type
	defer func() {
		if err != nil {
			processLicensePolicyListResults(err)
		}
	}()

	// Retrieve the subset of policies that match the where filters
	// NOTE: This has the side-effect of mapping alt. policy field name values
	var filteredMap *slicemultimap.MultiMap
	filteredMap, err = policyConfig.GetFilteredFamilyNameMap(whereFilters)

	if err != nil {
		return
	}

	// default output (writer) to standard out
	switch utils.GlobalFlags.PersistentFlags.OutputFormat {
	case FORMAT_DEFAULT:
		// defaults to text if no explicit `--format` parameter
		err = DisplayLicensePoliciesTabbedText(writer, filteredMap, licenseFlags)
	case FORMAT_TEXT:
		err = DisplayLicensePoliciesTabbedText(writer, filteredMap, licenseFlags)
	case FORMAT_CSV:
		err = DisplayLicensePoliciesCSV(writer, filteredMap, licenseFlags)
	case FORMAT_MARKDOWN:
		err = DisplayLicensePoliciesMarkdown(writer, filteredMap, licenseFlags)
	default:
		// default to text format for anything else
		getLogger().Warningf("Unsupported format: `%s`; using default format.",
			utils.GlobalFlags.PersistentFlags.OutputFormat)
		err = DisplayLicensePoliciesTabbedText(writer, filteredMap, licenseFlags)
	}
	return
}

// Display all license policies including those with SPDX IDs and those
// only with "family" names which is reflected in the contents of the
// hashmap keyed on family names.
// NOTE: assumes all entries in the policy config file MUST have family names
// TODO: Allow caller to pass flag to truncate or not (perhaps with value)
// TODO: Add a --no-title flag to skip title output
func DisplayLicensePoliciesTabbedText(writer io.Writer, filteredPolicyMap *slicemultimap.MultiMap, flags utils.LicenseCommandFlags) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// initialize tabwriter
	w := new(tabwriter.Writer)
	defer w.Flush()

	// min-width, tab-width, padding, pad-char, flags
	w.Init(writer, 8, 2, 2, ' ', 0)

	// create title row and underline row from slices of optional and compulsory titles
	titles, underlines := prepareReportTitleData(LICENSE_POLICY_LIST_ROW_DATA, flags.Summary)

	// Add tabs between column titles for the tabWRiter
	fmt.Fprintf(w, "%s\n", strings.Join(titles, "\t"))
	fmt.Fprintf(w, "%s\n", strings.Join(underlines, "\t"))

	// Sort entries for listing by family name keys
	keyNames := filteredPolicyMap.KeySet()
	sort.Slice(keyNames, func(i, j int) bool {
		return keyNames[i].(string) < keyNames[j].(string)
	})

	// output each license policy entry as a line (by sorted key)
	var lines [][]string
	var line []string

	for _, key := range keyNames {
		values, match := filteredPolicyMap.Get(key)
		getLogger().Tracef("%v (%t)", values, match)

		for _, value := range values {

			// Wrap all column text (i.e. flag `--wrap=true`)
			if utils.GlobalFlags.LicenseFlags.ListLineWrap {
				policy := value.(schema.LicensePolicy)

				lines, err = wrapTableRowText(24, ",",
					policy.UsagePolicy,
					policy.Family,
					policy.Id,
					policy.Name,
					policy.IsOsiApproved,
					policy.IsFsfLibre,
					policy.IsDeprecated,
					policy.Reference,
					policy.Aliases,
					policy.AnnotationRefs,
					policy.Notes,
				)

				// TODO: make truncate length configurable
				for _, line := range lines {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
						truncateString(line[0], 16, true),  // usage-policy
						truncateString(line[1], 20, true),  // family
						truncateString(line[2], 20, true),  // id
						truncateString(line[3], 20, true),  // name
						line[4],                            // IsOSIApproved
						line[5],                            // IsFsfLibre
						line[6],                            // IsDeprecated
						truncateString(line[7], 36, true),  // Reference,
						truncateString(line[8], 24, true),  // alias
						truncateString(line[9], 24, true),  // annotation
						truncateString(line[10], 24, true), // note
					)
				}

			} else {
				// TODO surface error data to top-level command
				line, _ = prepareReportLineData(
					value.(schema.LicensePolicy),
					LICENSE_POLICY_LIST_ROW_DATA,
					flags.Summary,
				)
				fmt.Fprintf(w, "%s\n", strings.Join(line, "\t"))

			}
		}
	}
	return
}

// TODO: Add a --no-title flag to skip title output
func DisplayLicensePoliciesCSV(writer io.Writer, filteredPolicyMap *slicemultimap.MultiMap, flags utils.LicenseCommandFlags) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// initialize writer and prepare the list of entries (i.e., the "rows")
	w := csv.NewWriter(writer)
	defer w.Flush()

	// Create title row data as []string
	titles, _ := prepareReportTitleData(LICENSE_POLICY_LIST_ROW_DATA, flags.Summary)

	if err = w.Write(titles); err != nil {
		return getLogger().Errorf("error writing to output (%v): %s", titles, err)
	}

	// Retrieve keys for policies to list
	keyNames := filteredPolicyMap.KeySet()

	// Emit no schemas found warning into output
	// TODO Use only for Warning messages, do not emit in output table
	if len(keyNames) == 0 {
		fmt.Fprintf(writer, "%s\n", MSG_OUTPUT_NO_POLICIES_FOUND)
		return fmt.Errorf(MSG_OUTPUT_NO_POLICIES_FOUND)
	}

	// Sort entries by family name
	sort.Slice(keyNames, func(i, j int) bool {
		return keyNames[i].(string) < keyNames[j].(string)
	})

	var line []string
	for _, key := range keyNames {
		values, match := filteredPolicyMap.Get(key)
		getLogger().Tracef("%v (%t)", values, match)

		for _, value := range values {
			// TODO surface error data to top-level command
			line, _ = prepareReportLineData(
				value.(schema.LicensePolicy),
				LICENSE_POLICY_LIST_ROW_DATA,
				flags.Summary,
			)

			if err = w.Write(line); err != nil {
				err = getLogger().Errorf("csv.Write: %w", err)
			}
		}
	}
	return
}

// TODO: Add a --no-title flag to skip title output
func DisplayLicensePoliciesMarkdown(writer io.Writer, filteredPolicyMap *slicemultimap.MultiMap, flags utils.LicenseCommandFlags) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Create title row data as []string
	titles, _ := prepareReportTitleData(LICENSE_POLICY_LIST_ROW_DATA, flags.Summary)

	// create title row
	titleRow := createMarkdownRow(titles)
	fmt.Fprintf(writer, "%s\n", titleRow)

	alignments := createMarkdownColumnAlignment(titles)
	alignmentRow := createMarkdownRow(alignments)
	fmt.Fprintf(writer, "%s\n", alignmentRow)

	// Retrieve keys for policies to list
	keyNames := filteredPolicyMap.KeySet()

	// Display a warning messing in the actual output and return (short-circuit)
	// Emit no schemas found warning into output
	// TODO Use only for Warning messages, do not emit in output table
	if len(keyNames) == 0 {
		fmt.Fprintf(writer, "%s\n", MSG_OUTPUT_NO_POLICIES_FOUND)
		return fmt.Errorf(MSG_OUTPUT_NO_POLICIES_FOUND)
	}

	// Sort entries by family name
	sort.Slice(keyNames, func(i, j int) bool {
		return keyNames[i].(string) < keyNames[j].(string)
	})

	var line []string
	var lineRow string

	for _, key := range keyNames {
		values, match := filteredPolicyMap.Get(key)
		getLogger().Tracef("%v (%t)", values, match)

		for _, value := range values {
			// TODO surface error data to top-level command
			line, _ = prepareReportLineData(
				value.(schema.LicensePolicy),
				LICENSE_POLICY_LIST_ROW_DATA,
				flags.Summary,
			)
			lineRow = createMarkdownRow(line)
			fmt.Fprintf(writer, "%s\n", lineRow)
		}
	}
	return
}
