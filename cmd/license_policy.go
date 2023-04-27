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

	"github.com/CycloneDX/sbom-utility/utils"
	"github.com/jwangsadinata/go-multimap/slicemultimap"
	"github.com/spf13/cobra"
)

const (
	SUBCOMMAND_POLICY_LIST = "list"
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
	POLICY_FILTER_KEY_ANNOTATIONS  = "annotations"
	POLICY_FILTER_KEY_ALIASES      = "aliases"
	POLICY_FILTER_KEY_NOTES        = "notes"
)

var POLICY_LIST_TITLES = []string{
	POLICY_FILTER_KEY_USAGE_POLICY,
	POLICY_FILTER_KEY_FAMILY,
	POLICY_FILTER_KEY_SPDX_ID,
	POLICY_FILTER_KEY_NAME,
	POLICY_FILTER_KEY_ANNOTATIONS,
	POLICY_FILTER_KEY_ALIASES,
	POLICY_FILTER_KEY_NOTES,
}
var VALID_POLICY_WHERE_FILTER_KEYS = []string{
	POLICY_FILTER_KEY_USAGE_POLICY,
	POLICY_FILTER_KEY_FAMILY,
	POLICY_FILTER_KEY_SPDX_ID,
	POLICY_FILTER_KEY_NAME,
	POLICY_FILTER_KEY_ANNOTATIONS,
	POLICY_FILTER_KEY_ALIASES,
	POLICY_FILTER_KEY_NOTES,
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
	command.Flags().StringVarP(&utils.GlobalFlags.OutputFormat, FLAG_FILE_OUTPUT_FORMAT, "", FORMAT_TEXT,
		FLAG_POLICY_OUTPUT_FORMAT_HELP+LICENSE_POLICY_SUPPORTED_FORMATS)
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

	outputFile, writer, err := createOutputFile(utils.GlobalFlags.OutputFile)

	// use function closure to assure consistent error output based upon error type
	defer func() {
		// always close the output file
		if outputFile != nil {
			err = outputFile.Close()
			getLogger().Infof("Closed output file: `%s`", utils.GlobalFlags.OutputFile)
		}
	}()

	// process filters supplied on the --where command flag
	whereFilters, err := processWhereFlag(cmd)

	if err == nil {
		err = ListLicensePolicies(writer, whereFilters)
	}

	return
}

// Assure all errors are logged
func processLicensePolicyListResults(err error) {
	if err != nil {
		getLogger().Error(err)
	}
}

func ListLicensePolicies(writer io.Writer, whereFilters []WhereFilter) (err error) {
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
	filteredMap, err = licensePolicyConfig.GetFilteredFamilyNameMap(whereFilters)

	if err != nil {
		return
	}

	// default output (writer) to standard out
	switch utils.GlobalFlags.OutputFormat {
	case FORMAT_DEFAULT:
		// defaults to text if no explicit `--format` parameter
		err = DisplayLicensePoliciesTabbedText(writer, filteredMap)
	case FORMAT_TEXT:
		err = DisplayLicensePoliciesTabbedText(writer, filteredMap)
	case FORMAT_CSV:
		err = DisplayLicensePoliciesCSV(writer, filteredMap)
	case FORMAT_MARKDOWN:
		err = DisplayLicensePoliciesMarkdown(writer, filteredMap)
	default:
		// default to text format for anything else
		getLogger().Warningf("Unsupported format: `%s`; using default format.",
			utils.GlobalFlags.OutputFormat)
		err = DisplayLicensePoliciesTabbedText(writer, filteredMap)
	}
	return
}

func FindPolicyBySpdxId(id string) (policyValue string, matchedPolicy LicensePolicy) {
	getLogger().Enter("id:", id)
	defer getLogger().Exit()

	var matched bool
	var arrPolicies []interface{}

	// Note: this will cause all policy hashmaps to be initialized (created), if it has not bee
	licensePolicyIdMap, err := licensePolicyConfig.GetLicenseIdMap()

	if err != nil {
		getLogger().Errorf("license policy map error: `%w`", err)
		os.Exit(ERROR_APPLICATION)
	}

	arrPolicies, matched = licensePolicyIdMap.Get(id)
	getLogger().Tracef("licensePolicyMapById.Get(%s): (%v) matches", id, len(arrPolicies))

	// There MUST be ONLY one policy per (discrete) license ID
	if len(arrPolicies) > 1 {
		getLogger().Errorf("Multiple (possibly conflicting) policies declared for SPDX ID=`%s`", id)
		os.Exit(ERROR_APPLICATION)
	}

	if matched {
		// retrieve the usage policy from the single (first) entry
		matchedPolicy = arrPolicies[0].(LicensePolicy)
		policyValue = matchedPolicy.UsagePolicy
	} else {
		getLogger().Tracef("No policy match found for SPDX ID=`%s` ", id)
		policyValue = POLICY_UNDEFINED
	}

	return policyValue, matchedPolicy
}

// NOTE: for now, we will look for the "family" name encoded in the License.Name field
// (until) we can get additional fields/properties added to the CDX LicenseChoice schema
func FindPolicyByFamilyName(name string) (policyValue string, matchedPolicy LicensePolicy) {
	getLogger().Enter("name:", name)
	defer getLogger().Exit()

	var matched bool
	var key string
	var arrPolicies []interface{}

	// NOTE: we have found some SBOM authors have placed license expressions
	// within the "name" field.  This prevents us from assigning policy
	// return
	if HasLogicalConjunctionOrPreposition(name) {
		getLogger().Warningf("policy name contains logical conjunctions or preposition: `%s`", name)
		policyValue = POLICY_UNDEFINED
		return
	}

	// Note: this will cause all policy hashmaps to be initialized (created), if it has not been
	familyNameMap, _ := licensePolicyConfig.GetFamilyNameMap()

	// See if any of the policy family keys contain the family name
	matched, key = searchForLicenseFamilyName(name)

	if matched {
		arrPolicies, _ = familyNameMap.Get(key)

		if len(arrPolicies) == 0 {
			getLogger().Errorf("No policy match found in hashmap for family name key: `%s`", key)
			os.Exit(ERROR_APPLICATION)
		}

		// NOTE: We can use the first policy (of a family) as they are
		// verified to be consistent when loaded from the policy config. file
		matchedPolicy = arrPolicies[0].(LicensePolicy)
		policyValue = matchedPolicy.UsagePolicy

		// If we have more than one license in the same family (name), then
		// check if there are any "usage policy" conflicts to display in report
		if len(arrPolicies) > 1 {
			conflict := policyConflictExists(arrPolicies)
			if conflict {
				getLogger().Tracef("Usage policy conflict for license family name=`%s` ", name)
				policyValue = POLICY_CONFLICT
			}
		}
	} else {
		getLogger().Tracef("No policy match found for license family name=`%s` ", name)
		policyValue = POLICY_UNDEFINED
	}

	return policyValue, matchedPolicy
}

// NOTE: caller assumes resp. for checking for empty input array
func policyConflictExists(arrPolicies []interface{}) bool {
	var currentUsagePolicy string
	var policy LicensePolicy

	// Init. usage policy to first entry in array
	policy = arrPolicies[0].(LicensePolicy)
	currentUsagePolicy = policy.UsagePolicy

	// Check every subsequent usage policy in array to identify mismatch (i.e., a conflict)
	for i := 1; i < len(arrPolicies); i++ {
		policy = arrPolicies[i].(LicensePolicy)
		if policy.UsagePolicy != currentUsagePolicy {
			return true
		}
	}
	return false
}

func FindPolicy(licenseInfo LicenseInfo) (matchedPolicy LicensePolicy, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Initialize to empty
	matchedPolicy = LicensePolicy{}

	switch licenseInfo.LicenseChoiceTypeValue {
	case LC_TYPE_ID:
		matchedPolicy.UsagePolicy, matchedPolicy = FindPolicyBySpdxId(licenseInfo.LicenseChoice.License.Id)
	case LC_TYPE_NAME:
		matchedPolicy.UsagePolicy, matchedPolicy = FindPolicyByFamilyName(licenseInfo.LicenseChoice.License.Name)
	case LC_TYPE_EXPRESSION:
		// Parse expression according to SPDX spec.
		var expressionTree *CompoundExpression
		expressionTree, err = parseExpression(licenseInfo.LicenseChoice.Expression)
		getLogger().Debugf("Parsed expression:\n%v", expressionTree)
		matchedPolicy.UsagePolicy = expressionTree.CompoundUsagePolicy
	}

	if matchedPolicy.UsagePolicy == "" {
		matchedPolicy.UsagePolicy = POLICY_UNDEFINED
	}
	return matchedPolicy, err
}

// Looks for an SPDX family (name) somewhere in the CDX License object "Name" field
func containsFamilyName(name string, familyName string) bool {
	// NOTE: we do not currently normalize as we assume family names
	// are proper substring of SPDX IDs which are mixed case and
	// should match exactly as encoded.
	return strings.Contains(name, familyName)
}

// Loop through all known license family names (in hashMap) to see if any
// appear in the CDX License "Name" field
func searchForLicenseFamilyName(licenseName string) (found bool, familyName string) {
	getLogger().Enter()
	defer getLogger().Exit()

	familyNameMap, err := licensePolicyConfig.GetFamilyNameMap()
	if err != nil {
		getLogger().Error(err)
		os.Exit(ERROR_APPLICATION)
	}

	keys := familyNameMap.Keys()

	for _, key := range keys {
		familyName = key.(string)
		getLogger().Debugf("Searching for familyName: '%s' in License Name: %s", familyName, licenseName)
		found = containsFamilyName(licenseName, familyName)

		if found {
			getLogger().Debugf("Match found: familyName: '%s' in License Name: %s", familyName, licenseName)
			return
		}
	}

	return
}

// Display all license policies including those with SPDX IDs and those
// only with "family" names which is reflected in the contents of the
// hashmap keyed on family names.
// NOTE: assumes all entries in the policy config file MUST have family names
// TODO: Allow caller to pass flag to truncate or not (perhaps with value)
// TODO: Add a --no-title flag to skip title output
func DisplayLicensePoliciesTabbedText(output io.Writer, filteredPolicyMap *slicemultimap.MultiMap) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// initialize tabwriter
	w := new(tabwriter.Writer)
	defer w.Flush()

	// min-width, tab-width, padding, pad-char, flags
	w.Init(output, 8, 2, 2, ' ', 0)

	// create underline row from slices of optional and compulsory titles
	underlines := createTitleTextSeparators(POLICY_LIST_TITLES)

	// Add tabs between column titles for the tabWRiter
	fmt.Fprintf(w, "%s\n", strings.Join(POLICY_LIST_TITLES, "\t"))
	fmt.Fprintf(w, "%s\n", strings.Join(underlines, "\t"))

	// Sort entries for listing by family name keys
	keyNames := filteredPolicyMap.KeySet()
	sort.Slice(keyNames, func(i, j int) bool {
		return keyNames[i].(string) < keyNames[j].(string)
	})

	// output each license policy entry as a line (by sorted key)
	var lines [][]string

	for _, key := range keyNames {
		values, match := filteredPolicyMap.Get(key)
		getLogger().Tracef("%v (%t)", values, match)

		for _, value := range values {
			policy := value.(LicensePolicy)

			// Wrap all column text (i.e. flag `--wrap=true`)
			if utils.GlobalFlags.LicenseFlags.ListLineWrap {
				lines, err = wrapTableRowText(24, ",",
					policy.UsagePolicy,
					policy.Family,
					policy.Id,
					policy.Name,
					policy.AnnotationRefs,
					policy.Aliases,
					policy.Notes,
				)

				// TODO: make truncate length configurable
				for _, line := range lines {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
						truncateString(line[0], 16, true), // usage-policy
						truncateString(line[1], 20, true), // family
						truncateString(line[2], 20, true), // id
						truncateString(line[3], 20, true), // name
						truncateString(line[4], 24, true), // annotation
						truncateString(line[5], 24, true), // alias
						truncateString(line[6], 24, true), // note
					)
				}

			} else {
				// No wrapping needed
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					truncateString(policy.UsagePolicy, 16, true),                       // usage-policy
					truncateString(policy.Family, 20, true),                            // family
					truncateString(policy.Id, 20, true),                                // id
					truncateString(policy.Name, 20, true),                              // name
					truncateString(strings.Join(policy.AnnotationRefs, ","), 24, true), // annotation
					truncateString(strings.Join(policy.Aliases, ","), 24, true),        // alias
					truncateString(strings.Join(policy.Notes, ","), 24, true),          // note
				)
			}
		}
	}
	return
}

// TODO: Add a --no-title flag to skip title output
func DisplayLicensePoliciesCSV(output io.Writer, filteredPolicyMap *slicemultimap.MultiMap) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// initialize writer and prepare the list of entries (i.e., the "rows")
	w := csv.NewWriter(output)
	defer w.Flush()

	if err = w.Write(POLICY_LIST_TITLES); err != nil {
		return getLogger().Errorf("error writing to output (%v): %s", POLICY_LIST_TITLES, err)
	}

	// Retrieve keys for policies to list
	keyNames := filteredPolicyMap.KeySet()

	// Emit no schemas found warning into output
	// TODO Use only for Warning messages, do not emit in output table
	if len(keyNames) == 0 {
		fmt.Fprintf(output, "%s\n", MSG_OUTPUT_NO_POLICIES_FOUND)
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
			policy := value.(LicensePolicy)
			line = nil
			line = append(line,
				policy.UsagePolicy,
				policy.Family,
				policy.Id,
				policy.Name,
				strings.Join(policy.AnnotationRefs, ", "),
				strings.Join(policy.Aliases, ", "),
				strings.Join(policy.Notes, ", "),
			)

			if err = w.Write(line); err != nil {
				getLogger().Errorf("csv.Write: %w", err)
			}
		}
	}
	return
}

// TODO: Add a --no-title flag to skip title output
func DisplayLicensePoliciesMarkdown(output io.Writer, filteredPolicyMap *slicemultimap.MultiMap) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// create title row
	titleRow := createMarkdownRow(POLICY_LIST_TITLES)
	fmt.Fprintf(output, "%s\n", titleRow)

	alignments := createMarkdownColumnAlignment(POLICY_LIST_TITLES)
	alignmentRow := createMarkdownRow(alignments)
	fmt.Fprintf(output, "%s\n", alignmentRow)

	// Retrieve keys for policies to list
	keyNames := filteredPolicyMap.KeySet()

	// Display a warning messing in the actual output and return (short-circuit)
	// Emit no schemas found warning into output
	// TODO Use only for Warning messages, do not emit in output table
	if len(keyNames) == 0 {
		fmt.Fprintf(output, "%s\n", MSG_OUTPUT_NO_POLICIES_FOUND)
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
			policy, ok := value.(LicensePolicy)

			if !ok {
				getLogger().Errorf("%s", MSG_LICENSE_INVALID_POLICY)
				os.Exit(ERROR_APPLICATION)
			}

			// reset loop variables for new assignments
			line = nil
			line = append(line, policy.UsagePolicy,
				policy.Family,
				policy.Id,
				policy.Name,
				strings.Join(policy.AnnotationRefs, ", "),
				strings.Join(policy.Aliases, ", "),
				strings.Join(policy.Notes, ", "),
			)

			lineRow = createMarkdownRow(line)
			fmt.Fprintf(output, "%s\n", lineRow)
		}
	}
	return
}
