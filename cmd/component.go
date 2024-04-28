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
	"github.com/jwangsadinata/go-multimap"
	"github.com/spf13/cobra"
)

const (
	SUBCOMMAND_COMPONENT_LIST = "list"
)

var VALID_SUBCOMMANDS_COMPONENT = []string{SUBCOMMAND_COMPONENT_LIST}

//	type CDXComponent struct {
//		Primary            bool                        `json:"-"`              // Proprietary: do NOT marshal/unmarshal
//		Type               string                      `json:"type,omitempty"` // Constraint: enum [see schema]
//		Name               string                      `json:"name,omitempty"`
//		Version            string                      `json:"version,omitempty"`
//		Description        string                      `json:"description,omitempty"`
//		Group              string                      `json:"group,omitempty"`
//		BOMRef             *CDXRefType                 `json:"bom-ref,omitempty"`
//		MimeType           string                      `json:"mime-type,omitempty"`
//		Supplier           *CDXOrganizationalEntity    `json:"supplier,omitempty"`
//		Author             string                      `json:"author,omitempty"`
//		Publisher          string                      `json:"publisher,omitempty"`
//		Scope              string                      `json:"scope,omitempty"` // Constraint: "enum": ["required","optional","excluded"]
//		Hashes             *[]CDXHash                  `json:"hashes,omitempty"`
//		Licenses           *[]CDXLicenseChoice         `json:"licenses,omitempty"`
//		Copyright          string                      `json:"copyright,omitempty"`
//		Cpe                string                      `json:"cpe,omitempty"`                                       // See: https://nvd.nist.gov/products/cpe
//		Purl               string                      `json:"purl,omitempty" scvs:"bom:resource:identifiers:purl"` // See: https://github.com/package-url/purl-spec
//		Swid               *CDXSwid                    `json:"swid,omitempty"`                                      // See: https://www.iso.org/standard/65666.html
//		Pedigree           *CDXPedigree                `json:"pedigree,omitempty"`                                  // anon. type
//		ExternalReferences *[]CDXExternalReference     `json:"externalReferences,omitempty"`
//		Components         *[]CDXComponent             `json:"components,omitempty"`
//		Evidence           *CDXComponentEvidence       `json:"evidence,omitempty"`                  // v1.3: added
//		Properties         *[]CDXProperty              `json:"properties,omitempty"`                // v1.3: added
//		Modified           bool                        `json:"modified,omitempty" cdx:"deprecated"` // v1.4: deprecated
//		ReleaseNotes       *[]CDXReleaseNotes          `json:"releaseNotes,omitempty"`              // v1.4: added
//		Signature          *JSFSignature               `json:"signature,omitempty"`                 // v1.4: added
//		ModelCard          *CDXModelCard               `json:"modelCard,omitempty"`                 // v1.5: added
//		Data               *[]CDXComponentData         `json:"data,omitempty"`                      // v1.5: added
//		Authors            *[]CDXOrganizationalContact `json:"authors,omitempty"`                   // v1.6: added
//		Tags               *[]string                   `json:"tags,omitempty" cdx:"+1.6"`           // v1.6: added
//	}
var COMPONENT_LIST_ROW_DATA = []ColumnFormatData{
	{COMPONENT_FILTER_KEY_TYPE, DEFAULT_COLUMN_TRUNCATE_LENGTH, REPORT_SUMMARY_DATA_TRUE, false},
	{COMPONENT_FILTER_KEY_NAME, DEFAULT_COLUMN_TRUNCATE_LENGTH, REPORT_SUMMARY_DATA_TRUE, false},
	{COMPONENT_FILTER_KEY_VERSION, DEFAULT_COLUMN_TRUNCATE_LENGTH, REPORT_SUMMARY_DATA_TRUE, false},
	{COMPONENT_FILTER_KEY_BOMREF, DEFAULT_COLUMN_TRUNCATE_LENGTH, REPORT_SUMMARY_DATA_TRUE, REPORT_REPLACE_LINE_FEEDS_TRUE},
}

// filter keys
// Note: these string values MUST match annotations for the ComponentInfo struct fields
const (
	COMPONENT_FILTER_KEY_TYPE    = "type"
	COMPONENT_FILTER_KEY_NAME    = "name"
	COMPONENT_FILTER_KEY_VERSION = "version"
	COMPONENT_FILTER_KEY_BOMREF  = "bom-ref"
)

var VALID_COMPONENT_FILTER_KEYS = []string{
	COMPONENT_FILTER_KEY_TYPE,
	COMPONENT_FILTER_KEY_NAME,
	COMPONENT_FILTER_KEY_VERSION,
	COMPONENT_FILTER_KEY_BOMREF,
}

var COMPONENT_LIST_TITLES = []string{
	COMPONENT_FILTER_KEY_TYPE,
	COMPONENT_FILTER_KEY_NAME,
	COMPONENT_FILTER_KEY_VERSION,
	COMPONENT_FILTER_KEY_BOMREF,
}

// Flags. Reuse query flag values where possible
const (
	FLAG_COMPONENT_TYPE      = "type"
	FLAG_COMPONENT_TYPE_HELP = "filter output by component type(s)"
)

const (
	MSG_OUTPUT_NO_COMPONENTS_FOUND = "[WARN] no matching components found for query"
)

// Command help formatting
const (
	FLAG_COMPONENT_OUTPUT_FORMAT_HELP = "format output using the specified type"
)

var COMPONENT_LIST_OUTPUT_SUPPORTED_FORMATS = MSG_SUPPORTED_OUTPUT_FORMATS_HELP +
	strings.Join([]string{FORMAT_TEXT, FORMAT_CSV, FORMAT_MARKDOWN}, ", ")

func NewCommandComponent() *cobra.Command {
	var command = new(cobra.Command)
	command.Use = CMD_USAGE_COMPONENT_LIST
	command.Short = "Report on components found in the BOM input file"
	command.Long = "Report on components found in the BOM input file"
	command.Flags().StringVarP(&utils.GlobalFlags.PersistentFlags.OutputFormat, FLAG_FILE_OUTPUT_FORMAT, "", FORMAT_TEXT,
		FLAG_COMPONENT_OUTPUT_FORMAT_HELP+COMPONENT_LIST_OUTPUT_SUPPORTED_FORMATS)
	command.Flags().StringP(FLAG_COMPONENT_TYPE, "", "", FLAG_COMPONENT_TYPE_HELP)
	command.Flags().StringP(FLAG_REPORT_WHERE, "", "", FLAG_REPORT_WHERE_HELP)
	command.RunE = componentCmdImpl
	command.ValidArgs = VALID_SUBCOMMANDS_COMPONENT
	command.PreRunE = func(cmd *cobra.Command, args []string) (err error) {
		// the command requires at least 1 valid subcommand (argument)
		if len(args) > 1 {
			return getLogger().Errorf("Too many arguments provided: %v", args)
		}

		// Make sure (optional) subcommand is known/valid
		if len(args) == 1 {
			if !preRunTestForSubcommand(VALID_SUBCOMMANDS_COMPONENT, args[0]) {
				return getLogger().Errorf("Subcommand provided is not valid: `%v`", args[0])
			}
		}

		if len(args) == 0 {
			getLogger().Tracef("No subcommands provided; defaulting to: `%s` subcommand", SUBCOMMAND_SCHEMA_LIST)
		}

		// Test for required flags (parameters)
		err = preRunTestForInputFile(args)

		return
	}
	return command
}

func retrieveComponentType(cmd *cobra.Command) (componentTypes string, err error) {

	componentTypes, err = cmd.Flags().GetString(FLAG_COMPONENT_TYPE)
	if err != nil {
		return
	}

	// TODO: parse "type" flag (comma-separated list of type names)
	// TODO: validate each one is supported in the CDX Component Type enum.
	// // validate component type(s) is a known keyword
	// TODO: support multiple types (slice) and return "invalid" as an error
	// if !schema.IsValidComponentType(componentTypes) {
	// 	// invalid
	// 	err = getLogger().Errorf("invalid type `%s`: `%s`", FLAG_COMPONENT_TYPE, componentType)
	// }

	return
}

func componentCmdImpl(cmd *cobra.Command, args []string) (err error) {
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

	// process filters supplied on the --where command flag
	whereFilters, err := processWhereFlag(cmd)

	// Process flag: --type
	var types string
	var commandFlags utils.ComponentCommandFlags
	types, err = retrieveComponentType(cmd)

	if err == nil {
		commandFlags.Types = types
		err = ListComponents(writer, utils.GlobalFlags.PersistentFlags, commandFlags, whereFilters)
	}

	return
}

// Assure all errors are logged
func processComponentListResults(err error) {
	if err != nil {
		// No special processing at this time
		getLogger().Error(err)
	}
}

// NOTE: resourceType has already been validated
func ListComponents(writer io.Writer, persistentFlags utils.PersistentCommandFlags, componentFlags utils.ComponentCommandFlags, whereFilters []common.WhereFilter) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// use function closure to assure consistent error output based upon error type
	defer func() {
		if err != nil {
			processComponentListResults(err)
		}
	}()

	// Note: returns error if either file load or unmarshal to JSON map fails
	var document *schema.BOM
	document, err = LoadInputBOMFileAndDetectSchema()

	if err != nil {
		return
	}

	// Hash all licenses within input file
	getLogger().Infof("Scanning document for licenses...")
	err = loadDocumentComponents(document, componentFlags.Types, whereFilters)

	if err != nil {
		return
	}

	format := persistentFlags.OutputFormat
	getLogger().Infof("Outputting listing (`%s` format)...", format)
	switch format {
	case FORMAT_TEXT:
		DisplayComponentListText(document, writer)
	case FORMAT_CSV:
		DisplayComponentListCSV(document, writer)
	case FORMAT_MARKDOWN:
		DisplayComponentListMarkdown(document, writer)
	default:
		// Default to Text output for anything else (set as flag default)
		getLogger().Warningf("Listing not supported for `%s` format; defaulting to `%s` format...",
			format, FORMAT_TEXT)
		DisplayComponentListText(document, writer)
	}

	return
}

func loadDocumentComponents(document *schema.BOM, componentTypes string, whereFilters []common.WhereFilter) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	// At this time, fail SPDX format SBOMs as "unsupported" (for "any" format)
	if !document.FormatInfo.IsCycloneDx() {
		err = schema.NewUnsupportedFormatForCommandError(
			document.FormatInfo.CanonicalName,
			document.GetFilename(),
			CMD_LICENSE, FORMAT_ANY)
		return
	}

	// Before looking for license data, fully unmarshal the SBOM into named structures
	if err = document.UnmarshalCycloneDXBOM(); err != nil {
		return
	}

	// Add top-level SBOM component
	err = document.HashmapComponentResources(whereFilters)
	if err != nil {
		return
	}

	return
}

func sortComponents(entries []multimap.Entry) {
	// Sort by Type then Name
	sort.Slice(entries, func(i, j int) bool {
		resource1 := (entries[i].Value).(schema.CDXResourceInfo)
		resource2 := (entries[j].Value).(schema.CDXResourceInfo)
		if resource1.Type != resource2.Type {
			return resource1.Type < resource2.Type
		}
		return resource1.Name < resource2.Name
	})
}

// NOTE: This list is NOT de-duplicated
// TODO: Add a --no-title flag to skip title output
func DisplayComponentListText(bom *schema.BOM, writer io.Writer) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// initialize tabwriter
	w := new(tabwriter.Writer)
	defer w.Flush()

	// min-width, tab-width, padding, pad-char, flags
	w.Init(writer, 8, 2, 2, ' ', 0)

	// create title row and underline row from slices of optional and compulsory titles
	titles, underlines := prepareReportTitleData(COMPONENT_LIST_ROW_DATA, true)

	// Add tabs between column titles for the tabWRiter
	fmt.Fprintf(w, "%s\n", strings.Join(titles, "\t"))
	fmt.Fprintf(w, "%s\n", strings.Join(underlines, "\t"))

	// Display a warning "missing" in the actual output and return (short-circuit)
	entries := bom.ResourceMap.Entries()

	// Emit no license warning into output
	if len(entries) == 0 {
		fmt.Fprintf(w, "%s\n", MSG_OUTPUT_NO_RESOURCES_FOUND)
		return
	}

	// Sort Components prior to outputting
	sortComponents(entries)

	// Emit row data
	var line []string
	for _, entry := range entries {
		line, err = prepareReportLineData(
			entry.Value.(schema.CDXResourceInfo),
			COMPONENT_LIST_ROW_DATA,
			true,
		)
		// Only emit line if no error
		if err != nil {
			return
		}
		fmt.Fprintf(w, "%s\n", strings.Join(line, "\t"))
	}
	return
}

// TODO: Add a --no-title flag to skip title output
func DisplayComponentListCSV(bom *schema.BOM, writer io.Writer) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// initialize writer and prepare the list of entries (i.e., the "rows")
	w := csv.NewWriter(writer)
	defer w.Flush()

	// Create title row data as []string
	titles, _ := prepareReportTitleData(COMPONENT_LIST_ROW_DATA, true)

	if err = w.Write(titles); err != nil {
		return getLogger().Errorf("error writing to output (%v): %s", titles, err)
	}

	// Display a warning "missing" in the actual output and return (short-circuit)
	entries := bom.ResourceMap.Entries()

	// Emit no resource found warning into output
	if len(entries) == 0 {
		currentRow := []string{MSG_OUTPUT_NO_RESOURCES_FOUND}
		if err = w.Write(currentRow); err != nil {
			// unable to emit an error message into output stream
			return getLogger().Errorf("error writing to output (%v): %s", currentRow, err)
		}
		return fmt.Errorf(currentRow[0])
	}

	// Sort Components prior to outputting
	sortComponents(entries)

	var line []string
	for _, entry := range entries {
		line, err = prepareReportLineData(
			entry.Value.(schema.CDXResourceInfo),
			COMPONENT_LIST_ROW_DATA,
			true,
		)
		// Only emit line if no error
		if err != nil {
			return
		}
		if err = w.Write(line); err != nil {
			err = getLogger().Errorf("csv.Write: %w", err)
		}
	}
	return
}

// TODO: Add a --no-title flag to skip title output
func DisplayComponentListMarkdown(bom *schema.BOM, writer io.Writer) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Create title row data as []string
	titles, _ := prepareReportTitleData(COMPONENT_LIST_ROW_DATA, true)

	// create title row
	titleRow := createMarkdownRow(titles)
	fmt.Fprintf(writer, "%s\n", titleRow)

	// create alignment row
	alignments := createMarkdownColumnAlignment(COMPONENT_LIST_TITLES)
	alignmentRow := createMarkdownRow(alignments)
	fmt.Fprintf(writer, "%s\n", alignmentRow)

	// Display a warning "missing" in the actual output and return (short-circuit)
	entries := bom.ResourceMap.Entries()

	// Emit no components found warning into output
	if len(entries) == 0 {
		fmt.Fprintf(writer, "%s\n", MSG_OUTPUT_NO_COMPONENTS_FOUND)
		return fmt.Errorf(MSG_OUTPUT_NO_COMPONENTS_FOUND)
	}

	// Sort Components prior to outputting
	sortComponents(entries)

	var line []string
	var lineRow string
	for _, entry := range entries {
		line, err = prepareReportLineData(
			entry.Value.(schema.CDXResourceInfo),
			COMPONENT_LIST_ROW_DATA,
			true,
		)
		// Only emit line if no error
		if err != nil {
			return
		}
		lineRow = createMarkdownRow(line)
		fmt.Fprintf(writer, "%s\n", lineRow)
	}
	return
}
