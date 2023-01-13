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

	"github.com/jwangsadinata/go-multimap/slicemultimap"
	"github.com/scs/sbom-utility/schema"
	"github.com/scs/sbom-utility/utils"
	"github.com/spf13/cobra"
)

const (
	SUBCOMMAND_RESOURCE_LIST = "list"
)

var VALID_SUBCOMMANDS_RESOURCE = []string{SUBCOMMAND_RESOURCE_LIST}

var RESOURCE_LIST_TITLES = []string{"type", "name", "version", "bom-ref"}
var VALID_RESOURCE_WHERE_FILTER_KEYS = []string{}

// Flags. Reuse query flag values where possible
const (
	FLAG_RESOURCE_TYPE       = "type"
	FLAG_RESOURCE_TYPE_HELP  = "filter output by resource type (i.e., component | service"
	FLAG_RESOURCE_WHERE      = FLAG_QUERY_WHERE
	FLAG_RESOURCE_WHERE_HELP = "comma-separated list of key=<regex> used to filter result set"
)

// Command help formatting
const (
	FLAG_RESOURCE_OUTPUT_FORMAT_HELP = "format output using the specified type"
)

var RESOURCE_LIST_SUPPORTED_FORMATS = MSG_SUPPORTED_OUTPUT_FORMATS_HELP +
	strings.Join([]string{OUTPUT_TEXT, OUTPUT_CSV, OUTPUT_MARKDOWN}, ", ")

// resource types
const (
	RESOURCE_TYPE_DEFAULT   = "" // i.e., all resource types
	RESOURCE_TYPE_COMPONENT = "component"
	RESOURCE_TYPE_SERVICE   = "service"
)

var VALID_RESOURCE_TYPES = []string{RESOURCE_TYPE_DEFAULT, RESOURCE_TYPE_COMPONENT, RESOURCE_TYPE_SERVICE}

// filter keys
const (
	RESOURCE_FILTER_KEY_TYPE   = "type"
	RESOURCE_FILTER_KEY_NAME   = "name"
	RESOURCE_FILTER_KEY_VALUE  = "value"
	RESOURCE_FILTER_KEY_BOMREF = "bom-ref"
)

var VALID_FILTER_KEYS = []string{RESOURCE_FILTER_KEY_TYPE, RESOURCE_FILTER_KEY_NAME, RESOURCE_FILTER_KEY_VALUE, RESOURCE_FILTER_KEY_BOMREF}

type ResourceInfo struct {
	isRoot           bool
	Type             string
	BomRef           string // TODO: need to strip `-` from `bom-ref` for where filter
	Name             string
	Version          string
	SupplierProvider schema.CDXOrganizationalEntity
	Properties       []schema.CDXProperty
	Component        schema.CDXComponent
	Service          schema.CDXService
}

// Holds resources (e.g., components, services) declared license(s)
var resourceMap = slicemultimap.New()

func ClearGlobalResourceData() {
	resourceMap.Clear()
}

func NewCommandResource() *cobra.Command {
	var command = new(cobra.Command)
	command.Use = CMD_USAGE_RESOURCE_LIST
	command.Short = "Report on resources found in SBOM input file"
	command.Long = "Report on resources found in SBOM input file"
	command.Flags().StringVarP(&utils.GlobalFlags.OutputFormat, FLAG_FILE_OUTPUT_FORMAT, "", OUTPUT_TEXT,
		FLAG_RESOURCE_OUTPUT_FORMAT_HELP+RESOURCE_LIST_SUPPORTED_FORMATS)
	command.Flags().StringP(FLAG_RESOURCE_TYPE, "", RESOURCE_TYPE_DEFAULT, FLAG_RESOURCE_TYPE_HELP)
	command.Flags().StringP(FLAG_RESOURCE_WHERE, "", "", FLAG_RESOURCE_WHERE_HELP)
	command.RunE = resourceCmdImpl
	command.ValidArgs = VALID_SUBCOMMANDS_RESOURCE
	command.PreRunE = func(cmd *cobra.Command, args []string) (err error) {
		// the resource command requires at least 1 valid subcommand (argument)
		getLogger().Tracef("args: %v\n", args)
		if len(args) == 0 {
			return getLogger().Errorf("Missing required argument(s).")
		} else if len(args) > 1 {
			return getLogger().Errorf("Too many arguments provided: %v", args)
		}

		// Make sure subcommand is known
		if !preRunTestForSubcommand(command, VALID_SUBCOMMANDS_RESOURCE, args[0]) {
			return getLogger().Errorf("Subcommand provided is not valid: `%v`", args[0])
		}

		// Test for required flags (parameters)
		err = preRunTestForInputFile(cmd, args)

		return
	}
	return command
}

func retrieveWhereFilters(cmd *cobra.Command) (whereFilters []WhereFilter, err error) {
	var whereExpressions []string
	whereValues, errGet := cmd.Flags().GetString(FLAG_RESOURCE_WHERE)

	if errGet != nil {
		err = getLogger().Errorf("failed to read flag `%s` value", FLAG_RESOURCE_WHERE)
		return
	}

	if whereValues != "" {
		whereExpressions = strings.Split(whereValues, QUERY_WHERE_EXPRESSION_SEP)

		var filter *WhereFilter
		for _, clause := range whereExpressions {

			filter = parseWhereFilter(clause)

			if filter == nil {
				err = NewQueryWhereClauseError(nil, clause)
				return
			}

			whereFilters = append(whereFilters, *filter)
		}
	}
	return
}

func retrieveResourceType(cmd *cobra.Command) (resourceType string, err error) {

	resourceType, err = cmd.Flags().GetString(FLAG_RESOURCE_TYPE)

	if err != nil {
		return
	}

	// validate value
	for _, validType := range VALID_RESOURCE_TYPES {
		if resourceType == validType {
			// valid
			return
		}
	}

	// invalid
	err = getLogger().Errorf("invalid resource `type`: `%s`", resourceType)
	return
}

func resourceCmdImpl(cmd *cobra.Command, args []string) (err error) {
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

	// Process flag: --where
	var whereFilters []WhereFilter
	whereFilters, err = retrieveWhereFilters(cmd)

	if err != nil {
		return
	}

	// Process flag: --type
	var resourceType string
	resourceType, err = retrieveResourceType(cmd)

	ListResources(writer, utils.GlobalFlags.OutputFormat, resourceType, whereFilters)

	return
}

func processResourceListResults(err error) {
	if err != nil {
		// No special processing at this time
		getLogger().Error(err)
	}
}

// NOTE: resourceType has already been validated
func ListResources(output io.Writer, format string, resourceType string, whereFilters []WhereFilter) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// use function closure to assure consistent error output based upon error type
	defer func() {
		if err != nil {
			processResourceListResults(err)
		}
	}()

	// Note: returns error if either file load or unmarshal to JSON map fails
	var document *schema.Sbom
	document, err = LoadInputSbomFileAndDetectSchema()

	if err != nil {
		return
	}

	// Hash all licenses within input file
	getLogger().Infof("Scanning document for licenses...")
	err = loadDocumentResources(document, resourceType)

	if err != nil {
		return
	}

	getLogger().Infof("Outputting listing (`%s` format)...", format)
	switch format {
	case OUTPUT_TEXT:
		DisplayResourceListText(output)
	case OUTPUT_CSV:
		DisplayResourceListCSV(output)
	case OUTPUT_MARKDOWN:
		//DisplayResourceListMarkdown(output)
	default:
		// Default to Text output for anything else (set as flag default)
		getLogger().Warningf("Listing not supported for `%s` format; defaulting to `%s` format...",
			format, OUTPUT_JSON)
		DisplayResourceListText(output)
	}

	return
}

func loadDocumentResources(document *schema.Sbom, resourceType string) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	// At this time, fail SPDX format SBOMs as "unsupported" (for "any" format)
	if !document.FormatInfo.IsCycloneDx() {
		err = schema.NewUnsupportedFormatForCommandError(
			document.FormatInfo.CanonicalName,
			document.GetFilename(),
			CMD_LICENSE, "<any>")
		return
	}

	// Clear out any old (global)hashmap data (NOTE: 'go test' needs this)
	ClearGlobalResourceData()

	// Before looking for license data, fully unmarshal the SBOM
	// into named structures
	if err = document.UnmarshalCDXSbom(); err != nil {
		return
	}

	// Add top-level SBOM component
	if resourceType == RESOURCE_TYPE_DEFAULT || resourceType == RESOURCE_TYPE_COMPONENT {
		var resourceInfo *ResourceInfo
		resourceInfo, err = hashComponentAsResource(*document.GetCdxMetadataComponent(), LC_LOC_METADATA_COMPONENT)
		if err != nil {
			return
		}
		resourceInfo.isRoot = true

		// Hash all components found in the (root).components[] (+ "nested" components)
		if components := document.GetCdxComponents(); len(components) > 0 {
			if err = hashComponents(components, LC_LOC_COMPONENTS); err != nil {
				return
			}
		}
	}

	if resourceType == RESOURCE_TYPE_DEFAULT || resourceType == RESOURCE_TYPE_SERVICE {
		// Hash services found in the (root).services[] (array) (+ "nested" services)
		if services := document.GetCdxServices(); len(services) > 0 {
			if err = hashServices(services, LC_LOC_SERVICES); err != nil {
				return
			}
		}
	}

	return
}

func hashComponents(components []schema.CDXComponent, location int) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	for _, cdxComponent := range components {
		_, err = hashComponentAsResource(cdxComponent, location)
		if err != nil {
			return
		}
	}
	return
}

// Hash a CDX Component and recursively those of any "nested" components
// TODO we should WARN if version is not a valid semver (e.g., examples/cyclonedx/BOM/laravel-7.12.0/bom.1.3.json)
func hashComponentAsResource(cdxComponent schema.CDXComponent, location int) (ri *ResourceInfo, err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)
	var resourceInfo ResourceInfo
	ri = &resourceInfo

	if cdxComponent.Name == "" {
		getLogger().Errorf("component missing required value `name` : %v ", cdxComponent)
	}

	if cdxComponent.Version == "" {
		getLogger().Warningf("component named `%s` missing `version`", cdxComponent.Name)
	}

	if cdxComponent.BomRef == "" {
		getLogger().Warningf("component named `%s` missing `bom-ref`", cdxComponent.Name)
	}

	// hash any component w/o a license using special key name
	resourceInfo.Type = RESOURCE_TYPE_COMPONENT
	resourceInfo.Component = cdxComponent
	resourceInfo.Name = cdxComponent.Name
	resourceInfo.BomRef = cdxComponent.BomRef
	resourceInfo.Version = cdxComponent.Version
	resourceInfo.SupplierProvider = cdxComponent.Supplier
	resourceInfo.Properties = cdxComponent.Properties

	// TODO: AppendLicenseInfo(LICENSE_NONE, resourceInfo)
	resourceMap.Put(resourceInfo.BomRef, resourceInfo)

	getLogger().Tracef("Put: %s (`%s`), `%s`)",
		resourceInfo.Name,
		resourceInfo.Version,
		resourceInfo.BomRef)

	// Recursively hash licenses for all child components (i.e., hierarchical composition)
	if len(cdxComponent.Components) > 0 {
		err = hashComponents(cdxComponent.Components, location)
		if err != nil {
			return
		}
	}
	return
}

func hashServices(services []schema.CDXService, location int) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	for _, cdxService := range services {
		_, err = hashServiceAsResource(cdxService, location)
		if err != nil {
			return
		}
	}
	return
}

// Hash a CDX Component and recursively those of any "nested" components
func hashServiceAsResource(cdxService schema.CDXService, location int) (ri *ResourceInfo, err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)
	var resourceInfo ResourceInfo
	ri = &resourceInfo

	if cdxService.Name == "" {
		getLogger().Errorf("service missing required value `name` : %v ", cdxService)
	}

	if cdxService.Version == "" {
		getLogger().Warningf("service named `%s` missing `version`", cdxService.Name)
	}

	if cdxService.BomRef == "" {
		getLogger().Warningf("service named `%s` missing `bom-ref`", cdxService.Name)
	}

	// hash any component w/o a license using special key name
	resourceInfo.Type = RESOURCE_TYPE_SERVICE
	resourceInfo.Service = cdxService
	resourceInfo.Name = cdxService.Name
	resourceInfo.BomRef = cdxService.BomRef
	resourceInfo.Version = cdxService.Version
	resourceInfo.SupplierProvider = cdxService.Provider
	resourceInfo.Properties = cdxService.Properties

	// TODO: AppendLicenseInfo(LICENSE_NONE, resourceInfo)
	resourceMap.Put(resourceInfo.BomRef, resourceInfo)

	getLogger().Tracef("Put: %s (`%s`), `%s`)",
		resourceInfo.Name,
		resourceInfo.Version,
		resourceInfo.BomRef)

	// Recursively hash licenses for all child components (i.e., hierarchical composition)
	if len(cdxService.Services) > 0 {
		err = hashServices(cdxService.Services, location)
		if err != nil {
			return
		}
	}
	return
}

// NOTE: This list is NOT de-duplicated
// TODO: Add a --no-title flag to skip title output
func DisplayResourceListText(output io.Writer) {
	getLogger().Enter()
	defer getLogger().Exit()

	// initialize tabwriter
	w := new(tabwriter.Writer)
	defer w.Flush()

	// min-width, tab-width, padding, pad-char, flags
	w.Init(output, 8, 2, 2, ' ', 0)

	// create title row and underline row from slices of optional and compulsory titles
	titles, underlines := createTitleRows(RESOURCE_LIST_TITLES, nil)

	// Add tabs between column titles for the tabWRiter
	fmt.Fprintf(w, "%s\n", strings.Join(titles, "\t"))
	fmt.Fprintf(w, "%s\n", strings.Join(underlines, "\t"))

	// Display a warning "missing" in the actual output and return (short-circuit)
	entries := resourceMap.Entries()

	// Emit no license warning into output
	if len(entries) == 0 {
		fmt.Fprintf(w, "%s\n", MSG_OUTPUT_NO_RESOURCES_FOUND)
		return
	}

	// Sort by Type
	sort.Slice(entries, func(i, j int) bool {
		resource1 := (entries[i].Value).(ResourceInfo)
		resource2 := (entries[j].Value).(ResourceInfo)
		if resource1.Type != resource2.Type {
			return resource1.Type < resource2.Type
		}

		return resource1.Name < resource2.Name
	})

	var resourceInfo ResourceInfo

	for _, entry := range entries {
		value := entry.Value
		resourceInfo = value.(ResourceInfo)

		// Format line and write to output
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			resourceInfo.Type,
			resourceInfo.Name,
			resourceInfo.Version,
			resourceInfo.BomRef)
	}
}

// TODO: Add a --no-title flag to skip title output
func DisplayResourceListCSV(output io.Writer) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// initialize writer and prepare the list of entries (i.e., the "rows")
	w := csv.NewWriter(output)
	defer w.Flush()

	if err = w.Write(RESOURCE_LIST_TITLES); err != nil {
		return getLogger().Errorf("error writing record to csv (%v): %s", output, err)
	}

	// Display a warning "missing" in the actual output and return (short-circuit)
	entries := resourceMap.Entries()

	// Emit no resource found warning into output
	if len(entries) == 0 {
		currentRow := []string{MSG_OUTPUT_NO_RESOURCES_FOUND}
		w.Write(currentRow)
		return fmt.Errorf(currentRow[0])
	}

	// Sort by Type
	sort.Slice(entries, func(i, j int) bool {
		resource1 := (entries[i].Value).(ResourceInfo)
		resource2 := (entries[j].Value).(ResourceInfo)
		if resource1.Type != resource2.Type {
			return resource1.Type < resource2.Type
		}

		return resource1.Name < resource2.Name
	})

	var resourceInfo ResourceInfo
	var line []string

	for _, entry := range entries {
		value := entry.Value
		resourceInfo = value.(ResourceInfo)
		line = nil
		line = append(line,
			resourceInfo.Type,
			resourceInfo.Name,
			resourceInfo.Version,
			resourceInfo.BomRef)

		if err = w.Write(line); err != nil {
			getLogger().Errorf("csv.Write: %w", err)
		}
	}

	return
}
