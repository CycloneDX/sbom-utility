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
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/CycloneDX/sbom-utility/utils"
	"github.com/spf13/cobra"
)

var STATS_LIST_OUTPUT_SUPPORTED_FORMATS = MSG_SUPPORTED_OUTPUT_FORMATS_HELP +
	strings.Join([]string{FORMAT_TEXT, FORMAT_CSV, FORMAT_MARKDOWN}, ", ")

func NewCommandStats() *cobra.Command {
	var command = new(cobra.Command)
	command.Use = CMD_USAGE_STATS_LIST
	command.Short = "Show BOM input file statistics"
	command.Long = "Show BOM input file statistics"
	command.Flags().StringVarP(&utils.GlobalFlags.PersistentFlags.OutputFormat, FLAG_FILE_OUTPUT_FORMAT, "", FORMAT_TEXT,
		STATS_LIST_OUTPUT_SUPPORTED_FORMATS)
	command.RunE = statsCmdImpl
	// TODO: command.ValidArgs = VALID_SUBCOMMANDS_S
	command.PreRunE = func(cmd *cobra.Command, args []string) (err error) {
		// Test for required flags (parameters)
		err = preRunTestForInputFile(cmd, args)
		return
	}
	return command
}

func statsCmdImpl(cmd *cobra.Command, args []string) (err error) {
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

	if err == nil {
		err = ListStats(writer, utils.GlobalFlags.PersistentFlags, utils.GlobalFlags.StatsFlags)
	}

	return
}

// Assure all errors are logged
func processStatisticsResults(err error) {
	if err != nil {
		// No special processing at this time
		getLogger().Error(err)
	}
}

// NOTE: resourceType has already been validated
func ListStats(writer io.Writer, persistentFlags utils.PersistentCommandFlags, statsFlags utils.StatsCommandFlags) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// use function closure to assure consistent error output based upon error type
	defer func() {
		if err != nil {
			processStatisticsResults(err)
		}
	}()

	// Note: returns error if either file load or unmarshal to JSON map fails
	var document *schema.BOM
	document, err = LoadInputBOMFileAndDetectSchema()

	if err != nil {
		return
	}

	loadDocumentStatisticalEntities(document, statsFlags)

	err = loadComponentStats(document)
	if err != nil {
		return
	}

	format := persistentFlags.OutputFormat
	getLogger().Infof("Outputting listing (`%s` format)...", format)
	switch format {
	case FORMAT_TEXT:
		DisplayStatsText(document, writer)
	// case FORMAT_CSV:
	// 	DisplayResourceListCSV(writer)
	// case FORMAT_MARKDOWN:
	// 	DisplayResourceListMarkdown(writer)
	default:
		// Default to Text output for anything else (set as flag default)
		getLogger().Warningf("Stats not supported for `%s` format; defaulting to `%s` format...",
			format, FORMAT_TEXT)
		DisplayStatsText(document, writer)
	}

	return
}

func loadComponentStats(document *schema.BOM) (err error) {
	if document == nil {
		return getLogger().Errorf("invalid BOM document")
	}

	stats := document.Statistics

	if stats == nil || stats.ComponentStats == nil {
		return getLogger().Errorf("invalid BOM stats")
	}

	//componentStats := stats.ComponentStats
	mapComponents := document.ComponentMap

	if mapComponents == nil {
		return getLogger().Errorf("invalid component map")
	}

	for _, key := range mapComponents.KeySet() {
		aComponents, _ := mapComponents.Get(key)

		//fmt.Printf("value=%v", aComponents)

		if len(aComponents) > 1 {
			// TODO: are they unique entries? or are DeepEqual() duplicates?
			getLogger().Warningf("component `%v` has duplicate `%v` entries", key, len(aComponents))
		}

		// for _, c := range aComponents {
		// 	fmt.Printf("comp=%v", c)
		// }
	}

	return
}

func loadDocumentStatisticalEntities(document *schema.BOM, statsFlags utils.StatsCommandFlags) (err error) {
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

	err = document.HashComponentResources(nil)
	if err != nil {
		return
	}

	err = document.HashServiceResources(nil)
	if err != nil {
		return
	}

	err = document.HashVulnerabilityResources(nil)
	if err != nil {
		return
	}

	return
}

// NOTE: This list is NOT de-duplicated
// TODO: Add a --no-title flag to skip title output
func DisplayStatsText(bom *schema.BOM, output io.Writer) {
	getLogger().Enter()
	defer getLogger().Exit()

	// initialize tabwriter
	w := new(tabwriter.Writer)
	defer w.Flush()

	// min-width, tab-width, padding, pad-char, flags
	w.Init(output, 8, 2, 2, ' ', 0)

	// create underline row from compulsory titles
	underlines := createTitleTextSeparators(RESOURCE_LIST_TITLES)

	// Add tabs between column titles for the tabWRiter
	fmt.Fprintf(w, "%s\n", strings.Join(RESOURCE_LIST_TITLES, "\t"))
	fmt.Fprintf(w, "%s\n", strings.Join(underlines, "\t"))

	// Display a warning "missing" in the actual output and return (short-circuit)
	entries := bom.ResourceMap.Entries()

	// Emit no license warning into output
	if len(entries) == 0 {
		fmt.Fprintf(w, "%s\n", MSG_OUTPUT_NO_RESOURCES_FOUND)
		return
	}

	// Sort by Type then Name
	sort.Slice(entries, func(i, j int) bool {
		resource1 := (entries[i].Value).(schema.CDXResourceInfo)
		resource2 := (entries[j].Value).(schema.CDXResourceInfo)
		if resource1.Type != resource2.Type {
			return resource1.Type < resource2.Type
		}

		return resource1.Name < resource2.Name
	})

	var resourceInfo schema.CDXResourceInfo

	for _, entry := range entries {
		value := entry.Value
		resourceInfo = value.(schema.CDXResourceInfo)

		// Format line and write to output
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			resourceInfo.Type,
			resourceInfo.Name,
			resourceInfo.Version,
			resourceInfo.BOMRef)
	}
}
