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
	"github.com/spf13/cobra"
)

const (
	SUBCOMMAND_SCHEMA_LIST = "list"
)

const (
	MSG_OUTPUT_NO_SCHEMAS_FOUND = "[WARN] no schemas found in configuration (i.e., \"config.json\")"
)

var VALID_SUBCOMMANDS_SCHEMA = []string{SUBCOMMAND_SCHEMA_LIST}

// Subcommand flags
const (
	FLAG_SCHEMA_OUTPUT_FORMAT_HELP = "format output using the specified type"
)

const (
	SCHEMA_DATA_KEY_KEY_NAME    = "name"    // summary
	SCHEMA_DATA_KEY_KEY_FORMAT  = "format"  // summary
	SCHEMA_DATA_KEY_KEY_VERSION = "version" // summary
	SCHEMA_DATA_KEY_KEY_VARIANT = "variant" // summary
	SCHEMA_DATA_KEY_KEY_FILE    = "file"    // summary
	SCHEMA_DATA_KEY_KEY_SOURCE  = "url"     // summary
)

// NOTE: columns will be output in order they are listed here:
var SCHEMA_LIST_ROW_DATA = []ColumnFormatData{
	{SCHEMA_DATA_KEY_KEY_NAME, DEFAULT_COLUMN_TRUNCATE_LENGTH, REPORT_SUMMARY_DATA_TRUE, false},
	{SCHEMA_DATA_KEY_KEY_FORMAT, DEFAULT_COLUMN_TRUNCATE_LENGTH, REPORT_SUMMARY_DATA_TRUE, false},
	{SCHEMA_DATA_KEY_KEY_VERSION, DEFAULT_COLUMN_TRUNCATE_LENGTH, REPORT_SUMMARY_DATA_TRUE, false},
	{SCHEMA_DATA_KEY_KEY_VARIANT, DEFAULT_COLUMN_TRUNCATE_LENGTH, REPORT_SUMMARY_DATA_TRUE, false},
	{SCHEMA_DATA_KEY_KEY_FILE, DEFAULT_COLUMN_TRUNCATE_LENGTH, REPORT_SUMMARY_DATA_TRUE, false},
	{SCHEMA_DATA_KEY_KEY_SOURCE, DEFAULT_COLUMN_TRUNCATE_LENGTH, REPORT_SUMMARY_DATA_TRUE, false},
}

// Command help formatting
var SCHEMA_LIST_SUPPORTED_FORMATS = MSG_SUPPORTED_OUTPUT_FORMATS_HELP +
	strings.Join([]string{FORMAT_TEXT, FORMAT_CSV, FORMAT_MARKDOWN}, ", ")

func NewCommandSchema() *cobra.Command {
	var command = new(cobra.Command)
	command.Use = CMD_USAGE_SCHEMA_LIST // "schema"
	command.Short = "View supported SBOM schemas"
	command.Long = fmt.Sprintf("View built-in SBOM schemas supported by the utility. The default command produces a list based upon `%s`.", DEFAULT_SCHEMA_CONFIG)
	command.Flags().StringVarP(&utils.GlobalFlags.PersistentFlags.OutputFormat, FLAG_FILE_OUTPUT_FORMAT, "", FORMAT_TEXT,
		FLAG_SCHEMA_OUTPUT_FORMAT_HELP+SCHEMA_LIST_SUPPORTED_FORMATS)
	command.Flags().StringP(FLAG_REPORT_WHERE, "", "", FLAG_REPORT_WHERE_HELP)
	command.RunE = schemaCmdImpl
	command.PreRunE = func(cmd *cobra.Command, args []string) (err error) {

		// TODO: pre-validate if --where keys are valid for this command

		// the command requires at least 1 valid subcommand (argument)
		if len(args) > 1 {
			return getLogger().Errorf("Too many arguments provided: %v", args)
		}

		// Make sure (optional) subcommand is known/valid
		if len(args) == 1 {
			if !preRunTestForSubcommand(command, VALID_SUBCOMMANDS_SCHEMA, args[0]) {
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

func schemaCmdImpl(cmd *cobra.Command, args []string) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Create output writer
	outputFilename := utils.GlobalFlags.PersistentFlags.OutputFile
	outputFile, writer, err := createOutputFile(outputFilename)
	getLogger().Tracef("outputFile: `%v`; writer: `%v`", outputFile, writer)

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

	err = ListSchemas(writer, utils.GlobalFlags.PersistentFlags, whereFilters)

	return
}

func flattenFormatSchemas(sliceFormatSchemas []schema.FormatSchema) (flattenedFormatSchemas []schema.FormatSchemaInstance) {

	for _, format := range sliceFormatSchemas {
		for _, schema := range format.Schemas {
			schema.Format = format.CanonicalName
			flattenedFormatSchemas = append(flattenedFormatSchemas, schema)
		}
	}
	return
}

func filterFormatSchemas(whereFilters []common.WhereFilter) (filteredFormats []schema.FormatSchemaInstance, err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	// Get format array
	sliceFormats := SupportedFormatConfig.Formats

	// flatten structs
	sliceSchemas := flattenFormatSchemas(sliceFormats)

	for _, schema := range sliceSchemas {

		var match bool = true

		if len(whereFilters) > 0 {
			mapFormat, _ := utils.ConvertStructToMap(schema)
			match, _ = whereFilterMatch(mapFormat, whereFilters)
		}

		if match {
			filteredFormats = append(filteredFormats, schema)

			getLogger().Tracef("append: %s\n",
				schema.Name)
		}

	}

	return
}

func sortFormatSchemaInstances(filteredSchemas []schema.FormatSchemaInstance) []schema.FormatSchemaInstance {
	// Sort by Format, Version, Variant
	sort.Slice(filteredSchemas, func(i, j int) bool {
		schema1 := filteredSchemas[i]
		schema2 := filteredSchemas[j]

		if schema1.Format != schema2.Format {
			return schema1.Format < schema2.Format
		}

		if schema1.Version != schema2.Version {
			return schema1.Version > schema2.Version
		}

		return schema1.Variant < schema2.Variant
	})

	return filteredSchemas
}

func ListSchemas(writer io.Writer, persistentFlags utils.PersistentCommandFlags, whereFilters []common.WhereFilter) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Hash all filtered list of schemas within input file
	getLogger().Infof("Scanning document for vulnerabilities...")
	var filteredSchemas []schema.FormatSchemaInstance
	filteredSchemas, err = filterFormatSchemas(whereFilters)

	if err != nil {
		return
	}

	// default output (writer) to standard out
	format := persistentFlags.OutputFormat
	switch format {
	case FORMAT_DEFAULT:
		// defaults to text if no explicit `--format` parameter
		err = DisplaySchemasTabbedText(writer, filteredSchemas)
	case FORMAT_TEXT:
		err = DisplaySchemasTabbedText(writer, filteredSchemas)
	case FORMAT_CSV:
		err = DisplaySchemasCSV(writer, filteredSchemas)
	case FORMAT_MARKDOWN:
		err = DisplaySchemasMarkdown(writer, filteredSchemas)
	default:
		// default to text format for anything else
		getLogger().Warningf("unsupported format: `%s`; using default format.", format)
		err = DisplaySchemasTabbedText(writer, filteredSchemas)
	}
	return
}

// TODO: Add a --no-title flag to skip title output
func DisplaySchemasTabbedText(output io.Writer, filteredSchemas []schema.FormatSchemaInstance) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// initialize tabwriter
	w := new(tabwriter.Writer)

	// min-width, tab-width, padding, pad-char, flags
	w.Init(output, 8, 2, 2, ' ', 0)
	defer w.Flush()

	// Emit no schemas found warning into output
	if len(filteredSchemas) == 0 {
		getLogger().Warningf("No supported built-in schemas found in `%s`.\n", DEFAULT_SCHEMA_CONFIG)
		return
	}

	// create title row and underline row from slices of optional and compulsory titles
	titles, underlines := prepareReportTitleData(SCHEMA_LIST_ROW_DATA, false)

	// Create title row and add tabs between column titles for the tabWRiter
	fmt.Fprintf(w, "%s\n", strings.Join(titles, "\t"))
	fmt.Fprintf(w, "%s\n", strings.Join(underlines, "\t"))

	// Sort by Format, Version, Variant
	filteredSchemas = sortFormatSchemaInstances(filteredSchemas)

	// Emit rows
	for _, schemaInstance := range filteredSchemas {

		fmt.Fprintf(w, "%v\t%s\t%s\t%s\t%s\t%s\n",
			schemaInstance.Name,
			schemaInstance.Format,
			schemaInstance.Version,
			schema.FormatSchemaVariant(schemaInstance.Variant),
			schemaInstance.File,
			schemaInstance.Url,
		)
	}

	// Always end on a newline
	fmt.Fprintln(w, "")
	return nil
}

// TODO: Add a --no-title flag to skip title output
func DisplaySchemasMarkdown(output io.Writer, filteredSchemas []schema.FormatSchemaInstance) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// create title row and alignment row from slices of optional and compulsory titles
	titles, _ := prepareReportTitleData(SCHEMA_LIST_ROW_DATA, false)
	titleRow := createMarkdownRow(titles)
	alignments := createMarkdownColumnAlignment(titles)
	alignmentRow := createMarkdownRow(alignments)
	fmt.Fprintf(output, "%s\n", titleRow)
	fmt.Fprintf(output, "%s\n", alignmentRow)

	// Emit no schemas found warning into output
	if len(filteredSchemas) == 0 {
		fmt.Fprintf(output, "%s\n", MSG_OUTPUT_NO_SCHEMAS_FOUND)
		return fmt.Errorf(MSG_OUTPUT_NO_SCHEMAS_FOUND)
	}

	var line []string
	var lineRow string

	// Sort by Format, Version, Variant
	filteredSchemas = sortFormatSchemaInstances(filteredSchemas)

	// Emit rows
	for _, schemaInstance := range filteredSchemas {

		// reset current line
		line = nil

		line = append(line,
			schemaInstance.Name,
			schemaInstance.Format,
			schemaInstance.Version,
			schema.FormatSchemaVariant(schemaInstance.Variant),
			schemaInstance.File,
			schemaInstance.Url,
		)

		lineRow = createMarkdownRow(line)
		fmt.Fprintf(output, "%s\n", lineRow)
	}
	return
}

// TODO: Add a --no-title flag to skip title output
func DisplaySchemasCSV(output io.Writer, filteredSchemas []schema.FormatSchemaInstance) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// initialize writer and prepare the list of entries (i.e., the "rows")
	w := csv.NewWriter(output)
	defer w.Flush()

	// create title row from slices of optional and compulsory titles
	titles, _ := prepareReportTitleData(SCHEMA_LIST_ROW_DATA, false)

	if err = w.Write(titles); err != nil {
		return getLogger().Errorf("error writing to output (%v): %s", titles, err)
	}

	// Emit no schemas found warning into output
	if len(filteredSchemas) == 0 {
		currentRow := []string{MSG_OUTPUT_NO_SCHEMAS_FOUND}
		if err = w.Write(currentRow); err != nil {
			return getLogger().Errorf("error writing to output (%v): %s", currentRow, err)
		}
		return fmt.Errorf(currentRow[0])
	}

	var line []string

	// Sort by Format, Version, Variant
	filteredSchemas = sortFormatSchemaInstances(filteredSchemas)

	// Emit rows
	for _, schemaInstance := range filteredSchemas {

		line = nil
		line = append(line,
			schemaInstance.Name,
			schemaInstance.Format,
			schemaInstance.Version,
			schema.FormatSchemaVariant(schemaInstance.Variant),
			schemaInstance.File,
			schemaInstance.Url,
		)

		if err = w.Write(line); err != nil {
			return getLogger().Errorf("error writing to output (%v): %s", line, err)
		}
	}

	return
}
