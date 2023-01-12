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
	"strings"
	"text/tabwriter"

	"github.com/scs/sbom-utility/schema"
	"github.com/scs/sbom-utility/utils"
	"github.com/spf13/cobra"
)

// Subcommand flags
const (
	FLAG_SCHEMA_OUTPUT_FORMAT_HELP = "format output using the specified type"
)

// Command help formatting
var SCHEMA_LIST_SUPPORTED_FORMATS = MSG_SUPPORTED_OUTPUT_FORMATS_HELP +
	strings.Join([]string{OUTPUT_TEXT, OUTPUT_CSV, OUTPUT_MARKDOWN}, ", ")

var SCHEMA_LIST_TITLES = []string{"Format", "Version", "Variant", "File", "Source"}

func NewCommandSchema() *cobra.Command {
	var command = new(cobra.Command)
	command.Use = "schema"
	command.Short = "View supported SBOM schemas"
	command.Long = fmt.Sprintf("View built-in SBOM schemas supported by the utility. The default command produces a list based upon `%s`.", DEFAULT_SCHEMA_CONFIG)
	command.Flags().StringVarP(&utils.GlobalFlags.OutputFormat, FLAG_FILE_OUTPUT_FORMAT, "", OUTPUT_TEXT,
		FLAG_SCHEMA_OUTPUT_FORMAT_HELP+SCHEMA_LIST_SUPPORTED_FORMATS)
	command.RunE = schemaCmdImpl
	command.PreRunE = func(cmd *cobra.Command, args []string) (err error) {
		if len(args) != 0 {
			return getLogger().Errorf("Too many arguments provided: %v", args)
		}
		return
	}
	return command
}

func schemaCmdImpl(cmd *cobra.Command, args []string) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	outputFile, writer, err := createOutputFile(utils.GlobalFlags.OutputFile)

	if err == nil {
		err = ListSchemas(writer)
	}

	// always close the output file
	if outputFile != nil {
		outputFile.Close()
		getLogger().Infof("Closed output file: `%s`", utils.GlobalFlags.OutputFile)
	}

	return
}

func ListSchemas(writer io.Writer) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// default output (writer) to standard out
	switch utils.GlobalFlags.OutputFormat {
	case OUTPUT_DEFAULT:
		// defaults to text if no explicit `--format` parameter
		err = DisplaySchemasTabbedText(writer)
	case OUTPUT_TEXT:
		err = DisplaySchemasTabbedText(writer)
	case OUTPUT_CSV:
		err = DisplaySchemasCSV(writer)
	case OUTPUT_MARKDOWN:
		err = DisplaySchemasMarkdown(writer)
	default:
		// default to text format for anything else
		getLogger().Warningf("Unsupported format: `%s`; using default format.",
			utils.GlobalFlags.OutputFormat)
		err = DisplaySchemasTabbedText(writer)
	}
	return
}

// TODO: Add a --no-title flag to skip title output
func DisplaySchemasTabbedText(output io.Writer) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// initialize tabwriter
	w := new(tabwriter.Writer)

	// min-width, tab-width, padding, pad-char, flags
	w.Init(output, 8, 2, 2, ' ', 0)

	defer w.Flush()

	if len(schema.SupportedFormatConfig.Formats) > 0 {
		var formatName = ""

		// Create title row and add tabs between column titles for the tabWRiter
		titles, underlines := createTitleRows(SCHEMA_LIST_TITLES, nil)
		fmt.Fprintf(w, "%s\n", strings.Join(titles, "\t"))
		fmt.Fprintf(w, "%s\n", strings.Join(underlines, "\t"))

		for _, format := range (schema.SupportedFormatConfig).Formats {
			formatName = format.CanonicalName

			if len(format.Schemas) > 0 {
				for _, currentSchema := range format.Schemas {
					fmt.Fprintf(w, "%v\t%s\t%s\t%s\t%s\n",
						formatName,
						currentSchema.Version,
						schema.FormatSchemaVariant(currentSchema.Variant),
						currentSchema.File,
						currentSchema.Url)
				}
			} else {
				getLogger().Warningf("No supported schemas for format `%s`.\n", formatName)
			}
		}
	} else {
		getLogger().Warningf("No supported built-in formats found in `%s`.\n", DEFAULT_SCHEMA_CONFIG)
	}

	fmt.Fprintln(w, "")
	return nil
}

// TODO: Add a --no-title flag to skip title output
func DisplaySchemasMarkdown(output io.Writer) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// create title row
	titles, _ := createTitleRows(SCHEMA_LIST_TITLES, nil)
	titleRow := createMarkdownRow(titles)
	fmt.Fprintf(output, "%s\n", titleRow)

	alignments := createMarkdownColumnAlignment(titles)
	alignmentRow := createMarkdownRow(alignments)
	fmt.Fprintf(output, "%s\n", alignmentRow)

	// Emit no schemas found warning into output
	if len(schema.SupportedFormatConfig.Formats) == 0 {
		fmt.Fprintf(output, "%s\n", MSG_OUTPUT_NO_SCHEMAS_FOUND)
		return fmt.Errorf(MSG_OUTPUT_NO_SCHEMAS_FOUND)
	}

	// TODO: Sort entries by schema format and version
	// NOTE: for now, entries are already sorted by creating them that way in the config.json file
	// sort.Slice(keyNames, func(i, j int) bool {
	// 	return keyNames[i].(string) < keyNames[j].(string)
	// })

	var line []string
	var lineRow string
	var formatName = ""

	for _, format := range (schema.SupportedFormatConfig).Formats {
		formatName = format.CanonicalName

		if len(format.Schemas) > 0 {
			for _, currentSchema := range format.Schemas {

				// reset current line
				line = nil

				line = append(line,
					formatName,
					currentSchema.Version,
					schema.FormatSchemaVariant(currentSchema.Variant),
					currentSchema.File,
					currentSchema.Url)

				lineRow = createMarkdownRow(line)
				fmt.Fprintf(output, "%s\n", lineRow)
			}
		} else {
			getLogger().Warningf("No supported schemas for format `%s`.\n", formatName)
		}
	}

	return
}

// TODO: Add a --no-title flag to skip title output
func DisplaySchemasCSV(output io.Writer) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// initialize writer and prepare the list of entries (i.e., the "rows")
	w := csv.NewWriter(output)
	defer w.Flush()

	if err = w.Write(SCHEMA_LIST_TITLES); err != nil {
		return getLogger().Errorf("error writing record to csv (%v): %s", output, err)
	}

	// Emit no schemas found warning into output
	if len(schema.SupportedFormatConfig.Formats) == 0 {
		fmt.Fprintf(output, "%s\n", MSG_OUTPUT_NO_SCHEMAS_FOUND)
		return fmt.Errorf(MSG_OUTPUT_NO_SCHEMAS_FOUND)
	}

	// TODO: Sort entries by schema format and version
	// sort.Slice(keyNames, func(i, j int) bool {
	// 	return keyNames[i].(string) < keyNames[j].(string)
	// })
	var line []string
	var formatName = ""

	for _, format := range (schema.SupportedFormatConfig).Formats {
		formatName = format.CanonicalName

		if len(format.Schemas) > 0 {
			for _, currentSchema := range format.Schemas {

				line = nil
				line = append(line,
					formatName,
					currentSchema.Version,
					schema.FormatSchemaVariant(currentSchema.Variant),
					currentSchema.File,
					currentSchema.Url)

				if err = w.Write(line); err != nil {
					getLogger().Errorf("csv.Write: %w", err)
				}
			}
		}
	}

	return
}
