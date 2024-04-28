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
	"fmt"
	"strconv"
	"strings"

	"github.com/CycloneDX/sbom-utility/common"
	"github.com/CycloneDX/sbom-utility/utils"
	"github.com/spf13/cobra"
)

// Common/reusable Flags used across multiple report commands
const (
	FLAG_REPORT_WHERE      = "where"
	FLAG_REPORT_WHERE_HELP = "comma-separated list of `key=<regex>` clauses used to filter the result set"
)

const (
	REPORT_LIST_TITLE_ROW_SEPARATOR = "-"
	REPORT_LIST_VALUE_NONE          = "none"
)

// Text report helpers
// func createTitleTextSeparators(titles []string) (separatorLine []string) {
// 	var underline string
// 	for _, title := range titles {
// 		underline = strings.Repeat(REPORT_LIST_TITLE_ROW_SEPARATOR, len(title))
// 		separatorLine = append(separatorLine, underline)
// 	}
// 	return
// }

// Markdown report helpers
const (
	MD_COLUMN_SEPARATOR = "|"
	MD_ALIGN_LEFT       = ":--"
	MD_ALIGN_CENTER     = "-:-"
	MD_ALIGN_RIGHT      = "--:"
)

// Helper function in case displayed table columns become too wide
func truncateString(value string, maxLength int, showDetail bool) string {
	length := len(value)
	if length > maxLength {
		value = value[:maxLength]
		if showDetail {
			value = fmt.Sprintf("%s (%v/%v)", value, maxLength, length)
		}
	}
	return value
}

func createMarkdownColumnAlignment(titles []string) (alignment []string) {
	for range titles {
		alignment = append(alignment, MD_ALIGN_LEFT)
	}
	return
}

func createMarkdownColumnAlignmentRow(columns []ColumnFormatData) (alignment []string) {
	for range columns {
		alignment = append(alignment, MD_ALIGN_LEFT)
	}
	return
}

func createMarkdownRow(data []string) string {
	return MD_COLUMN_SEPARATOR +
		strings.Join(data, MD_COLUMN_SEPARATOR) +
		MD_COLUMN_SEPARATOR
}

// Report processing helpers
func processWhereFlag(cmd *cobra.Command) (whereFilters []common.WhereFilter, err error) {
	// Process flag: --where
	whereValues, errGet := cmd.Flags().GetString(FLAG_REPORT_WHERE)

	if errGet != nil {
		err = getLogger().Errorf("failed to read flag `%s` value", FLAG_REPORT_WHERE)
		return
	}

	whereFilters, err = retrieveWhereFilters(whereValues)

	return
}

// Parse "--where" flags on behalf of utility commands that filter output reports (lists)
func retrieveWhereFilters(whereValues string) (whereFilters []common.WhereFilter, err error) {
	// Use common functions for parsing query request clauses
	wherePredicates := common.ParseWherePredicates(whereValues)
	whereFilters, err = common.ParseWhereFilters(wherePredicates)
	return
}

// A generic function that takes variadic "column" data (for a single row) as an interface{}
// of either string or []string types and, if needed, "wraps" the single row data into multiple
// text rows according to parameterized constraints.
// NOTE: Currently, only wraps []string values
// TODO: Also wrap on "maxChar" (per column) limit
func wrapTableRowText(maxChars int, joinChar string, columns ...interface{}) (tableData [][]string, err error) {

	// calculate column dimension needed as max of slice sizes
	numColumns := len(columns)

	// Allocate a 1 row table
	tableData = make([][]string, 1)

	// Allocate the first row of the multi-row "table"
	var numRowsAllocated int = 1
	rowData := make([]string, numColumns)
	tableData[0] = rowData

	// for each column inspect its data and "wrap" as needed
	// TODO: wrap on macChars using spaces; for now, just support list output
	for iCol, column := range columns {
		switch data := column.(type) {
		case string:
			// for now, a straightforward copy for string types
			rowData[iCol] = column.(string)
		case []string:
			entries := column.([]string)
			numRowsNeeded := len(entries)

			// If needed, allocate and append new rows
			if numRowsNeeded > numRowsAllocated {
				// as long as we need more rows allocated
				for ; numRowsAllocated < numRowsNeeded; numRowsAllocated++ {
					rowData = make([]string, numColumns)
					tableData = append(tableData, rowData)
				}
				getLogger().Debugf("tableData: (%v)", tableData)
			}

			// Add the multi-line data to appropriate row in the table
			for i := 0; i < numRowsNeeded; i++ {
				tableData[i][iCol] = entries[i]
			}
			//getLogger().Debugf("tableData: (%v)", tableData)
		case bool:
			rowData[iCol] = strconv.FormatBool(data)
		case int:
			rowData[iCol] = strconv.Itoa(data)
		case nil:
			//getLogger().Tracef("nil value for column: `%v`", columnData.DataKey)
			rowData[iCol] = REPORT_LIST_VALUE_NONE
		default:
			err = getLogger().Errorf("Unexpected type for report data: type: `%T`, value: `%v`", data, data)
		}
	}

	return
}

// Report column data values
const REPORT_SUMMARY_DATA_TRUE = true
const REPORT_REPLACE_LINE_FEEDS_TRUE = true
const DEFAULT_COLUMN_TRUNCATE_LENGTH = -1

// TODO: Support additional flags to:
//   - show number of chars shown vs. available when truncated (e.g., (x/y))
//   - provide "empty" value to display in column (e.g., "none" or "UNDEFINED")
//   - inform how to "summarize" (e.g., show-first-only) data if data type is a slice (e.g., []string)
//     NOTE: if only a subset of entries are shown on a summary, an indication of (x) entries could be shown as well
type ColumnFormatData struct {
	DataKey               string // Note: data key is the column label (where possible)
	DefaultTruncateLength int    // truncate data when `--format txt`
	IsSummaryData         bool   // include in `--summary` reports
	ReplaceLineFeeds      bool   // replace line feeds with spaces (e.g., for multi-line descriptions)
}

func prepareReportTitleData(formatData []ColumnFormatData, summarizedReport bool) (titleData []string, separatorData []string) {

	var underline string

	for _, columnData := range formatData {

		// if the report we are preparing is a summarized one (i.e., --summary true)
		// we will skip appending column data not marked to be included in a summary report
		if summarizedReport && !columnData.IsSummaryData {
			continue
		}
		titleData = append(titleData, columnData.DataKey)

		underline = strings.Repeat(REPORT_LIST_TITLE_ROW_SEPARATOR, len(columnData.DataKey))
		separatorData = append(separatorData, underline)
	}

	return
}

func prepareReportLineData(structIn interface{}, formatData []ColumnFormatData, summarizedReport bool) (lineData []string, err error) {
	var mapStruct map[string]interface{}
	var data interface{}
	var dataFound bool
	var sliceString []string
	var joinedData string

	mapStruct, err = utils.MarshalStructToJsonMap(structIn)

	for _, columnData := range formatData {
		// reset local vars
		sliceString = nil

		// if the report we are preparing is a summarized one (i.e., --summary true)
		// we will skip appending column data not marked to be included in a summary report
		if summarizedReport && !columnData.IsSummaryData {
			continue
		}

		data, dataFound = mapStruct[columnData.DataKey]

		if !dataFound {
			err = getLogger().Errorf("data not found in structure: key: `%s`", columnData.DataKey)
			return
		}

		switch typedData := data.(type) {
		case string:
			// replace line feeds with spaces in description
			if typedData != "" {
				if columnData.ReplaceLineFeeds {
					// For tabbed text tables, replace line feeds with spaces
					typedData = strings.ReplaceAll(typedData, "\n", " ")
				}
			}
			lineData = append(lineData, typedData)
		case bool:
			lineData = append(lineData, strconv.FormatBool(typedData))
		case int:
			lineData = append(lineData, strconv.Itoa(typedData))
		case []interface{}:
			// convert to []string
			for _, value := range typedData {
				sliceString = append(sliceString, value.(string))
			}

			// separate each entry with a comma (and space for readability)
			joinedData = strings.Join(sliceString, ", ")

			if joinedData != "" {
				// replace line feeds with spaces in description
				if columnData.ReplaceLineFeeds {
					// For tabbed text tables, replace line feeds with spaces
					joinedData = strings.ReplaceAll(joinedData, "\n", " ")
				}
			}

			if summarizedReport {
				if len(sliceString) > 0 {
					lineData = append(lineData, sliceString[0])
				}
				continue
			}

			lineData = append(lineData, joinedData)
		case nil:
			//getLogger().Tracef("nil value for column: `%v`", columnData.DataKey)
			lineData = append(lineData, REPORT_LIST_VALUE_NONE)
		default:
			err = getLogger().Errorf("Unexpected type for report data: type: `%T`, value: `%v`", data, data)
		}
	}

	return
}
