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
	"bytes"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// Common/reusable Flags used across multiple report commands
const (
	FLAG_REPORT_WHERE      = "where"
	FLAG_REPORT_WHERE_HELP = "comma-separated list of `key=<regex>` clauses used to filter the result set"
)

const (
	REPORT_LIST_TITLE_ROW_SEPARATOR = "-"
)

// Text report helpers
func createTitleTextSeparators(titles []string) (separatorLine []string) {
	var underline string
	for _, title := range titles {
		underline = strings.Repeat(REPORT_LIST_TITLE_ROW_SEPARATOR, len(title))
		separatorLine = append(separatorLine, underline)
	}
	return
}

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

const REPORT_LINE_CONTAINS_ANY = -1

func lineContainsValues(buffer bytes.Buffer, lineNum int, values ...string) (int, bool) {
	lines := strings.Split(buffer.String(), "\n")
	getLogger().Tracef("output: %s", lines)
	//var lineContainsValue bool = false

	for curLineNum, line := range lines {

		// if ths is a line we need to test
		if lineNum == REPORT_LINE_CONTAINS_ANY || curLineNum == lineNum {
			// test that all values occur in the current line
			for iValue, value := range values {
				if !strings.Contains(line, value) {
					// if we failed to match all values on the specified line return failure
					if curLineNum == lineNum {
						return curLineNum, false
					}
					// else, keep checking next line
					break
				}

				// If this is the last value to test for, then all values have matched
				if iValue+1 == len(values) {
					return curLineNum, true
				}
			}
		}
	}
	return REPORT_LINE_CONTAINS_ANY, false
}

func createMarkdownColumnAlignment(titles []string) (alignment []string) {
	for range titles {
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
func processWhereFlag(cmd *cobra.Command) (whereFilters []WhereFilter, err error) {
	// Process flag: --where
	whereValues, errGet := cmd.Flags().GetString(FLAG_REPORT_WHERE)

	if errGet != nil {
		err = getLogger().Errorf("failed to read flag `%s` value", FLAG_REPORT_WHERE)
		return
	}

	whereFilters, err = retrieveWhereFilters(whereValues)

	return
}

func retrieveWhereFilters(whereValues string) (whereFilters []WhereFilter, err error) {
	var whereExpressions []string

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

// A generic function that takes variadic "column" data (for a single row) as an interface{}
// of either string or []string types and, if needed, "wraps" the single row data into multiple
// text rows according to parameterized constraints.
// NOTE: Currently, only wraps []string values
// TODO: Also wrap on "maxChar" (per column) limit
func wrapTableRowText(maxChars int, joinChar string, columns ...interface{}) (tableData [][]string, err error) {

	// Assure separator char is set and ONLY a single character
	// TODO
	// if joinChar == "" || len(joinChar) > 1 {
	// 	joinChar = ","
	// }

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
		default:
			err = getLogger().Errorf("Unexpected type for report data: (%T): %v", data, data)
		}
	}

	return
}
