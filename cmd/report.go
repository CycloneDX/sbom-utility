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
