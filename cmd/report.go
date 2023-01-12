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

import "strings"

// Text report helpers
// TODO Make function params. variadic
func createTitleRows(titles1 []string, titles2 []string) (titles []string, underlines []string) {
	titles = append(titles1, titles2...)
	underlines = append(createTitleTextSeparators(titles1), createTitleTextSeparators(titles2)...)
	return
}

func createTitleTextSeparators(titles []string) (separatorLine []string) {
	var underline string
	for _, title := range titles {
		underline = strings.Repeat(LICENSE_LIST_TITLE_ROW_SEPARATOR, len(title))
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
