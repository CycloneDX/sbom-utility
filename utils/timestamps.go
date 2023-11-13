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

package utils

import (
	"fmt"
	"strings"
)

// TODO we SHOULD normalize the timestamp to Z (0)
func TruncateTimeStampISO8601Date(fullTimestamp string) (date string, err error) {

	// default to returning the original value
	date = fullTimestamp

	// TODO validate timestamp regex for yyy-mm-dd (minimum format)
	if fullTimestamp == "" {
		return
	}

	// if it appears to be date-only already, validate it
	if len(fullTimestamp) == 10 {
		if ValidateISO8601TimestampISO8601DateTime(fullTimestamp, REGEX_ISO_8601_DATE) {
			// return the (now validated) value passed in
			return
		} else {
			err = fmt.Errorf("invalid ISO 8601 timestamp: `%s`", fullTimestamp)
			// return what we were given
			return
		}
	}

	// Assume timestamp is date-time format; find where the date portion separator appears
	iSep := strings.IndexByte(fullTimestamp, ISO8601_TIME_SEPARATOR)

	if iSep == -1 {
		err = fmt.Errorf("invalid ISO 8601 timestamp: `%s`", fullTimestamp)
		// return what we were given
		return
	}

	// Slice out the date portion and validate what should be just the date portion
	date = fullTimestamp[:iSep]

	if !ValidateISO8601TimestampISO8601DateTime(date, REGEX_ISO_8601_DATE) {
		err = fmt.Errorf("invalid ISO 8601 timestamp: `%s`", fullTimestamp)
		// return what we were given
		date = fullTimestamp
		return
	}

	return
}

// Currently, truncate
const REGEX_ISO_8601_DATE_TIME = "[0-9]{4}-[0-9]{2}-[0-9]{2}T([0-9]{2}:){2}[0-9]{2}[+|-][0-9]{2}:[0-9]{2}"
const REGEX_ISO_8601_DATE = "[0-9]{4}-[0-9]{2}-[0-9]{2}"
const ISO8601_TIME_SEPARATOR = 'T'

// Validates a complete Date-Time ISO8601 timestamp
// TODO verify it works for data, date-time, date-time-timezone formats
func ValidateISO8601TimestampISO8601DateTime(timestamp string, regex string) (valid bool) {

	compiledRegEx, errCompile := CompileRegex(regex)

	if errCompile != nil {
		return false
	}

	// Test that the field value matches the regex supplied in the current filter
	// Note: the regex compilation is performed during command param. processing
	if match := compiledRegEx.Match([]byte(timestamp)); match {
		return true
	}

	return false
}
