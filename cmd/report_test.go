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
	"strings"
	"testing"

	"github.com/CycloneDX/sbom-utility/utils"
)

const REPORT_LINE_CONTAINS_ANY = -1

func innerRunReportResultTests(t *testing.T, testInfo *CommonTestInfo, outputBuffer bytes.Buffer, outputError error) (err error) {
	getLogger().Tracef("TestInfo: %s", testInfo)

	// TEST: Expected error matches actual error
	if testInfo.ResultExpectedError != nil {
		// NOTE: err = nil will also fail if error was expected
		if !ErrorTypesMatch(outputError, testInfo.ResultExpectedError) {
			err = getLogger().Errorf("expected error: %T, actual error: %T", testInfo.ResultExpectedError, outputError)
			t.Error(err.Error())
		}
		// TODO: getLogger().Tracef("success")
		// Always return (with the actual error); as subsequent tests are rendered invalid
		return outputError
	}

	// TEST: Unexpected error: return immediately/do not test output/results
	if outputError != nil {
		err = getLogger().Errorf("test failed: %s: detail: %s ", testInfo, outputError.Error())
		t.Error(err.Error())
		return
	}

	// TEST: Line contains a set of string values
	// TODO: support any number of row/values in test info. structure
	if len(testInfo.ResultLineContainsValues) > 0 {
		matchFoundLine, matchFound := lineContainsValues(outputBuffer, testInfo.ResultLineContainsValuesAtLineNum, testInfo.ResultLineContainsValues...)
		if !matchFound {
			err = getLogger().Errorf("output does not contain expected values: `%v` at line: %v\n", strings.Join(testInfo.ResultLineContainsValues, ","), testInfo.ResultLineContainsValuesAtLineNum)
			t.Error(err.Error())
			return
		}
		getLogger().Tracef("output contains expected values: `%v` at line: %v\n", testInfo.ResultLineContainsValues, matchFoundLine)
	}

	// TEST: Line Count
	if testInfo.ResultExpectedLineCount != TI_DEFAULT_LINE_COUNT {
		outputResults := outputBuffer.String()
		outputLineCount := strings.Count(outputResults, "\n")
		if outputLineCount != testInfo.ResultExpectedLineCount {
			err = getLogger().Errorf("output did not contain expected line count: %v/%v (expected/actual)", testInfo.ResultExpectedLineCount, outputLineCount)
			t.Errorf("%s: format: `%s`, summary: `%v`, where clause: `%s`",
				err.Error(),
				testInfo.ListFormat,
				testInfo.ListSummary,
				testInfo.WhereClause)
			return
		}
		getLogger().Tracef("success: output contained expected line count: %v", testInfo.ResultExpectedLineCount)
	}

	// TEST: valid JSON if format JSON
	// TODO: Allow caller to pass in CDX struct type to validate JSON array contains that type
	if testInfo.ListFormat == FORMAT_JSON {
		// Use Marshal to test for validity
		if !utils.IsValidJsonRaw(outputBuffer.Bytes()) {
			err = getLogger().Errorf("output did not contain valid format data; expected: `%s`", FORMAT_JSON)
			t.Error(err.Error())
			t.Logf("%s", outputBuffer.String())
			return
		}
		getLogger().Tracef("success: validated output format: `%s`", FORMAT_JSON)
	}

	// TODO: add general validation for CSV and Markdown formats
	if testInfo.ListFormat == FORMAT_CSV {
		getLogger().Tracef("Testing format: %s", FORMAT_CSV)
	}

	if testInfo.ListFormat == FORMAT_MARKDOWN {
		getLogger().Tracef("Testing format: %s", FORMAT_MARKDOWN)
	}

	return
}

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