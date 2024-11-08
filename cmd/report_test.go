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
	"bytes"
	"strings"
	"testing"

	"github.com/CycloneDX/sbom-utility/utils"
)

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

	// TEST: Line Count (total)
	if testInfo.ResultExpectedLineCount != TI_RESULT_DEFAULT_LINE_COUNT {
		verifyFileLineCountAndIndentation(t, outputBuffer, testInfo)
	}

	// TEST: Line contains a set of string values
	// TODO: support any number of row/values in test info. structure
	if len(testInfo.ResultLineContainsValues) > 0 {
		matchFoundLine, matchFound := bufferLineContainsValues(outputBuffer, testInfo.ResultLineContainsValuesAtLineNum, testInfo.ResultLineContainsValues...)
		if !matchFound {
			err = getLogger().Errorf("output does not contain expected values: '%v' at line: %v\n", strings.Join(testInfo.ResultLineContainsValues, ","), testInfo.ResultLineContainsValuesAtLineNum)
			t.Error(err.Error())
			return
		}
		getLogger().Tracef("output contains expected values: '%v' at line: %v\n", testInfo.ResultLineContainsValues, matchFoundLine)
	}

	// TEST: valid JSON if format JSON
	// TODO: Allow caller to pass in CDX struct type to validate JSON array contains that type
	if testInfo.OutputFormat == FORMAT_JSON {
		// Use Marshal to test for validity
		if !utils.IsValidJsonRaw(outputBuffer.Bytes()) {
			err = getLogger().Errorf("output did not contain valid format data; expected: '%s'", FORMAT_JSON)
			t.Error(err.Error())
			t.Logf("%s", outputBuffer.String())
			return
		}
		getLogger().Tracef("success: validated output format: '%s'", FORMAT_JSON)
	}

	// TODO: add general validation for CSV and Markdown formats
	if testInfo.OutputFormat == FORMAT_CSV {
		getLogger().Tracef("Testing format: %s", FORMAT_CSV)
	}

	if testInfo.OutputFormat == FORMAT_MARKDOWN {
		getLogger().Tracef("Testing format: %s", FORMAT_MARKDOWN)
	}

	return
}
