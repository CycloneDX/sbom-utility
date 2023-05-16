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
	"bufio"
	"bytes"
	"testing"
)

// -------------------------------------------
// resource list test helper functions
// -------------------------------------------
func innerBufferedTestSchemaList(t *testing.T, pTestInfo *CommonTestInfo, whereFilters []WhereFilter) (outputBuffer bytes.Buffer, err error) {
	// Declare an output outputBuffer/outputWriter to use used during tests
	var outputWriter = bufio.NewWriter(&outputBuffer)
	// ensure all data is written to buffer before further validation
	defer outputWriter.Flush()
	err = ListSchemas(outputWriter, whereFilters)
	return
}

func innerTestSchemaList(t *testing.T, pTestInfo *CommonTestInfo) (outputBuffer bytes.Buffer, basicTestInfo string, err error) {
	getLogger().Tracef("TestInfo: %s", pTestInfo)

	// Parse out --where filters and exit out if error detected
	whereFilters, err := prepareWhereFilters(t, pTestInfo)
	if err != nil {
		return
	}

	// invoke resource list command with a byte buffer
	outputBuffer, err = innerBufferedTestSchemaList(t, pTestInfo, whereFilters)

	// Run all common tests against "result" values in the CommonTestInfo struct
	err = innerRunReportResultTests(t, pTestInfo, outputBuffer, err)

	return
}

// ----------------------------------------
// Command tests
// ----------------------------------------

func TestSchemaListText(t *testing.T) {
	ti := NewCommonTestInfo()
	ti.ListFormat = FORMAT_TEXT
	ti.ResultExpectedLineCount = TI_DEFAULT_LINE_COUNT

	// verify correct error is returned
	innerTestSchemaList(t, ti)
}
