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
	"testing"

	"github.com/CycloneDX/sbom-utility/utils"
)

const (
	TEST_CDX_1_4_MATURITY_EXAMPLE_1_DELTA = "test/diff/cdx-1-4-mature-example-1-delta.json"
	TEST_ARRAY_ORDER_CHANGE_BASE          = "test/diff/json-array-order-change-base.json"
	TEST_ARRAY_ORDER_CHANGE_DELTA         = "test/diff/json-array-order-change-delta.json"

	TEST_ARRAY_ORDER_CHANGE_WITH_DELETE_BASE  = "test/diff/json-array-order-change-with-delete-base.json"
	TEST_ARRAY_ORDER_CHANGE_WITH_DELETE_DELTA = "test/diff/json-array-order-change-with-delete-delta.json"

	TEST_ARRAY_ORDER_CHANGE_WITH_ADD_BASE  = "test/diff/json-array-order-change-with-add-base.json"
	TEST_ARRAY_ORDER_CHANGE_WITH_ADD_DELTA = "test/diff/json-array-order-change-with-add-delta.json"

	TEST_ARRAY_ORDER_CHANGE_WITH_ADD_AND_DELETE_BASE  = "test/diff/json-array-order-change-with-add-and-delete-base.json"
	TEST_ARRAY_ORDER_CHANGE_WITH_ADD_AND_DELETE_DELTA = "test/diff/json-array-order-change-with-add-and-delete-delta.json"

	TEST_ARRAY_ORDER_2_CHANGES_BASE  = "test/diff/json-array-order-2-changes-base.json"
	TEST_ARRAY_ORDER_2_CHANGES_DELTA = "test/diff/json-array-order-2-changes-delta.json"
)

// Tests basic validation and expected errors
func innerDiffError(t *testing.T, baseFilename string, revisedFilename string, format string, expectedError error) (actualError error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Copy the test filename to the command line flags where the code looks for it
	utils.GlobalFlags.OutputFormat = format
	utils.GlobalFlags.InputFile = baseFilename
	utils.GlobalFlags.DiffFlags.RevisedFile = revisedFilename
	utils.GlobalFlags.DiffFlags.Colorize = true

	actualError = Diff(utils.GlobalFlags)

	getLogger().Tracef("baseFilename: `%s`, revisedFilename=`%s`, actualError=`%T`",
		utils.GlobalFlags.InputFile,
		utils.GlobalFlags.DiffFlags.RevisedFile,
		actualError)

	// Always compare actual against expected error (even if it is `nil`)
	if !ErrorTypesMatch(actualError, expectedError) {
		switch t := actualError.(type) {
		default:
			fmt.Printf("unhandled error type: `%v`\n", t)
			fmt.Printf(">> value: `%v`\n", t)
			getLogger().Error(actualError)
		}
		t.Errorf("expected error type: `%T`, actual type: `%T`", expectedError, actualError)
	}

	return
}

func TestDiffCdx14MatureDeltaDefault(t *testing.T) {
	innerDiffError(t,
		TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE,
		TEST_CDX_1_4_MATURITY_EXAMPLE_1_DELTA,
		FORMAT_DEFAULT,
		nil)
}

func TestDiffCdx14MatureDeltaText(t *testing.T) {
	innerDiffError(t,
		TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE,
		TEST_CDX_1_4_MATURITY_EXAMPLE_1_DELTA,
		FORMAT_TEXT,
		nil)
}

func TestDiffCdx14MatureDeltaJson(t *testing.T) {
	innerDiffError(t,
		TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE,
		TEST_CDX_1_4_MATURITY_EXAMPLE_1_DELTA,
		FORMAT_JSON,
		nil)
}

func TestDiffJsonArrayOrderMove2ObjectsFormatJson(t *testing.T) {
	innerDiffError(t,
		TEST_ARRAY_ORDER_2_CHANGES_BASE,
		TEST_ARRAY_ORDER_2_CHANGES_DELTA,
		FORMAT_JSON,
		nil)
}

func TestDiffJsonArrayOrderMove1ObjectFormatJson(t *testing.T) {
	innerDiffError(t,
		TEST_ARRAY_ORDER_CHANGE_BASE,
		TEST_ARRAY_ORDER_CHANGE_DELTA,
		FORMAT_JSON,
		nil)
}

func TestDiffJsonArrayOrderMove1ObjectFormatText(t *testing.T) {
	innerDiffError(t,
		TEST_ARRAY_ORDER_CHANGE_BASE,
		TEST_ARRAY_ORDER_CHANGE_DELTA,
		FORMAT_TEXT,
		nil)
}

func TestDiffJsonArrayOrderMove1ObjectWithDeleteFormatText(t *testing.T) {
	innerDiffError(t,
		TEST_ARRAY_ORDER_CHANGE_WITH_DELETE_BASE,
		TEST_ARRAY_ORDER_CHANGE_WITH_DELETE_DELTA,
		FORMAT_TEXT,
		nil)
}

func TestDiffJsonArrayOrderMove1ObjectWithAddFormatText(t *testing.T) {
	innerDiffError(t,
		TEST_ARRAY_ORDER_CHANGE_WITH_ADD_BASE,
		TEST_ARRAY_ORDER_CHANGE_WITH_ADD_DELTA,
		FORMAT_TEXT,
		nil)
}

func TestDiffJsonArrayOrderMove1ObjectWithAddAndDeleteFormatText(t *testing.T) {
	innerDiffError(t,
		TEST_ARRAY_ORDER_CHANGE_WITH_ADD_AND_DELETE_BASE,
		TEST_ARRAY_ORDER_CHANGE_WITH_ADD_AND_DELETE_DELTA,
		FORMAT_TEXT,
		nil)
}