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

// Non-standard test files
const (
	TEST_DIFF_PANIC_BASE  = "test/diff/panic/nats1.json"
	TEST_DIFF_PANIC_DELTA = "test/diff/panic/nats2.json"
)

// Tests basic validation and expected errors
func innerDiffError(t *testing.T, baseFilename string, revisedFilename string, format string, expectedError error) (actualError error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Copy the test filename to the command line flags where the code looks for it
	utils.GlobalFlags.PersistentFlags.OutputFormat = format
	utils.GlobalFlags.PersistentFlags.InputFile = baseFilename
	utils.GlobalFlags.DiffFlags.RevisedFile = revisedFilename
	utils.GlobalFlags.DiffFlags.Colorize = true

	getLogger().Tracef("baseFilename: `%s`, revisedFilename=`%s`, actualError=`%T`",
		utils.GlobalFlags.PersistentFlags.InputFile,
		utils.GlobalFlags.DiffFlags.RevisedFile,
		actualError)

	actualError = Diff(utils.GlobalFlags.PersistentFlags, utils.GlobalFlags.DiffFlags)

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
	err := innerDiffError(t,
		TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE,
		TEST_CDX_1_4_MATURITY_EXAMPLE_1_DELTA,
		FORMAT_DEFAULT,
		nil)
	if err != nil {
		t.Error(err)
	}
}

func TestDiffCdx14MatureDeltaText(t *testing.T) {
	err := innerDiffError(t,
		TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE,
		TEST_CDX_1_4_MATURITY_EXAMPLE_1_DELTA,
		FORMAT_TEXT,
		nil)
	if err != nil {
		t.Error(err)
	}
}

func TestDiffCdx14MatureDeltaJson(t *testing.T) {
	err := innerDiffError(t,
		TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE,
		TEST_CDX_1_4_MATURITY_EXAMPLE_1_DELTA,
		FORMAT_JSON,
		nil)
	if err != nil {
		t.Error(err)
	}
}

func TestDiffJsonArrayOrderMove2ObjectsFormatJson(t *testing.T) {
	err := innerDiffError(t,
		TEST_ARRAY_ORDER_2_CHANGES_BASE,
		TEST_ARRAY_ORDER_2_CHANGES_DELTA,
		FORMAT_JSON,
		nil)
	if err != nil {
		t.Error(err)
	}
}

func TestDiffJsonArrayOrderMove1ObjectFormatJson(t *testing.T) {
	err := innerDiffError(t,
		TEST_ARRAY_ORDER_CHANGE_BASE,
		TEST_ARRAY_ORDER_CHANGE_DELTA,
		FORMAT_JSON,
		nil)
	if err != nil {
		t.Error(err)
	}
}

func TestDiffJsonArrayOrderMove1ObjectFormatText(t *testing.T) {
	err := innerDiffError(t,
		TEST_ARRAY_ORDER_CHANGE_BASE,
		TEST_ARRAY_ORDER_CHANGE_DELTA,
		FORMAT_TEXT,
		nil)
	if err != nil {
		t.Error(err)
	}
}

func TestDiffJsonArrayOrderMove1ObjectWithDeleteFormatText(t *testing.T) {
	err := innerDiffError(t,
		TEST_ARRAY_ORDER_CHANGE_WITH_DELETE_BASE,
		TEST_ARRAY_ORDER_CHANGE_WITH_DELETE_DELTA,
		FORMAT_TEXT,
		nil)
	if err != nil {
		t.Error(err)
	}
}

func TestDiffJsonArrayOrderMove1ObjectWithAddFormatText(t *testing.T) {
	err := innerDiffError(t,
		TEST_ARRAY_ORDER_CHANGE_WITH_ADD_BASE,
		TEST_ARRAY_ORDER_CHANGE_WITH_ADD_DELTA,
		FORMAT_TEXT,
		nil)
	if err != nil {
		t.Error(err)
	}
}

func TestDiffJsonArrayOrderMove1ObjectWithAddAndDeleteFormatText(t *testing.T) {
	err := innerDiffError(t,
		TEST_ARRAY_ORDER_CHANGE_WITH_ADD_AND_DELETE_BASE,
		TEST_ARRAY_ORDER_CHANGE_WITH_ADD_AND_DELETE_DELTA,
		FORMAT_TEXT,
		nil)
	if err != nil {
		t.Error(err)
	}
}

// func debugDeltas(deltas []diff.Delta, indent string) (err error) {
// 	for _, delta := range deltas {
// 		//fmt.Printf("delta: %v\n", delta)
// 		//sim := delta.Similarity()
// 		//fmt.Printf("sim: %v\n", sim)
//
// 		indent2 := indent + "...."
//
// 		switch pointer := delta.(type) {
// 		case *diff.Object:
// 			fmt.Printf("%s[Object](%v): PostPosition(): \"%v\", # Deltas: %v\n", indent, pointer.Similarity(), ColorizeBackgroundCyan(pointer.PostPosition().String()), len(pointer.Deltas))
// 			debugDeltas(pointer.Deltas, indent2)
// 			//deltaJson[d.Position.String()], err = f.formatObject(d.Deltas)
// 		case *diff.Array:
// 			fmt.Printf("%s[Array](%v): PostPosition(): \"%v\", # Deltas: %v\n", indent, pointer.Similarity(), ColorizeBackgroundCyan((pointer.PostPosition()).String()), len(pointer.Deltas))
// 			debugDeltas(pointer.Deltas, indent2)
// 			//deltaJson[d.Position.String()], err = f.formatArray(d.Deltas)
// 		case *diff.Added:
// 			sValue := fmt.Sprintf("%v", pointer.Value)
// 			fmt.Printf("%s[Added](%v): Value: \"%v\", PostPosition(): \"%v\"\n", indent, pointer.Similarity(), ColorizeBackgroundGreen(sValue), ColorizeBackgroundCyan((pointer.PostPosition()).String()))
// 			//deltaJson[d.PostPosition().String()] = []interface{}{d.Value}
// 		case *diff.Modified:
// 			fmt.Printf("%s[Modified](%v): PostPosition: \"%v\", OldValue: \"%v\", NewValue: \"%v\"\n", indent, pointer.Similarity(), ColorizeBackgroundCyan((pointer.PostPosition()).String()), ColorizeBackgroundRed((pointer.OldValue).(string)), ColorizeBackgroundGreen((pointer.NewValue).(string)))
// 			//deltaJson[d.PostPosition().String()] = []interface{}{d.OldValue, d.NewValue}
// 		case *diff.TextDiff:
// 			fmt.Printf("%s[TextDiff](%v): PostPosition: \"%v\", OldValue: \"%v\", NewValue: \"%v\"\n", indent, pointer.Similarity(), ColorizeBackgroundCyan((pointer.PostPosition()).String()), ColorizeBackgroundRed((pointer.OldValue).(string)), ColorizeBackgroundGreen((pointer.NewValue).(string)))
// 			//deltaJson[d.PostPosition().String()] = []interface{}{d.DiffString(), 0, DeltaTextDiff}
// 		case *diff.Deleted:
// 			sValue := fmt.Sprintf("%v", pointer.Value)
// 			fmt.Printf("%s[Deleted](%v): Value: \"%v\", PrePosition(): \"%v\"\n", indent, pointer.Similarity(), ColorizeBackgroundRed(sValue), ColorizeBackgroundCyan(pointer.PrePosition().String()))
// 			//deltaJson[d.PrePosition().String()] = []interface{}{d.Value, 0, DeltaDelete}
// 		case *diff.Moved:
// 			sValue := fmt.Sprintf("%v", pointer.Value)
// 			fmt.Printf("%s[Moved](%v): Value: \"%v\", PrePosition(): \"%v\", PostPosition(): \"%v\"\n", indent, pointer.Similarity(), ColorizeBackgroundYellow(sValue), ColorizeBackgroundCyan(pointer.PrePosition().String()), ColorizeBackgroundCyan(pointer.PostPosition().String()))
// 			fmt.Printf("%s[ERROR] 'Move' operation NOT supported for formatting objects\n", indent)
// 		default:
// 			fmt.Printf("%sUnknown Delta type detected: \"%T\"\n", indent, delta)
// 		}
// 	}
//
// 	return
// }

// See: https://www.lihaoyi.com/post/BuildyourownCommandLinewithANSIescapecodes.html

// Validate value (range)
// func Colorize(color string, text string) (colorizedText string) {
// 	return color + text + Reset
// }

// NOTE: In order to debug panic handling... here is a test
// Unfortunately, we cannot run it as part of function test as it "times out"
// TODO: Create smaller test files that cause panic in Diff command's underlying libs.
// func TestDiffJsonPanicNATs(t *testing.T) {
// 	err := innerDiffError(t,
// 		TEST_DIFF_PANIC_BASE,
// 		TEST_DIFF_PANIC_DELTA,
// 		FORMAT_TEXT,
// 		nil)
// 	if err != nil {
// 		t.Error(err)
// 	}
// }
