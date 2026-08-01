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
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/CycloneDX/sbom-utility/utils"
)

const (
	TEST_DIFF_ARRAY_ORDER_CHANGE_BASE  = "test/diff/json-array-order-change-base.json"
	TEST_DIFF_ARRAY_ORDER_CHANGE_DELTA = "test/diff/json-array-order-change-delta.json"

	TEST_DIFF_ARRAY_ORDER_CHANGE_WITH_DELETE_BASE  = "test/diff/json-array-order-change-with-delete-base.json"
	TEST_DIFF_ARRAY_ORDER_CHANGE_WITH_DELETE_DELTA = "test/diff/json-array-order-change-with-delete-delta.json"

	TEST_DIFF_ARRAY_ORDER_CHANGE_WITH_ADD_BASE  = "test/diff/json-array-order-change-with-add-base.json"
	TEST_DIFF_ARRAY_ORDER_CHANGE_WITH_ADD_DELTA = "test/diff/json-array-order-change-with-add-delta.json"

	TEST_DIFF_ARRAY_ORDER_CHANGE_WITH_ADD_AND_DELETE_BASE  = "test/diff/json-array-order-change-with-add-and-delete-base.json"
	TEST_DIFF_ARRAY_ORDER_CHANGE_WITH_ADD_AND_DELETE_DELTA = "test/diff/json-array-order-change-with-add-and-delete-delta.json"

	TEST_DIFF_ARRAY_ORDER_2_CHANGES_BASE  = "test/diff/json-array-order-2-changes-base.json"
	TEST_DIFF_ARRAY_ORDER_2_CHANGES_DELTA = "test/diff/json-array-order-2-changes-delta.json"

	// Nested array order change (licenses inside metadata)
	TEST_DIFF_CDX_1_4_NESTED_ARRAY_ORDER_CHANGE_BASE  = "test/diff/cdx-1-4-nested-array-order-change-base.json"
	TEST_DIFF_CDX_1_4_NESTED_ARRAY_ORDER_CHANGE_DELTA = "test/diff/cdx-1-4-nested-array-order-change-delta.json"

	// CycloneDX 1.7 license structure changes
	TEST_DIFF_CDX_1_7_LICENSE_BASE  = "test/diff/cdx-1-7-license-base.json"
	TEST_DIFF_CDX_1_7_LICENSE_DELTA = "test/diff/cdx-1-7-license-delta.json"

	// Edge cases
	TEST_DIFF_IDENTICAL_BASE      = "test/diff/json-identical-base.json"
	TEST_DIFF_SCALAR_CHANGE_BASE  = "test/diff/json-scalar-field-change-base.json"
	TEST_DIFF_SCALAR_CHANGE_DELTA = "test/diff/json-scalar-field-change-delta.json"
)

// Test CycloneDX BOM deltas
const (
	TEST_DIFF_CDX_1_4_MATURITY_EXAMPLE_1_DELTA = "test/diff/cdx-1-4-mature-example-1-delta.json"
	TEST_DIFF_CDX_1_4_MATURITY_EXAMPLE_2_DELTA = "test/diff/cdx-1-4-mature-example-1-delta2.json"

	TEST_DIFF_CDX_1_5_VULNERABILITY_BASE     = "test/diff/vulnerability/cdx-1-5-vulnerabilities-base.bom.json"
	TEST_DIFF_CDX_1_5_VULNERABILITY_ADD_1    = "test/diff/vulnerability/cdx-1-5-vulnerabilities-delta-add-1.bom.json"
	TEST_DIFF_CDX_1_5_VULNERABILITY_REMOVE_1 = "test/diff/vulnerability/cdx-1-5-vulnerabilities-delta-remove-1.bom.json"
)

// Non-standard test files
const (
	TEST_DIFF_PANIC_BASE  = "test/diff/panic/nats1.json"
	TEST_DIFF_PANIC_DELTA = "test/diff/panic/nats2.json"
)

type DiffTestInfo struct {
	CommonTestInfo
	RevisedFilename string
	Colorize        bool
}

func (ti *DiffTestInfo) String() string {
	buffer, _ := utils.EncodeAnyToDefaultIndentedJSONStr(ti)
	return buffer.String()
}

func NewDiffTestInfo(inputFile string, revisedFilename string) *DiffTestInfo {
	var ti = new(DiffTestInfo)
	ti.RevisedFilename = revisedFilename
	var pCommon = &ti.CommonTestInfo
	// Note: Diff default format is "unified" (standard ---/+++/@@ output via go-difflib).
	// To test the legacy go-jsondiff text or JSON formats, set ti.OutputFormat explicitly.
	pCommon.InitBasic(inputFile, FORMAT_UNIFIED, nil)
	return ti
}

// innerDiffTest runs Diff() with the given test parameters and checks the error result.
func innerDiffTest(t *testing.T, testInfo *DiffTestInfo) (actualError error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Copy test parameters to persistent and command-specific flags.
	// NOTE: diff format goes into DiffFlags.OutputFormat (not PersistentFlags.OutputFormat)
	// to match the Cobra flag binding in NewCommandDiff.
	utils.GlobalFlags.PersistentFlags.OutputFile = testInfo.OutputFile
	utils.GlobalFlags.PersistentFlags.InputFile = testInfo.InputFile
	utils.GlobalFlags.DiffFlags.OutputFormat = testInfo.OutputFormat
	utils.GlobalFlags.DiffFlags.RevisedFile = testInfo.RevisedFilename
	utils.GlobalFlags.DiffFlags.Colorize = testInfo.Colorize

	getLogger().Tracef("baseFilename: '%s', revisedFilename='%s', actualError=`%T`",
		utils.GlobalFlags.PersistentFlags.InputFile,
		utils.GlobalFlags.DiffFlags.RevisedFile,
		actualError)

	actualError = Diff(utils.GlobalFlags.PersistentFlags, utils.GlobalFlags.DiffFlags)

	// Always compare actual against expected error (even if it is `nil`)
	if !ErrorTypesMatch(actualError, testInfo.ResultExpectedError) {
		switch t := actualError.(type) {
		default:
			fmt.Printf("unhandled error type: '%v'\n", t)
			fmt.Printf(">> value: '%v'\n", t)
			getLogger().Error(actualError)
		}
		t.Errorf("expected error type: `%T`, actual type: `%T`", testInfo.ResultExpectedError, actualError)
	}

	return
}

// innerDiffTestFormatJSON runs a FORMAT_JSON diff and validates the output is well-formed
// JSON with the expected envelope fields (base, revised, modified, diff).
// If expectModified is true it also asserts modified==true and diff is non-empty.
// Returns the parsed envelope for callers that want to inspect further.
func innerDiffTestFormatJSON(t *testing.T, ti *DiffTestInfo, expectModified bool) map[string]interface{} {
	t.Helper()

	// Route output to a temp file so we can read it back
	if ti.OutputFile == "" {
		ti.OutputFile = ti.CreateTemporaryTestOutputFilename(ti.RevisedFilename)
	}

	err := innerDiffTest(t, ti)
	if err != nil {
		t.Fatalf("Diff() returned unexpected error: %v", err)
	}

	raw, readErr := os.ReadFile(ti.OutputFile)
	if readErr != nil {
		t.Fatalf("could not read output file %s: %v", ti.OutputFile, readErr)
	}

	// Trim trailing newline that Diff() appends then parse
	var envelope map[string]interface{}
	if jsonErr := json.Unmarshal([]byte(strings.TrimRight(string(raw), "\n")), &envelope); jsonErr != nil {
		t.Fatalf("FORMAT_JSON output is not valid JSON: %v\nraw output:\n%s", jsonErr, raw)
	}

	// Structural assertions common to all FORMAT_JSON output
	for _, key := range []string{"base", "revised", "modified", "diff"} {
		if _, ok := envelope[key]; !ok {
			t.Errorf("FORMAT_JSON envelope missing required key %q", key)
		}
	}

	modified, _ := envelope["modified"].(bool)
	diffText, _ := envelope["diff"].(string)

	if expectModified {
		if !modified {
			t.Errorf("expected modified=true but got false")
		}
		if diffText == "" {
			t.Errorf("expected non-empty diff text but got empty string")
		}
	} else {
		if modified {
			t.Errorf("expected modified=false but got true")
		}
		if diffText != "" {
			t.Errorf("expected empty diff text for identical files but got:\n%s", diffText)
		}
	}

	return envelope
}

// =====================================================
// FORMAT_TEXT tests
// =====================================================

func TestDiffJsonArrayOrderMove2ObjectsFormatText(t *testing.T) {
	ti := NewDiffTestInfo(TEST_DIFF_ARRAY_ORDER_2_CHANGES_BASE, TEST_DIFF_ARRAY_ORDER_2_CHANGES_DELTA)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_DIFF_ARRAY_ORDER_2_CHANGES_DELTA)
	if err := innerDiffTest(t, ti); err != nil {
		t.Error(err)
	}
}

func TestDiffJsonArrayOrderMove1ObjectFormatText(t *testing.T) {
	ti := NewDiffTestInfo(TEST_DIFF_ARRAY_ORDER_CHANGE_BASE, TEST_DIFF_ARRAY_ORDER_CHANGE_DELTA)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_DIFF_ARRAY_ORDER_CHANGE_DELTA)
	if err := innerDiffTest(t, ti); err != nil {
		t.Error(err)
	}
}

func TestDiffJsonArrayOrderMove1ObjectWithDeleteFormatText(t *testing.T) {
	ti := NewDiffTestInfo(TEST_DIFF_ARRAY_ORDER_CHANGE_WITH_DELETE_BASE, TEST_DIFF_ARRAY_ORDER_CHANGE_WITH_DELETE_DELTA)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_DIFF_ARRAY_ORDER_CHANGE_WITH_DELETE_DELTA)
	if err := innerDiffTest(t, ti); err != nil {
		t.Error(err)
	}
}

func TestDiffJsonArrayOrderMove1ObjectWithAddFormatText(t *testing.T) {
	ti := NewDiffTestInfo(TEST_DIFF_ARRAY_ORDER_CHANGE_WITH_ADD_BASE, TEST_DIFF_ARRAY_ORDER_CHANGE_WITH_ADD_DELTA)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_DIFF_ARRAY_ORDER_CHANGE_WITH_ADD_DELTA)
	if err := innerDiffTest(t, ti); err != nil {
		t.Error(err)
	}
}

func TestDiffJsonArrayOrderMove1ObjectWithAddAndDeleteFormatText(t *testing.T) {
	ti := NewDiffTestInfo(TEST_DIFF_ARRAY_ORDER_CHANGE_WITH_ADD_AND_DELETE_BASE, TEST_DIFF_ARRAY_ORDER_CHANGE_WITH_ADD_AND_DELETE_DELTA)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_DIFF_ARRAY_ORDER_CHANGE_WITH_ADD_AND_DELETE_DELTA)
	if err := innerDiffTest(t, ti); err != nil {
		t.Error(err)
	}
}

// Edge case: deeply nested array order change (licenses inside metadata object).
func TestDiffCdx14NestedArrayOrderChangeFormatText(t *testing.T) {
	ti := NewDiffTestInfo(TEST_DIFF_CDX_1_4_NESTED_ARRAY_ORDER_CHANGE_BASE, TEST_DIFF_CDX_1_4_NESTED_ARRAY_ORDER_CHANGE_DELTA)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_DIFF_CDX_1_4_NESTED_ARRAY_ORDER_CHANGE_DELTA)
	if err := innerDiffTest(t, ti); err != nil {
		t.Error(err)
	}
}

// CycloneDX 1.7: licenseChoice structure changes — licensing block, acknowledgement field,
// top-level expression item, and new component added.
func TestDiffCdx17LicenseChangesFormatText(t *testing.T) {
	ti := NewDiffTestInfo(TEST_DIFF_CDX_1_7_LICENSE_BASE, TEST_DIFF_CDX_1_7_LICENSE_DELTA)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_DIFF_CDX_1_7_LICENSE_DELTA)
	if err := innerDiffTest(t, ti); err != nil {
		t.Error(err)
	}
}

// CycloneDX 1.7: same fixtures as FORMAT_TEXT but via the JSON envelope — verifies
// that the large, nested licensing block round-trips correctly through the envelope.
func TestDiffCdx17LicenseChangesFormatJson(t *testing.T) {
	ti := NewDiffTestInfo(TEST_DIFF_CDX_1_7_LICENSE_BASE, TEST_DIFF_CDX_1_7_LICENSE_DELTA)
	ti.OutputFormat = FORMAT_JSON
	innerDiffTestFormatJSON(t, ti, true)
}

// Edge case: only top-level scalar fields differ (version, serialNumber, timestamp, component version).
func TestDiffScalarFieldChangesFormatText(t *testing.T) {
	ti := NewDiffTestInfo(TEST_DIFF_SCALAR_CHANGE_BASE, TEST_DIFF_SCALAR_CHANGE_DELTA)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_DIFF_SCALAR_CHANGE_DELTA)
	if err := innerDiffTest(t, ti); err != nil {
		t.Error(err)
	}
}

// Edge case: identical files — diff should produce no output and no error.
func TestDiffIdenticalFilesFormatText(t *testing.T) {
	ti := NewDiffTestInfo(TEST_DIFF_IDENTICAL_BASE, TEST_DIFF_IDENTICAL_BASE)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_DIFF_IDENTICAL_BASE)
	if err := innerDiffTest(t, ti); err != nil {
		t.Error(err)
	}
	// Output file should be empty (or absent) — no diff lines written for identical files.
	raw, _ := os.ReadFile(ti.OutputFile)
	if len(strings.TrimSpace(string(raw))) > 0 {
		t.Errorf("expected no output for identical files but got:\n%s", raw)
	}
}

// Edge case: colorize flag — just verify it produces output without error (ANSI codes are terminal-only).
func TestDiffColorizeFormatText(t *testing.T) {
	ti := NewDiffTestInfo(TEST_DIFF_ARRAY_ORDER_CHANGE_WITH_ADD_AND_DELETE_BASE, TEST_DIFF_ARRAY_ORDER_CHANGE_WITH_ADD_AND_DELETE_DELTA)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_DIFF_ARRAY_ORDER_CHANGE_WITH_ADD_AND_DELETE_DELTA)
	ti.Colorize = true
	if err := innerDiffTest(t, ti); err != nil {
		t.Error(err)
	}
}

// =====================================================
// CycloneDX BOM variant tests — FORMAT_TEXT
// =====================================================

func TestDiffCdx14MatureDelta1Text(t *testing.T) {
	ti := NewDiffTestInfo(TEST_CDX_1_4_MATURE_EXAMPLE_1_BASE, TEST_DIFF_CDX_1_4_MATURITY_EXAMPLE_1_DELTA)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_DIFF_CDX_1_4_MATURITY_EXAMPLE_1_DELTA)
	if err := innerDiffTest(t, ti); err != nil {
		t.Error(err)
	}
}

func TestDiffCdx14MatureDelta2Text(t *testing.T) {
	ti := NewDiffTestInfo(TEST_CDX_1_4_MATURE_EXAMPLE_1_BASE, TEST_DIFF_CDX_1_4_MATURITY_EXAMPLE_2_DELTA)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_DIFF_CDX_1_4_MATURITY_EXAMPLE_2_DELTA)
	if err := innerDiffTest(t, ti); err != nil {
		t.Error(err)
	}
}

func TestDiffJsonVulnerabilitiesAdd1FormatText(t *testing.T) {
	ti := NewDiffTestInfo(TEST_DIFF_CDX_1_5_VULNERABILITY_BASE, TEST_DIFF_CDX_1_5_VULNERABILITY_ADD_1)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_DIFF_CDX_1_5_VULNERABILITY_ADD_1)
	if err := innerDiffTest(t, ti); err != nil {
		t.Error(err)
	}
}

func TestDiffJsonVulnerabilitiesRemove1FormatText(t *testing.T) {
	ti := NewDiffTestInfo(TEST_DIFF_CDX_1_5_VULNERABILITY_BASE, TEST_DIFF_CDX_1_5_VULNERABILITY_REMOVE_1)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_DIFF_CDX_1_5_VULNERABILITY_REMOVE_1)
	if err := innerDiffTest(t, ti); err != nil {
		t.Error(err)
	}
}

// =====================================================
// FORMAT_UNIFIED tests
// =====================================================

func TestDiffCdx14MatureDelta1Unified(t *testing.T) {
	ti := NewDiffTestInfo(TEST_CDX_1_4_MATURE_EXAMPLE_1_BASE, TEST_DIFF_CDX_1_4_MATURITY_EXAMPLE_1_DELTA)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_DIFF_CDX_1_4_MATURITY_EXAMPLE_1_DELTA)
	ti.OutputFormat = FORMAT_UNIFIED
	if err := innerDiffTest(t, ti); err != nil {
		t.Error(err)
	}
}

// Edge case: identical files produce no output in unified format.
func TestDiffIdenticalFilesFormatUnified(t *testing.T) {
	ti := NewDiffTestInfo(TEST_DIFF_IDENTICAL_BASE, TEST_DIFF_IDENTICAL_BASE)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_DIFF_IDENTICAL_BASE)
	ti.OutputFormat = FORMAT_UNIFIED
	if err := innerDiffTest(t, ti); err != nil {
		t.Error(err)
	}
	raw, _ := os.ReadFile(ti.OutputFile)
	if len(strings.TrimSpace(string(raw))) > 0 {
		t.Errorf("expected no output for identical files in unified format but got:\n%s", raw)
	}
}

// =====================================================
// FORMAT_JSON tests
// =====================================================

// Array order change: envelope must be valid JSON, modified=true, diff non-empty.
func TestDiffJsonArrayOrderMove1ObjectFormatJson(t *testing.T) {
	ti := NewDiffTestInfo(TEST_DIFF_ARRAY_ORDER_CHANGE_BASE, TEST_DIFF_ARRAY_ORDER_CHANGE_DELTA)
	ti.OutputFormat = FORMAT_JSON
	innerDiffTestFormatJSON(t, ti, true)
}

// Add + delete + value change in array.
func TestDiffJsonArrayOrderWithAddAndDeleteFormatJson(t *testing.T) {
	ti := NewDiffTestInfo(TEST_DIFF_ARRAY_ORDER_CHANGE_WITH_ADD_AND_DELETE_BASE, TEST_DIFF_ARRAY_ORDER_CHANGE_WITH_ADD_AND_DELETE_DELTA)
	ti.OutputFormat = FORMAT_JSON
	innerDiffTestFormatJSON(t, ti, true)
}

// Scalar-only changes across multiple top-level fields.
func TestDiffScalarFieldChangesFormatJson(t *testing.T) {
	ti := NewDiffTestInfo(TEST_DIFF_SCALAR_CHANGE_BASE, TEST_DIFF_SCALAR_CHANGE_DELTA)
	ti.OutputFormat = FORMAT_JSON
	innerDiffTestFormatJSON(t, ti, true)
}

// Identical files: FORMAT_JSON still emits a valid envelope with modified=false and diff="".
// Unlike FORMAT_TEXT/UNIFIED (which write nothing), FORMAT_JSON always writes the envelope
// so that programmatic consumers get a well-formed document regardless of outcome.
func TestDiffIdenticalFilesFormatJson(t *testing.T) {
	ti := NewDiffTestInfo(TEST_DIFF_IDENTICAL_BASE, TEST_DIFF_IDENTICAL_BASE)
	ti.OutputFormat = FORMAT_JSON
	innerDiffTestFormatJSON(t, ti, false)
}

// CycloneDX mature example: envelope contains both filenames.
func TestDiffCdx14MatureDelta1FormatJson(t *testing.T) {
	ti := NewDiffTestInfo(TEST_CDX_1_4_MATURE_EXAMPLE_1_BASE, TEST_DIFF_CDX_1_4_MATURITY_EXAMPLE_1_DELTA)
	ti.OutputFormat = FORMAT_JSON
	envelope := innerDiffTestFormatJSON(t, ti, true)
	// Verify the filenames round-trip correctly in the envelope.
	if base, _ := envelope["base"].(string); base != TEST_CDX_1_4_MATURE_EXAMPLE_1_BASE {
		t.Errorf("envelope base: want %q, got %q", TEST_CDX_1_4_MATURE_EXAMPLE_1_BASE, base)
	}
	if revised, _ := envelope["revised"].(string); revised != TEST_DIFF_CDX_1_4_MATURITY_EXAMPLE_1_DELTA {
		t.Errorf("envelope revised: want %q, got %q", TEST_DIFF_CDX_1_4_MATURITY_EXAMPLE_1_DELTA, revised)
	}
}

// Vulnerability added: large insert block — confirms envelope handles multi-hundred-line diffs.
func TestDiffJsonVulnerabilitiesAdd1FormatJson(t *testing.T) {
	ti := NewDiffTestInfo(TEST_DIFF_CDX_1_5_VULNERABILITY_BASE, TEST_DIFF_CDX_1_5_VULNERABILITY_ADD_1)
	ti.OutputFormat = FORMAT_JSON
	innerDiffTestFormatJSON(t, ti, true)
}

// Vulnerability removed: large delete block.
func TestDiffJsonVulnerabilitiesRemove1FormatJson(t *testing.T) {
	ti := NewDiffTestInfo(TEST_DIFF_CDX_1_5_VULNERABILITY_BASE, TEST_DIFF_CDX_1_5_VULNERABILITY_REMOVE_1)
	ti.OutputFormat = FORMAT_JSON
	innerDiffTestFormatJSON(t, ti, true)
}

// Nested array inside a BOM object (metadata.licenses).
func TestDiffCdx14NestedArrayOrderChangeFormatJson(t *testing.T) {
	ti := NewDiffTestInfo(TEST_DIFF_CDX_1_4_NESTED_ARRAY_ORDER_CHANGE_BASE, TEST_DIFF_CDX_1_4_NESTED_ARRAY_ORDER_CHANGE_DELTA)
	ti.OutputFormat = FORMAT_JSON
	innerDiffTestFormatJSON(t, ti, true)
}

// =====================================================
// Large-file / formerly-panicking test
// =====================================================

// NOTE: The large NATS test files previously caused panics/timeouts in the old go-jsondiff
// library. They can now be run directly since go-difflib handles large inputs safely.
// Keeping commented out to avoid slow CI until smaller representative fixtures are created.
// TODO: Create smaller test files that reproduce the large-BOM scenario.
// func TestDiffJsonPanicNATs(t *testing.T) {
// 	ti := NewDiffTestInfo(TEST_DIFF_PANIC_BASE, TEST_DIFF_PANIC_DELTA)
// 	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_DIFF_PANIC_DELTA)
// 	if err := innerDiffTest(t, ti); err != nil {
// 		t.Error(err)
// 	}
// }
