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
	"testing"

	"github.com/CycloneDX/sbom-utility/utils"
)

const (
	TEST_CDX_1_4_MATURITY_EXAMPLE_1_DELTA = "test/diff/cdx-1-4-mature-example-1-delta.json"
)

// Tests basic validation and expected errors
func innerDiffError(t *testing.T, baseFilename string, revisedFilename string, format string, expectedError error) (actualError error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Copy the test filename to the command line flags where the code looks for it
	utils.GlobalFlags.OutputFormat = format
	utils.GlobalFlags.InputFile = baseFilename
	utils.GlobalFlags.DiffFlags.DeltaFile = revisedFilename

	Diff(baseFilename, revisedFilename, format)

	//getLogger().Tracef("document: `%s`, isValid=`%t`, actualError=`%T`", document.GetFilename(), isValid, actualError)

	// Always compare actual against expected error (even if it is `nil`)
	// if !ErrorTypesMatch(actualError, expectedError) {
	// 	if len(schemaErrors) > 0 {
	// 		getLogger().Debugf("schemaErrors=`%s`", schemaErrors)
	// 	}

	// 	switch t := actualError.(type) {
	// 	default:
	// 		fmt.Printf("unhandled error type: `%v`\n", t)
	// 		fmt.Printf(">> value: `%v`\n", t)
	// 		getLogger().Error(actualError)
	// 	}
	// 	t.Errorf("expected error type: `%T`, actual type: `%T`", expectedError, actualError)
	// }

	// ANY error returned from Validate() SHOULD mark the input file as "invalid"
	// if actualError != nil && isValid {
	// 	t.Errorf("Validate() returned error (`%T`); however, input file still valid (%t)", actualError, isValid)
	// }

	// // ALWAYS make sure the if error was NOT expected that input file is marked "valid"
	// if expectedError == nil && !isValid {
	// 	t.Errorf("Input file invalid (%t); expected valid (no error)", isValid)
	// }

	return
}

func TestDiffEqual(t *testing.T) {
	utils.GlobalFlags.ValidateFlags.ForcedJsonSchemaFile = TEST_SCHEMA_CDX_1_3_CUSTOM
	innerDiffError(t,
		TEST_CDX_1_4_MATURITY_EXAMPLE_1_BASE,
		TEST_CDX_1_4_MATURITY_EXAMPLE_1_DELTA,
		FORMAT_JSON,
		nil)
}
