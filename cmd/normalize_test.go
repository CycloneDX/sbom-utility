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
	"bufio"
	"bytes"
	"io"
	"log"
	"os"
	"testing"

	"github.com/CycloneDX/sbom-utility/utils"
)

const (
	TEST_CDX_1_5_NORMALIZE_COMPONENTS               = "test/normalize/cdx-1-5-components.bom.json"
	TEST_CDX_1_5_NORMALIZE_SERVICES                 = "test/normalize/cdx-1-5-services.bom.json"
	TEST_CDX_1_5_NORMALIZE_LICENSES                 = "test/normalize/cdx-1-5-licenses.bom.json"
	TEST_CDX_1_5_NORMALIZE_DEPENDENCIES             = "test/normalize/cdx-1-5-dependencies.bom.json"
	TEST_CDX_1_5_NORMALIZE_EXTERNAL_REFERENCES      = "test/normalize/cdx-1-5-external-references.bom.json"
	TEST_CDX_1_5_NORMALIZE_VULNERABILITIES          = "test/normalize/cdx-1-5-vulnerabilities.bom.json"
	TEST_CDX_1_5_NORMALIZE_VULNERABILITIES_NATS_BOX = "test/normalize/cdx-1-5-vulnerabilities-container-nats-box.bom.json"
	TEST_CDX_1_4_NORMALIZE_COMPONENTS_XXL           = "test/normalize/cdx-1-4-components-xxl.bom.json"
	TEST_CDX_1_2_NORMALIZE_COMPONENTS_PROTON        = "test/normalize/cdx-1-2-components-protonmail.bom.json"
)

type NormalizeTestInfo struct {
	CommonTestInfo
	Keys      []string
	FromPaths []string
	Normalize bool
}

func (ti *NormalizeTestInfo) String() string {
	buffer, _ := utils.EncodeAnyToDefaultIndentedJSONStr(ti)
	return buffer.String()
}

func NewNormalizeTestInfo(inputFile string, resultExpectedError error) *NormalizeTestInfo {
	var ti = new(NormalizeTestInfo)
	// Set to test normalization by default
	ti.Normalize = true
	var pCommon = &ti.CommonTestInfo
	pCommon.InitBasic(inputFile, FORMAT_JSON, resultExpectedError)
	return ti
}

func innerTestNormalize(t *testing.T, testInfo *NormalizeTestInfo) (outputBuffer bytes.Buffer, basicTestInfo string, err error) {
	getLogger().Tracef("TestInfo: %s", testInfo)

	// Mock stdin if requested
	if testInfo.MockStdin == true {
		utils.GlobalFlags.PersistentFlags.InputFile = INPUT_TYPE_STDIN
		file, err := os.Open(testInfo.InputFile) // For read access.
		if err != nil {
			log.Fatal(err)
		}

		// convert byte slice to io.Reader
		savedStdIn := os.Stdin
		// !!!Important restore stdin
		defer func() { os.Stdin = savedStdIn }()
		os.Stdin = file
	}

	// invoke resource list command with a byte buffer
	outputBuffer, err = innerBufferedTestNormalize(testInfo)
	// if the command resulted in a failure
	if err != nil {
		// if tests asks us to report a FAIL to the test framework
		cti := &testInfo.CommonTestInfo
		if cti.Autofail {
			encodedTestInfo, _ := utils.EncodeAnyToDefaultIndentedJSONStr(testInfo)
			t.Errorf("%s: failed: %v\n%s", cti.InputFile, err, encodedTestInfo.String())
		}
		return
	}

	return
}

func innerBufferedTestNormalize(testInfo *NormalizeTestInfo) (outputBuffer bytes.Buffer, err error) {

	// The command looks for the input & output filename in global flags struct
	utils.GlobalFlags.PersistentFlags.InputFile = testInfo.InputFile
	utils.GlobalFlags.PersistentFlags.OutputFile = testInfo.OutputFile
	utils.GlobalFlags.PersistentFlags.OutputFormat = testInfo.OutputFormat
	utils.GlobalFlags.PersistentFlags.OutputIndent = testInfo.OutputIndent
	utils.GlobalFlags.PersistentFlags.OutputNormalize = testInfo.Normalize // NOTE: default=true
	utils.GlobalFlags.TrimFlags.Keys = testInfo.Keys
	utils.GlobalFlags.TrimFlags.FromPaths = testInfo.FromPaths
	var outputWriter io.Writer
	var outputFile *os.File

	// TODO: centralize this logic to a function all Commands can use...
	// Note: Any "Mocking" of os.Stdin/os.Stdout should be done in functions that call this one
	if testInfo.OutputFile == "" {
		// Declare an output outputBuffer/outputWriter to use used during tests
		bufferedWriter := bufio.NewWriter(&outputBuffer)
		outputWriter = bufferedWriter
		// MUST ensure all data is written to buffer before further testing
		defer bufferedWriter.Flush()
	} else {
		outputFile, outputWriter, err = createOutputFile(testInfo.OutputFile)
		getLogger().Tracef("outputFile: `%v`; writer: `%v`", testInfo.OutputFile, outputWriter)

		// use function closure to assure consistent error output based upon error type
		defer func() {
			// always close the output file (even if error, as long as file handle returned)
			if outputFile != nil {
				outputFile.Close()
				getLogger().Infof("Closed output file: `%s`", testInfo.OutputFile)
			}
		}()

		if err != nil {
			return
		}
	}

	// NOTE: We use the Trim() command to test the Normalize() functionality for now
	// TODO: Ideally, we want a top-level command "Normalize()" with other flag options
	// BUT, also want to allow normalization any time ANY command writes BOM as output
	// so the Trim() command is a great first impl. towards those goals.
	err = Trim(outputWriter, utils.GlobalFlags.PersistentFlags, utils.GlobalFlags.TrimFlags)
	return
}

func TestNormalizeCdx15Components(t *testing.T) {
	ti := NewNormalizeTestInfo(TEST_CDX_1_5_NORMALIZE_COMPONENTS, nil)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_CDX_1_5_NORMALIZE_COMPONENTS)
	// ti.FromPaths = []string{"components"}
	innerTestNormalize(t, ti)
	document, err := LoadBOMOutputFile(ti.CommonTestInfo)
	if err != nil {
		t.Error(err)
	}

	// Before looking for license data, fully unmarshal the SBOM into named structures
	if err = document.UnmarshalCycloneDXBOM(); err != nil {
		return
	}
}

func TestNormalizeCdx15Services(t *testing.T) {
	ti := NewNormalizeTestInfo(TEST_CDX_1_5_NORMALIZE_SERVICES, nil)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_CDX_1_5_NORMALIZE_SERVICES)
	innerTestNormalize(t, ti)
}

func TestNormalizeCdx15Dependencies(t *testing.T) {
	ti := NewNormalizeTestInfo(TEST_CDX_1_5_NORMALIZE_DEPENDENCIES, nil)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_CDX_1_5_NORMALIZE_DEPENDENCIES)
	innerTestNormalize(t, ti)
}

func TestNormalizeCdx15ExternalReferences(t *testing.T) {
	ti := NewNormalizeTestInfo(TEST_CDX_1_5_NORMALIZE_EXTERNAL_REFERENCES, nil)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_CDX_1_5_NORMALIZE_EXTERNAL_REFERENCES)
	innerTestNormalize(t, ti)
}

func TestNormalizeCdx15Vulnerabilities(t *testing.T) {
	ti := NewNormalizeTestInfo(TEST_CDX_1_5_NORMALIZE_VULNERABILITIES, nil)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_CDX_1_5_NORMALIZE_VULNERABILITIES)
	innerTestNormalize(t, ti)
}

func TestNormalizeCdx15Licenses(t *testing.T) {
	ti := NewNormalizeTestInfo(TEST_CDX_1_5_NORMALIZE_LICENSES, nil)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_CDX_1_5_NORMALIZE_LICENSES)
	innerTestNormalize(t, ti)
}

// XXL Sort tests
func TestNormalizeCdx12ComponentsProtonMail(t *testing.T) {
	ti := NewNormalizeTestInfo(TEST_CDX_1_2_NORMALIZE_COMPONENTS_PROTON, nil)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_CDX_1_2_NORMALIZE_COMPONENTS_PROTON)
	innerTestNormalize(t, ti)
}

func TestNormalizeCdx14ComponentsXXL(t *testing.T) {
	ti := NewNormalizeTestInfo(TEST_CDX_1_4_NORMALIZE_COMPONENTS_XXL, nil)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_CDX_1_4_NORMALIZE_COMPONENTS_XXL)
	innerTestNormalize(t, ti)
}

func TestNormalizeCdx15VulnerabilitiesNatsBox(t *testing.T) {
	ti := NewNormalizeTestInfo(TEST_CDX_1_5_NORMALIZE_VULNERABILITIES_NATS_BOX, nil)
	ti.OutputFile = ti.CreateTemporaryTestOutputFilename(TEST_CDX_1_5_NORMALIZE_VULNERABILITIES_NATS_BOX)
	innerTestNormalize(t, ti)
}

// EXPERIMENTAL:
// TODO: see if we can create a function to loop through all nested structures and
// report one which ones do NOT have support for the Normalizer interface.
// This could be used to verify always have code to normalize any structure as
// new ones are added release-to-release
// func TestNormalizeReflect(t *testing.T) {
// 	document, err := LoadBOMFile(TEST_CDX_1_5_NORMALIZE_COMPONENTS)
// 	if err != nil {
// 		return
// 	}

// 	if err = document.UnmarshalCycloneDXBOM(); err != nil {
// 		return
// 	}

// 	// Test reflect.New using an existing instance
// 	//ptrBom := reflect.New(reflect.TypeOf(*document))
// 	//fmt.Printf("New *schema.BOM: %+v\n", ptrBom)

// 	// Test reflect.New using an existing (empty) instance
// 	//bom2Type := reflect.TypeOf(schema.BOM{})
// 	//ptrBom2 := reflect.New(bom2Type)
// 	//fmt.Printf("New *schema.BOM: %+v\n", ptrBom2)

// 	// Assure we can
// 	ptrCdxBom := document.GetCdxBom()
// 	//fmt.Printf("*schema.CDXBom: %+v\n", ptrCdxBom)

// 	ListFields(ptrCdxBom)
// }

// func ListFields(itfc interface{}) {
// 	// NOTE: we can immediately use ValueOf() to dereference the interface{}
// 	// NOTE: Elem() will panic if reflect.ValueOf(itfc).Kind() != reflect.Ptr || reflect.Interface
// 	rvoItfc := reflect.ValueOf(itfc)

// 	// Deref. if needed to get the ACTUAL type we want to list fields for
// 	if rvoItfc.Kind() == reflect.Pointer || rvoItfc.Kind() == reflect.Interface {
// 		rvoItfc = reflect.ValueOf(itfc).Elem()
// 	}

// 	// Immediately grab the Type of the dereferenced interface{}
// 	rvoType := rvoItfc.Type()
// 	fmt.Printf("Interface: Type: `%v`, Kind: `%v`\n", rvoType.String(), rvoType.Kind())

// 	if rvoType.Kind() == reflect.Struct {
// 		// Iterate over all fields of the Struct type (if any)
// 		for i := 0; i < rvoType.NumField(); i++ {
// 			field := rvoType.Field(i)

// 			// Indirect returns the fieldValue that v points to.
// 			// - If <input> is a nil pointer, Indirect returns a zero Value.
// 			// - If <input> is not a pointer, Indirect returns <input> (no dereference using Elem() method).
// 			fieldName := field.Name
// 			fieldValue := reflect.Indirect(rvoItfc).FieldByName(fieldName)
// 			fvKind := fieldValue.Kind()
// 			fvValueOf := reflect.ValueOf(fieldValue)
// 			// TODO: explore `field.PkgPath`
// 			fmt.Printf(">> Field(%v): `%s`, Kind: `%s`, Tags: `%s`, Value: `%v`\n", i, fieldName, fvKind.String(), field.Tag, fvValueOf)

// 			// TODO: explore use of isItfc := field.CanInterface()
// 			if fvKind == reflect.Ptr || fvKind == reflect.Interface {
// 				if !fieldValue.IsNil() {
// 					// NOTE:  temp.Elem() could be reflect.Struct, reflect.Map, reflect.Slice, etc.
// 					ListFields(fieldValue.Interface())
// 				}
// 			}
// 		}
// 	} else {
// 		fmt.Printf("!!! Unhandled Kind(): `%v`", rvoType.Kind())
// 	}
// }
