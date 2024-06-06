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
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/CycloneDX/sbom-utility/utils"
	"github.com/spf13/cobra"
)

// flags (do not translate)
const (
	FLAG_PATCH_FILE = "patch-file"
)

// flag help (translate)
const (
	MSG_PATCH_FILE = "patch filename"
)

const (
	ERR_PATCH_REPLACE_PATH_EXISTS = "invalid path. Path does not exist to replace value"
)

// The "-" character is used to index the end of the array (see [RFC6901])
const (
	RFC6901_END_OF_ARRAY = "-"
)

var PATCH_OUTPUT_SUPPORTED_FORMATS = MSG_SUPPORTED_OUTPUT_FORMATS_HELP +
	strings.Join([]string{FORMAT_JSON}, ", ")

// Command PreRunE helper function to test for patch file
func preRunTestForPatchFile(args []string) error {
	getLogger().Enter()
	defer getLogger().Exit()
	getLogger().Tracef("args: %v", args)

	// Make sure the input filename is present and exists
	patchFilename := utils.GlobalFlags.PatchFlags.PatchFile
	if patchFilename == "" {
		return getLogger().Errorf("Missing required argument(s): %s", FLAG_PATCH_FILE)
	} else if _, err := os.Stat(patchFilename); err != nil {
		return getLogger().Errorf("File not found: `%s`", patchFilename)
	}
	return nil
}

func NewCommandPatch() *cobra.Command {
	var command = new(cobra.Command)
	command.Use = CMD_USAGE_PATCH
	command.Short = "Apply an IETF RFC 6902 patch file to a JSON BOM file"
	command.Long = "Apply an IETF RFC 6902 patch file to a JSON BOM file"
	command.RunE = patchCmdImpl
	command.PreRunE = func(cmd *cobra.Command, args []string) (err error) {
		// Test for required flags (parameters)
		err = preRunTestForInputFile(args)
		if err != nil {
			return
		}
		err = preRunTestForPatchFile(args)
		if err != nil {
			return
		}
		return
	}
	initCommandPatchFlags(command)

	return command
}

func initCommandPatchFlags(command *cobra.Command) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// NOTE: Cobra commands that use the same variable with different "default" values (i.e., "txt", "json")
	// will overwrite each other during initialization... we must use a unique variable for each command/conflict
	command.PersistentFlags().StringVar(&utils.GlobalFlags.PatchFlags.OutputFormat, FLAG_OUTPUT_FORMAT, FORMAT_JSON,
		MSG_FLAG_OUTPUT_FORMAT+PATCH_OUTPUT_SUPPORTED_FORMATS)
	command.Flags().StringVarP(&utils.GlobalFlags.PatchFlags.PatchFile, FLAG_PATCH_FILE, "", "", MSG_PATCH_FILE)
	command.PersistentFlags().BoolVar(&utils.GlobalFlags.PersistentFlags.OutputNormalize, FLAG_OUTPUT_NORMALIZE, false, MSG_FLAG_OUTPUT_NORMALIZE)
	err = command.MarkFlagRequired(FLAG_PATCH_FILE)
	if err != nil {
		err = getLogger().Errorf("unable to mark flag `%s` as required: %s", FLAG_PATCH_FILE, err)
	}
	return
}

func patchCmdImpl(cmd *cobra.Command, args []string) (err error) {
	getLogger().Enter(args)
	defer getLogger().Exit()

	// Create output writer
	outputFilename := utils.GlobalFlags.PersistentFlags.OutputFile
	outputFile, writer, err := createOutputFile(outputFilename)
	getLogger().Tracef("outputFile: `%v`; writer: `%v`", outputFilename, writer)

	// Overcome Cobra limitation in variable reuse between diff. commands
	// That is, as soon as ANY command sets a default value, it cannot be changed
	utils.GlobalFlags.PersistentFlags.OutputFormat = utils.GlobalFlags.PatchFlags.OutputFormat

	// use function closure to assure consistent error output based upon error type
	defer func() {
		// always close the output file
		if outputFile != nil {
			outputFile.Close()
			getLogger().Infof("Closed output file: `%s`", outputFilename)
		}
	}()

	if err == nil {
		err = Patch(writer, utils.GlobalFlags.PersistentFlags, utils.GlobalFlags.PatchFlags)
	}

	return
}

// Assure all errors are logged
func processPatchResults(err error) {
	if err != nil {
		// No special processing at this time
		getLogger().Error(err)
	}
}

// NOTE: resourceType has already been validated
func Patch(writer io.Writer, persistentFlags utils.PersistentCommandFlags, patchFlags utils.PatchCommandFlags) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// use function closure to assure consistent error output based upon error type
	defer func() {
		if err != nil {
			processPatchResults(err)
		}
	}()

	// Note: returns error if either file load or unmarshal to JSON map fails
	var document *schema.BOM
	if document, err = LoadInputBOMFileAndDetectSchema(); err != nil {
		return
	}

	// At this time, fail SPDX format SBOMs as "unsupported" (for "any" format)
	if !document.FormatInfo.IsCycloneDx() {
		err = schema.NewUnsupportedFormatForCommandError(
			document.FormatInfo.CanonicalName,
			document.GetFilename(),
			CMD_LICENSE, FORMAT_ANY)
		return
	}

	// validate parameters
	patchFile := utils.GlobalFlags.PatchFlags.PatchFile
	if patchFile == "" {
		err = fmt.Errorf("invalid patch file: %s", patchFile)
		return
	}

	patchDocument := NewIETFRFC6902PatchDocument(patchFile)
	if err = patchDocument.UnmarshalRecords(); err != nil {
		return
	}

	if err = processPatchRecords(document, patchDocument); err != nil {
		return
	}

	// After patch records are applied to the JSON map;
	// update the corresponding "CdxBom" using the "unmarshal" wrapper.
	// NOTE: If any JSON keys that are NOT part of the CycloneDX spec.
	// have been added via a patch "add" operation, they will be removed
	// during the unmarshal process.
	if document.CdxBom, err = schema.UnMarshalDocument(document.JsonMap); err != nil {
		return
	}

	// Sort slices of BOM if "sort" flag set to true
	if persistentFlags.OutputNormalize {
		// Sort the slices of structures
		if document.GetCdxBom() != nil {
			bom := document.GetCdxBom()
			if schema.NormalizeSupported(bom) {
				document.GetCdxBom().Normalize()
			}
		}
	}

	// Output the "patched" version of the Input BOM
	format := persistentFlags.OutputFormat
	getLogger().Infof("Writing patched BOM (`%s` format)...", format)
	switch format {
	case FORMAT_JSON:
		err = document.WriteAsEncodedJSONInt(writer, utils.GlobalFlags.PersistentFlags.GetOutputIndentInt())
	default:
		// Default to Text output for anything else (set as flag default)
		getLogger().Warningf("Patch not supported for `%s` format; defaulting to `%s` format...",
			format, FORMAT_JSON)
		err = document.WriteAsEncodedJSONInt(writer, utils.GlobalFlags.PersistentFlags.GetOutputIndentInt())
	}

	return
}

func innerPatch(document *schema.BOM) (err error) {
	// validate parameters
	patchFile := utils.GlobalFlags.PatchFlags.PatchFile
	if patchFile == "" {
		err = fmt.Errorf("invalid patch file: %s", patchFile)
		return
	}

	patchDocument := NewIETFRFC6902PatchDocument(patchFile)
	if err = patchDocument.UnmarshalRecords(); err != nil {
		return
	}

	if err = processPatchRecords(document, patchDocument); err != nil {
		return
	}
	return
}

func processPatchRecords(bomDocument *schema.BOM, patchDocument *IETF6902Document) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	for _, record := range patchDocument.Records {
		getLogger().Tracef("patch: %s\n", record.String())

		// operation objects MUST have exactly one "path" member.
		// That member's value is a string containing a JSON-Pointer value
		// [RFC6901] that references a location within the target document
		// (the "target location") where the operation is performed.
		// NOTE: RFC 6901 indicates an "empty" path means a pointer to the
		// entire document which effectively mean patch the entire document
		// which does not make sense...
		if record.Path == "" {
			// TODO: make this a declared error type that can be tested
			return fmt.Errorf("invalid IETF RFC 6902 patch operation. \"path\" is empty")
		}

		var keys []string
		jsonMap := bomDocument.GetJSONMap()

		if jsonMap == nil {
			return fmt.Errorf("invalid json document (nil)")
		}

		if keys, err = parseMapKeysFromPath(record.Path); err != nil {
			return
		}

		lengthKeys := len(keys)
		if lengthKeys == 0 {
			return fmt.Errorf("invalid document path (nil)")
		}

		switch record.Operation {
		case IETF_RFC6902_OP_ADD:
			if record.Value == nil {
				// TODO: make this a declared error type that can be tested
				return fmt.Errorf("invalid IETF RFC 6902 patch operation. \"value\" missing")
			}
			if err = addOrReplaceValue(jsonMap, keys, record.Value, false); err != nil {
				return
			}
		case IETF_RFC6902_OP_REPLACE:
			// NOTE: Replace logic is identical to "add" operation except that
			// the target "key" MUST exist...
			if record.Value == nil {
				// TODO: make this a declared error type that can be tested
				return fmt.Errorf("invalid IETF RFC 6902 patch operation. \"value\" missing")
			}
			if err = addOrReplaceValue(jsonMap, keys, record.Value, true); err != nil {
				return
			}
		case IETF_RFC6902_OP_REMOVE:
			if err = removeValue(jsonMap, keys, record.Value); err != nil {
				return
			}
		case IETF_RFC6902_OP_TEST:
			// NOTE: "test" operations do not change the input JSON.  They either
			// will report (via INFO messages) "success" of a data match or return
			// a (typed) error that indicates a non-match and terminates all
			// patch record processing.
			var equal bool
			var actualValue interface{}
			if equal, actualValue, err = testValue(jsonMap, keys, record.Value); err != nil {
				return
			}
			// The RFC6902 spec. requires returning an "error" if the test values does not match
			// the value found in the document...
			if !equal {
				err = NewIETFRFC6902TestError(record.String(), actualValue)
				return
			}
			successMessage := fmt.Sprintf("%s. test record: %s, actual value: %v\n", MSG_IETF_RFC6902_OPERATION_SUCCESS, record.String(), actualValue)
			getLogger().Info(successMessage)
		case IETF_RFC6902_OP_MOVE:
			fallthrough
		case IETF_RFC6902_OP_COPY:
			return NewUnsupportedError(record.Operation, "IETF RFC 6902 operation not currently supported")
		default:
			return NewUnsupportedError(record.Operation, "invalid IETF RFC 6902 operation")
		}
	}

	return
}

func parseMapKeysFromPath(path string) (keys []string, err error) {
	// first char SHOULD be a forward slash, if not error
	if path == "" || path[0] != '/' {
		err = fmt.Errorf("invalid path. Path must begin with forward slash")
		return
	}
	// parse out paths ignoring leading forward slash character
	keys = strings.Split(path[1:], "/")
	return
}

func parseArrayIndex(indexPath string) (arrayIndex int, err error) {
	// Check for RFC6901 end-of-array character
	if indexPath == RFC6901_END_OF_ARRAY {
		arrayIndex = -1
		return
	}
	// otherwise, the path should be convertible to an integer
	arrayIndex, err = strconv.Atoi(indexPath)
	return
}

// func parseArrayIndexFromPath(path string) (arrayIndex int, err error) {
// 	var keys []string
// 	keys, err = parseMapKeysFromPath(path)
// 	if err != nil {
// 		return
// 	}

// 	lengthKeys := len(keys)
// 	if lengthKeys <= 0 {
// 		err = fmt.Errorf("invalid path. Path: %s", path)
// 		return
// 	}
// 	return parseArrayIndex(keys[lengthKeys-1])
// }

// The "test" operation tests that a value at the target location is
// equal to a specified value.
//   - The operation object MUST contain a "value" member that conveys the
//     value to be compared to the target location's value.
//   - The target location MUST be equal to the "value" value for the
//     operation to be considered successful.
//
// Here, "equal" means that the value at the target location and the
// value conveyed by "value" are of the same JSON type, and that they
// are considered equal by the following rules for that type:
//
//   - strings: are considered equal if they contain the same number of
//     Unicode characters and their code points are byte-by-byte equal.
//
//   - numbers: are considered equal if their values are numerically
//     equal.
//
//   - arrays: are considered equal if they contain the same number of
//
//     values, and if each value can be considered equal to the value at
//     the corresponding position in the other array, using this list of
//     type-specific rules.
//
//   - objects: are considered equal if they contain the same number of
//     members, and if each member can be considered equal to a member in
//     the other object, by comparing their keys (as strings) and their
//     values (using this list of type-specific rules).
//
//   - literals (false, true, and null): are considered equal if they are
//     the same.
func testValue(parentMap map[string]interface{}, keys []string, value interface{}) (equal bool, actualValue interface{}, err error) {
	var nextNodeKey string   // := keys[0]
	var nextNode interface{} // := parentMap[nextNodeKey]
	lengthKeys := len(keys)

	switch lengthKeys {
	case 0:
		err = fmt.Errorf("invalid map key (nil)")
		return
	case 1: // special case of adding new key/value to document root
		nextNode = parentMap
	default: // adding keys/values along document path
		nextNodeKey = keys[0]
		nextNode = parentMap[nextNodeKey]
	}

	switch typedNode := nextNode.(type) {
	case map[string]interface{}:
		// If the resulting value is indeed another map type, we expect for a Json Map
		// we preserve that pointer for the next iteration
		if lengthKeys > 2 {
			// if the next node is a map AND there is more than one path following it,
			// it would mean we have not yet reached the final map or slice to add
			// a value to
			equal, actualValue, err = testValue(typedNode, keys[1:], value)
			return
		} else {
			// if the next node is a map AND only 1 path remains after it,
			// it would mean that last path is a new key to be added
			// to the next node's map with the provided value
			actualValue = typedNode[keys[0]]
			equal, err = isValueEqual(value, actualValue)
			if !equal || err != nil {
				return
			}
		}
	case []interface{}:
		if lengthKeys != 2 {
			// TODO: create a formal error type for this
			err = fmt.Errorf("invalid path. IETF RFC 6901 does not permit paths after array indices")
			return
		}
		var arrayIndex int
		indexPath := keys[1]
		arrayIndex, err = parseArrayIndex(indexPath)
		if err != nil {
			return
		}
		actualValue = typedNode[arrayIndex]
		equal, err = isValueEqual(value, actualValue)
		if !equal || err != nil {
			return
		}
	default:
		// Optimistically, assign the value and emit a warning of the unexpected JSON type
		getLogger().Warningf("Invalid document node type: (%T)", nextNode)
		return
	}
	return
}

func isValueEqual(value1 interface{}, value2 interface{}) (equal bool, err error) {
	// We want to assure type match before actual value comparison
	switch value1.(type) {
	case bool:
		if _, ok := value2.(bool); !ok {
			err = fmt.Errorf("invalid type comparison. value1: %v (%T), value2: %v (%T)", value1, value1, value2, value2)
			return
		}
		equal = (value1 == value2)
	case float64:
		if _, ok := value2.(float64); !ok {
			err = fmt.Errorf("invalid type comparison. value1: %v (%T), value2: %v (%T)", value1, value1, value2, value2)
			return
		}
		equal = (value1 == value2)
	case string:
		if _, ok := value2.(string); !ok {
			err = fmt.Errorf("invalid type comparison. value1: %v (%T), value2: %v (%T)", value1, value1, value2, value2)
			return
		}
		equal = (value1 == value2)
		return
	case []interface{}:
		if _, ok := value2.([]interface{}); !ok {
			err = fmt.Errorf("invalid type comparison. value1: %v (%T), value2: %v (%T)", value1, value1, value2, value2)
			return
		}
		equal = reflect.DeepEqual(value1, value2)
		return
	case map[string]interface{}:
		if _, ok := value2.(map[string]interface{}); !ok {
			err = fmt.Errorf("invalid type comparison. value1: %v (%T), value2: %v (%T)", value1, value1, value2, value2)
			return
		}
		equal = reflect.DeepEqual(value1, value2)
		return
	default:
		err = fmt.Errorf("invalid type comparison. Unexpected type for value: %v (%T)", value1, value1)
		return
	}

	return
}

// The "remove" operation removes the value at the target location.
//
// - The target location MUST exist for the operation to be successful.
// - If removing an element from an array, any elements above the
// specified index are shifted one position to the left.
func removeValue(parentMap map[string]interface{}, keys []string, value interface{}) (err error) {
	var nextNodeKey string   // := keys[0]
	var nextNode interface{} // := parentMap[nextNodeKey]
	lengthKeys := len(keys)

	switch lengthKeys {
	case 0:
		return fmt.Errorf("invalid map key (nil)")
	case 1: // special case of adding new key/value to document root
		nextNode = parentMap
	default: // adding keys/values along document path
		nextNodeKey = keys[0]
		nextNode = parentMap[nextNodeKey]
	}

	switch typedNode := nextNode.(type) {
	case map[string]interface{}:
		// If the resulting value is indeed another map type, we expect for a Json Map
		// we preserve that pointer for the next iteration
		if lengthKeys > 2 {
			// if the next node is a map AND there is more than one path following it,
			// it would mean we have not yet reached the final map or slice to add
			// a value to
			err = removeValue(typedNode, keys[1:], value)
			return
		} else {
			// if the next node is a map AND only 1 path remains after it,
			// it would mean that last path is a new key to be added
			// to the next node's map with the provided value
			delete(typedNode, keys[0])
		}
	case []interface{}:
		if lengthKeys != 2 {
			err = fmt.Errorf("invalid path. IETF RFC 6901 does not permit paths after array indices")
			return
		}

		var arrayIndex int
		indexPath := keys[1]
		arrayIndex, err = parseArrayIndex(indexPath)
		if err != nil {
			return
		}
		var newSlice []interface{}
		newSlice, err = removeValueFromSliceAtIndex(typedNode, arrayIndex)
		parentMap[nextNodeKey] = newSlice
	case float64:
		// NOTE: It is a conscious decision of tbe encoding/json package to
		// decode all Number values to float64
		parentMap[nextNodeKey] = value
	case bool:
		parentMap[nextNodeKey] = value
	default:
		// Optimistically, assign the value and emit a warning of the unexpected JSON type
		parentMap[nextNodeKey] = value
		getLogger().Warningf("Invalid document node type: (%T)", nextNode)
		return
	}
	return
}

// The "add" operation performs one of the following functions,
// depending upon what the target location references:
//
//   - If the target location specifies an array index, a new value is
//     inserted into the array at the specified index.
//
//   - If the target location specifies an object member that does not
//     already exist, a new member is added to the object.
//
//   - If the target location specifies an object member that does exist,
//     that member's value is replaced.
//
// The operation object MUST contain a "value" member whose content
// specifies the value to be added.
//
// The "replace" operation replaces the value at the target location
// with a new value.  The operation object MUST contain a "value" member
// whose content specifies the replacement value.
func addOrReplaceValue(parentMap map[string]interface{}, keys []string, value interface{}, replace bool) (err error) {
	var nextNodeKey string   // := keys[0]
	var nextNode interface{} // := parentMap[nextNodeKey]
	lengthKeys := len(keys)

	switch lengthKeys {
	case 0:
		return fmt.Errorf("invalid map key (nil)")
	case 1: // special case of adding new key/value to document root
		nextNode = parentMap
	default: // adding keys/values along document path
		nextNodeKey = keys[0]
		nextNode = parentMap[nextNodeKey]
	}

	switch typedNode := nextNode.(type) {
	case map[string]interface{}:
		// If the resulting value is indeed another map type, we expect for a Json Map
		// we preserve that pointer for the next iteration
		if lengthKeys > 2 {
			// if the next node is a map AND there is more than one path following it,
			// it would mean we have not yet reached the final map or slice to add
			// a value to
			err = addOrReplaceValue(typedNode, keys[1:], value, replace)
			return
		} else {
			// if the next node is a map AND only 1 path remains after it,
			// it would mean that last path is a new key to be added
			// to the next node's map with the provided value
			currentKey := keys[lengthKeys-1]
			if _, exists := typedNode[currentKey]; !exists && replace {
				err = fmt.Errorf(ERR_PATCH_REPLACE_PATH_EXISTS)
				return
			}
			typedNode[currentKey] = value
		}
	case []interface{}:
		if lengthKeys != 2 {
			err = fmt.Errorf("invalid path. IETF RFC 6901 does not permit paths after array indices")
			return
		}

		var arrayIndex int
		indexPath := keys[1]
		arrayIndex, err = parseArrayIndex(indexPath)
		if err != nil {
			return
		}
		newSlice := insertValueIntoSlice(nextNode.([]interface{}), arrayIndex, value)
		parentMap[nextNodeKey] = newSlice
	case float64:
		// NOTE: It is a conscious decision of tbe encoding/json package to
		// decode all Number values to float64
		parentMap[nextNodeKey] = value
	case bool:
		parentMap[nextNodeKey] = value
	default:
		// Optimistically, assign the value and emit a warning of the unexpected JSON type
		parentMap[nextNodeKey] = value
		getLogger().Warningf("Invalid document node type: (%T)", nextNode)
		return
	}
	return
}

func insertValueIntoSlice(slice []interface{}, index int, value interface{}) []interface{} {
	if index == -1 || index >= len(slice) {
		return append(slice, value)
	}
	slice = append(slice[:index+1], slice[index:]...)
	slice[index] = value
	return slice
}

func removeValueFromSliceAtIndex(slice []interface{}, index int) (newSlice []interface{}, err error) {
	if index < 0 || index >= len(slice) {
		err = fmt.Errorf("remove array element failed. Index (%v) out of range for array (length: %v). ", index, len(slice))
		return
	}
	// unpack elements from the slice subsets (i.e. using ... notation)
	return append(slice[:index], slice[index+1:]...), nil
}
