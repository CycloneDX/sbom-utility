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

// The "-" character is used to index the end of the array (see [RFC6901])
const (
	RFC6901_END_OF_ARRAY = "-"
)

var PATCH_OUTPUT_SUPPORTED_FORMATS = MSG_SUPPORTED_OUTPUT_FORMATS_HELP +
	strings.Join([]string{FORMAT_JSON}, ", ")

// Command PreRunE helper function to test for patch file
func preRunTestForPatchFile(cmd *cobra.Command, args []string) error {
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
		err = preRunTestForInputFile(cmd, args)
		if err != nil {
			return
		}
		err = preRunTestForPatchFile(cmd, args)
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

	command.PersistentFlags().StringVar(&utils.GlobalFlags.PersistentFlags.OutputFormat, FLAG_OUTPUT_FORMAT, FORMAT_JSON,
		MSG_FLAG_OUTPUT_FORMAT+PATCH_OUTPUT_SUPPORTED_FORMATS)
	command.Flags().StringVarP(&utils.GlobalFlags.PatchFlags.PatchFile, FLAG_PATCH_FILE, "", "", MSG_PATCH_FILE)
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

	// TODO: write out "patched" BOM
	// TODO: allow user to change document serial # and/or version
	// Use the JSON Map to unmarshal to CDX-specific types

	// After patch records are applied; update the CdxBOM
	err = document.UnmarshalCycloneDXBOM()

	// Output the "patched" version of the Input BOM
	format := persistentFlags.OutputFormat
	getLogger().Infof("Writing patched BOM (`%s` format)...", format)
	switch format {
	case FORMAT_JSON:
		err = document.WriteAsEncodedJSONInt(writer, utils.GlobalFlags.PersistentFlags.GetOutputIndentInt())
	default:
		// Default to Text output for anything else (set as flag default)
		getLogger().Warningf("Trim not supported for `%s` format; defaulting to `%s` format...",
			format, FORMAT_JSON)
		err = document.WriteAsEncodedJSONInt(writer, utils.GlobalFlags.PersistentFlags.GetOutputIndentInt())
	}

	return
}

func processPatchRecords(bomDocument *schema.BOM, patchDocument *IETF6902Document) (err error) {

	patchRecords := patchDocument.Records

	for _, record := range patchRecords {
		fmt.Printf("patch: %s\n", record.String())
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

		switch record.Operation {
		case IETF_RFC6902_OP_ADD:
			var keys []string
			jsonMap := bomDocument.GetJSONMap()
			if keys, err = parseMapKeysFromPath(record.Path); err != nil {
				return
			}
			err = addValue(jsonMap, keys, record.Value)
			if err != nil {
				return
			}
			// if err = addValueOld(bomDocument, record.Path, record.Value); err != nil {
			// 	return
			// }
		case IETF_RFC6902_OP_REMOVE:
		case IETF_RFC6902_OP_REPLACE:
		case IETF_RFC6902_OP_MOVE:
		case IETF_RFC6902_OP_COPY:
		case IETF_RFC6902_OP_TEST:
		default:
			return fmt.Errorf("invalid IETF RFC 6902 operation: %s", record.Operation)
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
func addValue(parentMap map[string]interface{}, keys []string, value interface{}) (err error) {

	// TODO move err to caller
	if parentMap == nil {
		return fmt.Errorf("invalid parent document path (nil)")
	}

	if value == nil {
		// TODO: make this a declared error type that can be tested
		return fmt.Errorf("invalid IETF RFC 6902 patch operation. \"value\" missing")
	}

	lengthKeys := len(keys)
	if lengthKeys == 0 {
		return fmt.Errorf("invalid map key (nil)")
	}
	nextNodeKey := keys[0]
	nextNode := parentMap[nextNodeKey]

	switch typedNode := nextNode.(type) {
	case map[string]interface{}:
		// If the resulting value is indeed another map type, we expect for a Json Map
		// we preserve that pointer for the next iteration
		if lengthKeys > 1 { // TODO: > 2 ???
			err = addValue(typedNode, keys[1:], value)
			return
		} else {
			// add value to nextNode's map
			typedNode[keys[0]] = value
		}
	case []interface{}:
		if lengthKeys != 2 {
			err = fmt.Errorf("invalid path. IETF RFC 6901 does not permit paths after array indices")
			return
		}

		// TODO: get index (or '-') to use for insert into slice
		// newSlice := nextNode.([]interface{})
		// newSlice = append(newSlice, value)
		var arrayIndex int
		indexPath := keys[1]
		arrayIndex, err = parseIndex(indexPath)
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

// sNode, _ := utils.MarshalAnyToFormattedJsonString(typedNode)
// fmt.Printf("map:\n\"%s\"\n", sNode)
func insertValueIntoSlice(slice []interface{}, index int, value interface{}) []interface{} {
	if index == -1 || index > len(slice) {
		return append(slice, value)
	}
	slice = append(slice[:index+1], slice[index:]...)
	slice[index] = value
	return slice
}

func parseIndex(indexPath string) (arrayIndex int, err error) {

	// Check for RFC6901 end-of-array character
	if indexPath == RFC6901_END_OF_ARRAY {
		arrayIndex = -1
		return
	}
	// otherwise, the path should be convertible to an integer
	arrayIndex, err = strconv.Atoi(indexPath)
	return
}

// =================================================================
// =================================================================

// parse path returns index (-1 if not specified) and either a slice or json map
// if path is a slice, verify that the value matches the expected type
// if path is a map, assure value matches the expected type
// func parsePathOld(path string) (queryPath string, arrayIndex int, err error) {
// 	// NOTE: return parm. "queryPath" is empty, which defaults to "root" of document
// 	arrayIndex = -1 // default to insert "last"

// 	// first char SHOULD be a forward slash, if not error else remove it for processing
// 	if path[0] != '/' {
// 		err = fmt.Errorf("invalid path. Path must begin with forward slash")
// 		return
// 	}

// 	if len(path) > 1 {
// 		// parse out paths ignoring leading forward slash character
// 		paths := strings.Split(path[1:], "/")

// 		if lengthPaths := len(paths); lengthPaths > 1 {
// 			lastPath := paths[lengthPaths-1]
// 			if lastPath == "-" {
// 				arrayIndex = -1 // default
// 				paths = paths[0 : lengthPaths-1]
// 			} else if arrayIndex, err = strconv.Atoi(lastPath); err == nil {
// 				paths = paths[0 : lengthPaths-1]
// 			}
// 			queryPath = strings.Join(paths, ".")
// 		}
// 	}
// 	return
// }

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
// func addValueOld(document *schema.BOM, path string, value interface{}) (err error) {

// 	// The operation object MUST contain a "value" member whose content
// 	// specifies the value to be added.
// 	if value == nil {
// 		// TODO: make this a declared error type that can be tested
// 		return fmt.Errorf("invalid IETF RFC 6902 patch operation. \"value\" missing")
// 	}

// 	var queryPath string
// 	var index int
// 	queryPath, index, err = parsePathOld(path)
// 	if err != nil {
// 		return
// 	}
// 	fmt.Printf("index: %v\n", index)

// 	// out = append(out, value)
// 	itfcProperties := document.JsonMap["properties"]
// 	fmt.Printf("B4: pProperties (interface{}): %p\n", itfcProperties)
// 	sliceProperties := itfcProperties.([]interface{})
// 	fmt.Printf("B4: iProperties ([]interface{}): %p\n", sliceProperties)

// 	newMap1 := map[string]interface{}{"name": "BBB", "value": "222"}
// 	// Append the new map to the slice
// 	sliceProperties = append(sliceProperties, newMap1)
// 	fmt.Printf("Appended: iProperties ([]interface{}): %p\n", sliceProperties)

// 	sliceProperties = append(sliceProperties, value)
// 	fmt.Printf("Appended: iProperties ([]interface{}): %p\n", sliceProperties)

// 	itfcProperties = sliceProperties
// 	fmt.Printf("Appended: pProperties ([]interface{}): %p\n", sliceProperties)

// 	document.JsonMap["properties"] = itfcProperties

// 	var pResults interface{}
// 	var pointer interface{}
// 	pointer = document.JsonMap
// 	fmt.Printf("B4: pointer (JsonMap): %p\n", pointer)

// 	pointer = document.GetJSONMap()
// 	fmt.Printf("B4: pointer (GetJsonMap()): %p\n", pointer)
// 	pResults, _ = retrievePathPointer(document, strings.Split(queryPath, "."))
// 	fmt.Printf("pResults: %v (%T) (%p)\n", pResults, pResults, pResults)
// 	s, _ := utils.MarshalAnyToFormattedJsonString(pResults)
// 	fmt.Printf("pResults: %s\n", s)

// 	// Create a new map with the desired values
// 	newMap2 := map[string]interface{}{"name": "AAA", "value": "111"}

// 	// Append the new map to the slice
// 	slice := pResults.([]interface{})
// 	slice = append(slice, newMap2)
// 	slice = append(slice, value)
// 	fmt.Printf("After: slice pointer: %p\n", slice)
// 	pResults = &slice

// 	// valueOf := reflect.ValueOf(pResults)
// 	// if valueOf.Kind() == reflect.Slice {
// 	// 	fmt.Printf("pResults: Kind: %v\n", valueOf.Kind())
// 	// 	fmt.Printf("value (type:%T): %v\n", value, value)
// 	// 	pResults = append(pResults.([]interface{}), value)
// 	// }

// 	// j, _ := utils.MarshalAnyToFormattedJsonString(document.JsonMap)
// 	// fmt.Printf("JsonMap: %s\n", j)

// 	return
// }

// func retrievePathPointer(document *schema.BOM, paths []string) (pointer interface{}, err error) {
// 	getLogger().Enter()
// 	defer getLogger().Exit()

// 	pointer = document.JsonMap
// 	fmt.Printf("pointer (JsonMap): %p\n", pointer)

// 	pointer = document.GetJSONMap()
// 	fmt.Printf("pointer (GetJsonMap()): %p\n", pointer)

// 	for i, key := range paths {
// 		switch t := pointer.(type) {
// 		case map[string]interface{}:
// 			// If the resulting value is indeed another map type, we expect for a Json Map
// 			// we preserve that pointer for the next iteration
// 			pointer = pointer.(map[string]interface{})[key]
// 			fmt.Printf("key: \"%s\", pointer: %p (pointer.(map[string]interface{})[key])\n", key, pointer)
// 		case []interface{}:
// 			// TODO: are slices diff?
// 			// We no longer have a map to dereference into
// 			// So if there are more keys left as selectors it is an error
// 			if len(paths) > i+1 {
// 				err = fmt.Errorf("Boo")
// 				return
// 			}
// 		default:
// 			getLogger().Debugf("Invalid datatype of query: key: %s (%t)", key, t)
// 			err = fmt.Errorf("Hiss")
// 			return
// 		}
// 	}
// 	fmt.Printf("returning pointer: %p\n", pointer)

// 	return
// }
