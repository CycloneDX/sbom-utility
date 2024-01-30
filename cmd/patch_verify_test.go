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
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/CycloneDX/sbom-utility/common"
	"github.com/CycloneDX/sbom-utility/utils"
)

// -------------------------------------------
// test helper functions
// -------------------------------------------

func VerifyPatchedOutputFileResult(t *testing.T, originalTest PatchTestInfo) (outputBuffer bytes.Buffer, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	patchDocument := NewIETFRFC6902PatchDocument(originalTest.PatchFile)
	if err = patchDocument.UnmarshalRecords(); err != nil {
		return
	}

	// If no patch records were found after unmarshal
	if patchDocument.Records == nil {
		return
	}

	// Create a new test info. structure copying in data from the original test
	queryTestInfo := NewCommonTestInfo()
	queryTestInfo.InputFile = originalTest.OutputFile

	// Load and Query temporary "patched" output BOM file using the "from" path
	// Default to "root" (i.e,, "") path if none selected.
	DEFAULT_PATH_DOC_ROOT := ""
	request, err := common.NewQueryRequestSelectFromWhere(
		common.QUERY_TOKEN_WILDCARD, DEFAULT_PATH_DOC_ROOT, "")
	if err != nil {
		t.Errorf("%s: %v", ERR_TYPE_UNEXPECTED_ERROR, err)
		return
	}

	// Verify each key was removed
	var pResult interface{}
	for _, record := range patchDocument.Records {
		var queryPath, key string
		queryPath, key, err = retrieveQueryPathFromPatchRecord(record.Path)
		//fmt.Printf("queryPath: %s, key: %s\n", queryPath, key)
		if err != nil {
			t.Errorf("%s: %v", "unable to parse patch record path.", err)
			return
		}
		request.SetRawFromPaths(queryPath)

		// use a buffered query on the temp. output file on the (parent) path
		pResult, outputBuffer, err = innerQuery(t, queryTestInfo, request)

		// NOTE: Query typically does NOT support non JSON map or slice
		// we need to allow float64, bool and string for "patch" validation
		if err != nil && !ErrorTypesMatch(err, &common.QueryResultInvalidTypeError{}) {
			t.Errorf("%s: %v", ERR_TYPE_UNEXPECTED_ERROR, err)
			return
		}

		// short-circuit if the "from" path dereferenced to a non-existent key
		if pResult == nil {
			t.Errorf("empty (nil) found at from clause: %s", request.String())
			return
		}

		// verify the "key" was removed from the (parent) JSON map
		err = VerifyPatched(record, pResult, key)
		if err != nil {
			return
		}
	}

	return
}

func VerifyPatched(record IETF6902Record, pResult interface{}, key string) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// verify the "key" was removed from the (parent) JSON map
	if pResult != nil {
		var contains bool
		switch typedResult := pResult.(type) {
		case map[string]interface{}:
			// NOTE: this is for "Add" operation only
			switch record.Operation {
			case IETF_RFC6902_OP_ADD:
				if _, ok := typedResult[key]; !ok {
					formattedResult, _ := utils.EncodeAnyToDefaultIndentedJSONStr(typedResult)
					err = getLogger().Errorf("patch failed. Key `%s`, found in: `%s`", key, formattedResult.String())
					return
				}
			case IETF_RFC6902_OP_REMOVE:
				return
			}
		case []interface{}:
			// NOTE: this is for "Add" operation only
			switch record.Operation {
			case IETF_RFC6902_OP_ADD:
				if len(typedResult) == 0 {
					err = getLogger().Errorf("verify failed. Record slice value is empty.")
					return
				}

				if record.Value == nil {
					err = getLogger().Errorf("verify failed. Document slice test value is nil.")
					return
				}
				_, _, contains, err = sliceContainsValue(typedResult, record.Value)
				if !contains {
					err = getLogger().Errorf("verify failed. Document value (%v) does not contain expected value (%v).", typedResult, record.Value)
					return
				}
			case IETF_RFC6902_OP_REMOVE:
				// { "op": "remove", "path": "/metadata/properties/1" }
				return
			}
		case string:
			switch record.Operation {
			case IETF_RFC6902_OP_ADD:
				if record.Value != typedResult {
					err = getLogger().Errorf("verify failed. Document value (%v) does not contain expected value (%v).", typedResult, record.Value)
					return
				}
			case IETF_RFC6902_OP_REMOVE:
				return
			}
			return
		case float64: // NOTE: encoding/json turns int64 to float64
			switch record.Operation {
			case IETF_RFC6902_OP_ADD:
				if record.Value != typedResult {
					err = getLogger().Errorf("verify failed. Document value (%v) does not contain expected value (%v).", typedResult, record.Value)
					return
				}
			case IETF_RFC6902_OP_REMOVE:
				return
			}
			return
		case bool:
			switch record.Operation {
			case IETF_RFC6902_OP_ADD:
				if record.Value != typedResult {
					err = getLogger().Errorf("verify failed. Document value (%v) does not contain expected value (%v).", typedResult, record.Value)
					return
				}
			case IETF_RFC6902_OP_REMOVE:
				return
			}
			return
		default:
			err = getLogger().Errorf("verify failed. Unexpected JSON type: `%T`", typedResult)
			return
		}
	} else {
		// TODO: return typed error
		getLogger().Trace("nil results")
	}
	return
}

func sliceContainsValue(slice []interface{}, value interface{}) (foundValue interface{}, index int, contains bool, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	switch typedValue := value.(type) {
	case map[string]interface{}:
		var ok bool
		for i, entry := range slice {
			if foundValue, ok = entry.(map[string]interface{}); !ok {
				err = fmt.Errorf("type mismatch error. Slice values: %v (%T), value: %v (%T)", entry, entry, foundValue, foundValue)
				return
			}
			if reflect.DeepEqual(foundValue, typedValue) {
				contains = true
				index = i
				return
			}
		}
		return
	case []interface{}:
		if reflect.DeepEqual(slice, typedValue) {
			contains = true
			return
		}
		return
	case string:
		foundValue = value
		contains = slices.Contains(slice, value)
		return
	case bool:
		foundValue = value
		contains = slices.Contains(slice, value)
		return
	case float64:
		foundValue = value
		contains = slices.Contains(slice, value)
		return
	default:
		getLogger().Errorf("contains test failed. Unexpected JSON type: `%T`", typedValue)
	}
	return
}
