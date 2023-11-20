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

package utils

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

const (
	DEFAULT_JSON_INDENT_STRING = "    "
	DEFAULT_JSON_PREFIX_STRING = ""
)

func IsJsonMapType(any interface{}) (isMapType bool) {
	_, isMapType = any.(map[string]interface{})
	return
}

func IsJsonSliceType(any interface{}) (isSliceType bool) {
	_, isSliceType = any.([]interface{})
	return
}

func IsValidJsonMap(test string) bool {
	var js map[string]interface{}
	err := json.Unmarshal([]byte(test), &js)
	return err == nil
}

func IsValidJsonRaw(test []byte) bool {
	var js interface{}
	err := json.Unmarshal(test, &js)
	return err == nil
}

// NOTE: simple wrapper method on json package to standardize parms
// WARNING: By default, json.Marshal() methods will use a unicode encoding
// which will encode utf8 characters such as: '@', '<', '>', etc.
func MarshalAnyToFormattedJsonString(any interface{}) (string, error) {
	// Indent each level with 2 space chars.
	byteMapOut, err := json.MarshalIndent(any, "", "  ")
	return string(byteMapOut), err
}

func MarshalStructToJsonMap(any interface{}) (mapOut map[string]interface{}, err error) {
	// TODO: validate input parameter is a struct
	var bytesOut []byte
	bytesOut, err = json.Marshal(any)

	if err != nil {
		return
	}
	err = json.Unmarshal(bytesOut, &mapOut)
	return
}

// Creates strings of spaces based upon provided integer length (e.g., the --indent <length> flag)
func GenerateIndentString(length int) (prefix string) {
	var sb strings.Builder
	for i := 0; i < length; i++ {
		sb.WriteString(" ")
	}
	return sb.String()
}

// NOTE: Using this custom encoder avoids the json.Marshal() default
// behavior of encoding utf8 characters such as: '@', '<', '>', etc.
// as unicode.
func EncodeAnyToIndentedJSONStr(any interface{}, indent string) (outputBuffer bytes.Buffer, err error) {
	bufferedWriter := bufio.NewWriter(&outputBuffer)
	encoder := json.NewEncoder(bufferedWriter)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent(DEFAULT_JSON_PREFIX_STRING, indent)
	err = encoder.Encode(any)
	// MUST ensure all data is written to buffer before further testing
	bufferedWriter.Flush()
	return
}

func EncodeAnyToDefaultIndentedJSONStr(any interface{}) (outputBuffer bytes.Buffer, err error) {
	return EncodeAnyToIndentedJSONStr(any, DEFAULT_JSON_INDENT_STRING)
}

func EncodeAnyToIndentedJSONInt(any interface{}, numSpaces int) (outputBuffer bytes.Buffer, err error) {
	indentString := GenerateIndentString(numSpaces)
	return EncodeAnyToIndentedJSONStr(any, indentString)
}

func WriteAnyAsEncodedJSONInt(writer io.Writer, any interface{}, numSpaces int) (outputBuffer bytes.Buffer, err error) {
	outputBuffer, err = EncodeAnyToIndentedJSONInt(any, numSpaces)
	if writer != nil && err == nil {
		_, err = writer.Write(outputBuffer.Bytes())
	}
	return
}

// TODO: function NOT complete, only placeholder type switch
// TODO: allow generic function to be applied to types
// func PrintTypes(values ...interface{}) {
// 	for index, value := range values {
// 		switch t := value.(type) {
// 		case nil:
// 		case int:
// 		case uint:
// 		case int32:
// 		case int64:
// 		case uint64:
// 		case float32:
// 		case float64:
// 		case string:
// 		case bool:
// 		}
// 	}
// }
