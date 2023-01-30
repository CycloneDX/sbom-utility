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

package log

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/hokaccha/go-prettyjson"
)

const (
	EMPTY_STRING = "\"\""
)

// TODO enable consumer to configure colors from preset palette
var (
	BoldBlue   = color.New(color.FgBlue, color.Bold).SprintFunc()
	BoldGreen  = color.New(color.FgGreen, color.Bold).SprintFunc()
	BoldCyan   = color.New(color.FgCyan, color.Bold).SprintFunc()
	BoldYellow = color.New(color.FgYellow, color.Bold).SprintFunc()
)

func FormatMap(mapName string, field map[string]interface{}) (string, error) {

	var sb strings.Builder

	if reflect.ValueOf(field).Kind() != reflect.Map {
		return "", fmt.Errorf("invalid `Map`; actual Type: (%v)", reflect.TypeOf(field))
	}

	// m is a map[string]interface.
	// loop over keys and values in the map.
	for k, v := range field {
		sb.WriteString(fmt.Sprintf("[%s]: %+v", k, v))
	}

	return sb.String(), nil
}

func (log *MiniLogger) FormatStruct(unformatted interface{}) string {

	formatted, err := log.FormatStructE(unformatted)

	if err != nil {
		return err.Error()
	}

	return formatted
}

func (log *MiniLogger) FormatStructE(dataStructure interface{}) (string, error) {
	return innerFormatStruct(dataStructure, log.indentRunes, log.spacesIncrement, log.maxStrLength)
}

func FormatStruct(dataStructure interface{}) (string, error) {
	indentRunes := []rune("")
	spacesIncrement := []rune("")
	return innerFormatStruct(dataStructure, indentRunes, spacesIncrement, 128)
}

func innerFormatStruct(dataStructure interface{}, indentRunes []rune, spacesIncrement []rune, maxStrLen int) (string, error) {
	dataReflectValue := reflect.ValueOf(dataStructure)
	dataReflectKind := dataReflectValue.Kind()
	dataReflectType := reflect.TypeOf(dataStructure)

	if dataReflectKind != reflect.Struct {
		return "", fmt.Errorf("invalid `Struct`; actual Type: (%v)", reflect.TypeOf(dataStructure))
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\n%s{\n", string(indentRunes)))

	numFields := dataReflectType.NumField()

	var fieldStruct reflect.StructField
	var fieldName string
	var fieldTypeString string
	var fieldValueString string
	var fieldLength int

	// TODO: optionally, colorize keys/values; see "github.com/fatih/color" package
	// e.g., keys=white, string=green, floats/ints=cyan, bool=yellow, nil=magenta
	if numFields > 0 {

		for i := 0; i < numFields; i++ {
			fieldStruct = dataReflectType.Field(i)
			fieldName = fieldStruct.Name

			// TODO: using the .String() method interface reduces `[]byte` values
			// to "<[]uint8 Value>"; if you remove it, you see ALL the bytes
			// A better solution might be to show the first 'x' bytes (slice/truncate)
			fieldValue := dataReflectValue.Field(i)
			fieldValueKind := fieldValue.Kind()

			if fieldValueKind == reflect.Struct {
				// TODO: increment runes
				extraIndent := spacesIncrement //[]rune("  ")
				nestedIndentedRunes := append(indentRunes, extraIndent...)
				fieldValueString, _ = innerFormatStruct(fieldValue.Interface(), nestedIndentedRunes, spacesIncrement, maxStrLen)
			} else if fieldValueKind == reflect.Bool {
				fieldValueString = strconv.FormatBool(fieldValue.Bool())
			} else {
				fieldValueString = fieldValue.String()
				fieldLength = len(fieldValueString)

				if fieldLength == 0 {
					fieldValueString = EMPTY_STRING
				} else if fieldLength > maxStrLen {
					fieldValueString = fieldValueString[:maxStrLen]
				}
			}

			fieldTypeString = fmt.Sprintf("(%+v)", dataReflectValue.Field(i).Type())

			// TODO: use tabwriter to see if we can eliminate using too many spaces between columns
			//if len(fieldValueString) > 0 {
			line := fmt.Sprintf("%s%s%-12s %-7s %s %v\n",
				string(indentRunes),
				string(spacesIncrement),
				fieldName,
				fieldTypeString,
				":",
				fieldValueString)
			sb.WriteString(line)
		}
	} else {
		sb.WriteString(fmt.Sprintf("%s%s%s\n", string(indentRunes), string(spacesIncrement), "<empty>"))
	}
	sb.WriteString(fmt.Sprintf("%s}", string(indentRunes)))

	return sb.String(), nil
}

// Note: "go-prettyjson" colorizes output for shell output
func FormatInterfaceAsColorizedJson(data interface{}) (string, error) {
	formatter := prettyjson.NewFormatter()
	bytes, err := formatter.Marshal(data)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func FormatInterfaceAsJson(data interface{}) (string, error) {
	bytes, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// Often used in conjunction with formatting structures...
func AddTabs(text string) (tabbedText string) {
	tabbedText = strings.Replace(text, "\n", "\n\t", -1)
	return
}
