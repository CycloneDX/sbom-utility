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

package schema

import (
	"bytes"
	"encoding/gob"
	"strconv"

	"github.com/CycloneDX/sbom-utility/common"
)

// Note: Golang supports the RE2 regular exp. engine which does not support many
// features such as lookahead, lookbehind, etc.
// See: https://en.wikipedia.org/wiki/Comparison_of_regular_expression_engines
func whereFilterMatch(mapObject map[string]interface{}, whereFilters []common.WhereFilter) (match bool, err error) {
	var buf bytes.Buffer
	var key string

	// create a byte encoder
	enc := gob.NewEncoder(&buf)

	for _, filter := range whereFilters {

		key = filter.Key
		value, present := mapObject[key]
		getLogger().Debugf("testing object map[%s]: `%v`", key, value)

		if !present {
			match = false
			err = getLogger().Errorf("key `%s` not found ib object map", key)
			break
		}

		// Reset the encoder'a byte buffer on each iteration and
		// convert the value (an interface{}) to []byte we can use on regex. eval.
		buf.Reset()

		// Do not encode nil pointer values; replace with empty string
		if value == nil {
			value = ""
		}

		// Handle non-string data types in the map by converting them to string
		switch data := value.(type) {
		case string:
			value = data
		case bool:
			value = strconv.FormatBool(data)
		case int:
			value = strconv.Itoa(data)
		case float64:
			// NOTE: JSON Unmarshal() always decodes JSON Numbers as "float64" type
			value = strconv.FormatFloat(data, 'f', -1, 64)
		default:
			getLogger().Errorf("unhandled datatype. key=%s, value=`%v`, type=`%T`", key, data, data)
		}

		err = enc.Encode(value)

		if err != nil {
			err = getLogger().Errorf("Unable to convert value: `%v`, to []byte", value)
			return
		}

		// Test that the field value matches the regex supplied in the current filter
		// Note: the regex compilation is performed during command param. processing
		if match = filter.ValueRegEx.Match(buf.Bytes()); !match {
			break
		}
	}

	return
}
