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

func (bom *BOM) TrimJsonMap(key string) {
	if key != "" {
		if jsonMap := bom.GetJSONMap(); jsonMap != nil {
			bom.trimEntity(jsonMap, key)
		}
	}
}

func (bom *BOM) trimEntity(entity interface{}, key string) {
	switch typedEntity := entity.(type) {
	case map[string]interface{}:
		jsonMap := typedEntity
		_, ok := jsonMap[key]
		if ok {
			// TODO: make it an option to just "nil" out the value
			// as this is faster as well as sufficient for json.Marshal() purposes
			// as keys with nil values are already omitted.
			//jsonMap[key] = nil
			delete(jsonMap, key)
		}
		for _, mapValue := range jsonMap {
			// avoid making costly function calls for primitive types
			switch typedValue := mapValue.(type) {
			case map[string]interface{}:
				bom.trimEntity(typedValue, key)
			case []interface{}:
				bom.trimEntity(typedValue, key)
			}
		}
	case []interface{}:
		// if type is other than above
		sliceValue := typedEntity
		for i := range sliceValue {
			bom.trimEntity(sliceValue[i], key)
		}
	default:
		// if type is other than above
		getLogger().Debugf("unhandled type: [%T]", typedEntity)
	}
}