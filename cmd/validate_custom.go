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
	"github.com/CycloneDX/sbom-utility/common"
	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/CycloneDX/sbom-utility/utils"
	"github.com/jwangsadinata/go-multimap/slicemultimap"
)

// Validate all custom requirements that cannot be found be schema validation
// These is accomplished using specific "check" functions against JSON document types:
// - isUnique, hasProperties
func validateCustomCDXDocument(document *schema.BOM, validateFlags utils.ValidateCommandFlags, policyConfig *schema.LicensePolicyConfig) (innerError error) {
	getLogger().Enter()
	defer getLogger().Exit(innerError)

	// Load custom validation file
	errCfg := schema.LoadCustomValidationConfig(validateFlags.ConfigCustomValidationFile)
	if errCfg != nil {
		getLogger().Warningf("custom validation not possible: %s", errCfg.Error())
		innerError = errCfg
		return
	}

	// Validate that at least required (e.g., valid, approved) "License" data exists
	// TODO: Use different command line flag to trigger custom license validation
	// if innerError = validateLicenseData(document, policyConfig); innerError != nil {
	// 	return
	// }

	numCustomValidationActions := len(schema.CustomValidationChecks.Validation.ValidationActions)
	if numCustomValidationActions > 0 {
		getLogger().Tracef("Found %v custom validation actions.", numCustomValidationActions)
		innerError = processValidationActions(document, schema.CustomValidationChecks.Validation.ValidationActions)
	} else {
		getLogger().Tracef("No custom validation actions found.")
	}
	return
}

func processValidationActions(document *schema.BOM, actions []schema.ValidationAction) (innerError error) {
	var path, selectorKey, selectorKeyValue string

	for _, action := range actions {
		getLogger().Infof("Validating custom action (id: `%s`, selector: `%s`)...", action.Id, action.Selector.String())

		path = action.Selector.Path
		selectorKey = action.Selector.PrimaryKey.Key
		selectorKeyValue = action.Selector.PrimaryKey.Value

		// Use utility's "query" function to obtain BOM document subsets (as JSON map(s))
		// Prepare a "QueryRequest" by first using "path" to locate the subset of the BOM
		// document to be processed
		qr := common.NewQueryRequest()
		qr.SetRawFromPaths(action.Selector.Path)

		// then add "where" filter if we have a selector key-value (into an array)
		if selectorKey != "" {
			var whereFilter common.WhereFilter
			whereFilter, innerError = prepareWhereFilter(action.Selector)
			filters := []common.WhereFilter{whereFilter}
			qr.SetWhereFilters(filters)
		}

		// Perform the query and validate the result
		result, errQuery := QueryJSONMap(document.GetJSONMap(), qr)

		if errQuery != nil {
			// TODO: leverage Query error type or create new type
			innerError = getLogger().Errorf("%s. %s: %s", ERR_QUERY, MSG_QUERY_ERROR_SELECTOR, path)
			buffer, errEncode := utils.EncodeAnyToDefaultIndentedJSONStr(result)
			if errEncode != nil {
				getLogger().Tracef("result: %s", buffer.String())
			}
			return
		}

		// value found in BOM is either a map or array of map
		jsonMap, jsonArrayOfMap, typeError := getJsonType(result)
		if typeError != nil {
			innerError = typeError
			return
		}

		// error out if selector (i.e., path with optional primary key) was not found in BOM
		if len(jsonMap) == 0 && len(jsonArrayOfMap) == 0 {
			innerError = NewJSONElementNotFoundError(action)
			return
		}

		if jsonArrayOfMap != nil {
			// hash values using primary key-value specified; Note that "" (empty) is a valid key value
			var hashmap *slicemultimap.MultiMap
			hashmap, innerError = hashJsonArrayElements(jsonArrayOfMap, selectorKey)

			for _, fx := range action.Functions {
				getLogger().Infof(">> Checking %s: (selector: `%v`)...", fx, action.Selector)
				switch fx {
				case "isUnique":
					unique, numOccurrences := IsUnique(hashmap, selectorKeyValue)
					if !unique {
						innerError = NewItemIsUniqueError(action, numOccurrences)
					}
				case "hasProperties":
					properties := action.Properties
					// make sure we have properties to validate...
					if len(properties) == 0 {
						// TODO need a special error for "no properties found"
						innerError = NewItemHasPropertiesError(action, schema.ItemKeyValue{})
						return
					}
					exists, missingProperty := JsonArrayElementsHaveProperties(jsonArrayOfMap, properties)
					if !exists {
						innerError = NewItemHasPropertiesError(action, missingProperty)
						return
					}
				default:
					innerError = getLogger().Errorf("unknown function: `%s`...", fx)
					return
				}
			}
		} else if jsonMap != nil { // redundant check, but leave for now
			for _, fx := range action.Functions {
				getLogger().Tracef("processing function: `%s`...", fx)
				switch fx {
				case "hasProperties":
					properties := action.Properties
					// make sure we have properties to validate...
					if len(properties) == 0 {
						//innerError = getLogger().Errorf("No properties declared. Action id: `%s`, selector path: `%v`", action.Id, path)
						// TODO need a special error for "no properties found"
						innerError = NewItemHasPropertiesError(action, schema.ItemKeyValue{})
						return
					}
					exists, missingProperty := JsonMapHasProperties(jsonMap, properties)
					if !exists {
						// innerError = propertyError
						innerError = NewItemHasPropertiesError(action, missingProperty)
						return
					}
				default:
					innerError = getLogger().Errorf("unknown function: `%s`...", fx)
					return
				}
			}
		}
	}
	return
}

func hashJsonArrayElements(jsonArrayOfMap []map[string]interface{}, selectorKey string) (hashmap *slicemultimap.MultiMap, innerError error) {
	hashmap = slicemultimap.New()

	for i, m := range jsonArrayOfMap {
		// Assure primary key exists
		if selectorKey != "" {
			_, exists := m[selectorKey]
			if !exists {
				innerError = getLogger().Errorf("invalid key. Key '%s' does not exist in element[%d] key-value map: %v", selectorKey, i, m)
				return
			}
		}
		primaryKeyValue := m[selectorKey]
		getLogger().Tracef("hashing element[%d] with key-value[%s]: %s...", i, selectorKey, primaryKeyValue)
		hashmap.Put(primaryKeyValue, m)
	}
	return
}

func prepareWhereFilter(selector schema.ItemSelector) (whereFilter common.WhereFilter, innerError error) {
	selectorKey := selector.PrimaryKey.Key
	selectorKeyValue := selector.PrimaryKey.Value

	whereFilter.Operand = common.QUERY_WHERE_OPERAND_EQUALS
	whereFilter.Key = selectorKey
	whereFilter.Value = selectorKeyValue
	whereFilter.ValueRegEx, innerError = utils.CompileRegex(whereFilter.Value)
	return
}

func IsUnique(hashmap *slicemultimap.MultiMap, keyValue string) (unique bool, numOccurrences int) {
	values, found := hashmap.Get(keyValue)
	// if multi-hashmap has more than one occurrence "value", property is NOT unique
	numOccurrences = len(values)
	if found && numOccurrences == 1 {
		unique = true
	}
	return
}

func JsonArrayElementsHaveProperties(arrayOfMap []map[string]interface{}, properties []schema.ItemKeyValue) (exists bool, missingProperty schema.ItemKeyValue) {
	exists = false
	for _, jsonMap := range arrayOfMap {
		exists, missingProperty = JsonMapHasProperties(jsonMap, properties)
		if !exists {
			// TODO: print map of failed array item
			getLogger().Tracef("property not found. Property key: `%s`, value: `%s`", missingProperty.Key, missingProperty.Value)
			break
		}
	}
	return
}

func JsonMapHasProperties(jsonMap map[string]interface{}, properties []schema.ItemKeyValue) (exists bool, missingProperty schema.ItemKeyValue) {
	exists = false
	for _, property := range properties {
		exists = KeyValueExistsInMap(jsonMap, property.Key, property.Value)
		if !exists {
			getLogger().Tracef("property not found. Property key: `%s`, value: `%s`", property.Key, property.Value)
			missingProperty = property
			break
		}
	}
	return
}

func KeyValueExistsInMap(jsonMap map[string]interface{}, key string, valueRegex string) (exists bool) {
	var value interface{}
	value, exists = jsonMap[key]
	if !exists {
		return
	}
	if valueRegex != "" {
		matches, _ := matchesRegex(value, valueRegex)
		getLogger().Tracef("value: `%s` matches regex: `%s` (%v)", value, valueRegex, matches)
		exists = matches
	}
	return
}

func matchesRegex(value interface{}, regex string) (matched bool, innerError error) {
	if regex == "" {
		innerError = getLogger().Errorf("invalid regex. regex is empty.")
		return
	}
	if stringValue, ok := value.(string); ok {
		compiledRegex, errCompile := utils.CompileRegex(regex)
		if errCompile != nil {
			innerError = errCompile
			return
		}

		getLogger().Debugf(">> Testing value: '%s'...", stringValue)
		matched = compiledRegex.Match([]byte(stringValue))
		if !matched {
			innerError = getLogger().Errorf("invalid value. Value '%s' does not match regex '%s'", value, regex)
			return
		} else {
			getLogger().Debugf("matched:  ")
		}

	} else {
		innerError = getLogger().Errorf("invalid value. Value '%s' was not a string", value)
		return
	}
	return
}

func getJsonType(value interface{}) (jsonMap map[string]interface{}, jsonArrayOfMap []map[string]interface{}, innerError error) {
	switch typedResult := value.(type) {
	case []interface{}:
		jsonArrayOfMap, innerError = convertToJsonArrayOfMaps(typedResult)
	case map[string]interface{}:
		jsonMap, innerError = convertToJsonMap(typedResult)
	default:
		innerError = getLogger().Errorf("%s. type: '%T'", ERR_TYPE_INVALID_JSON_TYPE, typedResult)
	}
	return
}

func convertToJsonArrayOfMaps(sourceInterfaces []interface{}) (targetMaps []map[string]interface{}, innerError error) {
	// Iterate and perform type assertion
	for _, item := range sourceInterfaces {
		if m, ok := item.(map[string]interface{}); ok {
			targetMaps = append(targetMaps, m)
		} else {
			innerError = getLogger().Errorf("%s", ERR_TYPE_INVALID_JSON_ARRAY)
		}
	}
	return
}

func convertToJsonMap(sourceInterface interface{}) (targetMap map[string]interface{}, innerError error) {
	// perform type assertion
	if m, ok := sourceInterface.(map[string]interface{}); ok {
		targetMap = m
	} else {
		innerError = getLogger().Errorf("%s", ERR_TYPE_INVALID_JSON_MAP)
	}
	return
}

// =================================================================================
// TODO: Use different command line flag to trigger custom license validation
// TODO: Assure that after hashing "license" data within the "components" array
// that at least one valid license is found
// TODO: Assure top-level "metadata.component"
// TODO support []WhereFilter
// func validateLicenseData(document *schema.BOM, policyConfig *schema.LicensePolicyConfig) (err error) {
// 	getLogger().Enter()
// 	defer getLogger().Exit(err)
// 	// Now we need to validate that the input file contains licenses
// 	// the license "hash" function does this validation checking for us...
// 	// TODO support []WhereFilter
// 	// NOTE: licenseFlags will be all defaults (should not matter for simple true/false validation)
// 	err = loadDocumentLicenses(document, policyConfig, nil, utils.GlobalFlags.LicenseFlags)
// 	if err != nil {
// 		return
// 	}
// 	// TODO: verify that the input file contained valid license data
// 	return
// }
