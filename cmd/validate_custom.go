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
// These custom requirements are categorized by the following areas:
// 1. Composition - document elements are organized as required (even though allowed by schema)
// 2. Metadata - Top-level, document metadata includes specific fields and/or values that match required criteria (e.g., regex)
// 3. License data - Components, Services (or any object that carries a License) meets specified requirements
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

	// Validate all custom composition requirements for overall CDX SBOM are met
	// if innerError = validateCustomDocumentComposition(document); innerError != nil {
	// 	return
	// }

	// Validate that at least required (e.g., valid, approved) "License" data exists
	if innerError = validateLicenseData(document, policyConfig); innerError != nil {
		return
	}

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
		// Prepare a "QueryRequest"
		// First, use "path" to locate the subset of the BOM document to be processed
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

		// Array of map
		if jsonArrayOfMap != nil {
			// hash values using primary key-value specified; Note that "" (empty) is a valid key value
			var hashmap *slicemultimap.MultiMap
			hashmap, innerError = hashJsonArrayElements(jsonArrayOfMap, selectorKey)

			for _, fx := range action.Functions {
				getLogger().Infof(">> Checking %s: (selector: `%v`)...", fx, action.Selector)
				switch fx {
				case "isUnique":
					var unique bool
					unique, innerError = IsUnique(hashmap, selectorKeyValue)
					if !unique {
						innerError = getLogger().Errorf("item not unique. selector: `%v`", action.Selector.String())
					}
				case "hasProperties":
					properties := action.Properties
					// make sure we have properties to validate...
					if len(properties) == 0 {
						innerError = getLogger().Errorf("no properties declared. Action id: `%s`, selector path: `%v`", action.Id, path)
						return
					}
					exists, propertyError := JsonArrayElementsHaveProperties(jsonArrayOfMap, properties)
					if !exists {
						innerError = propertyError
						return
					}
				default:
					innerError = getLogger().Errorf("unknown function: `%s`...", fx)
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
						innerError = getLogger().Errorf("No properties declared. Action id: `%s`, selector path: `%v`", action.Id, path)
						return
					}
					exists, propertyError := JsonMapHasProperties(jsonMap, properties)
					if !exists {
						innerError = propertyError
						return
					}
				default:
					innerError = getLogger().Errorf("unknown function: `%s`...", fx)
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
	// var whereFilter = common.WhereFilter{}
	selectorKey := selector.PrimaryKey.Key
	selectorKeyValue := selector.PrimaryKey.Value

	whereFilter.Operand = common.QUERY_WHERE_OPERAND_EQUALS
	whereFilter.Key = selectorKey
	whereFilter.Value = selectorKeyValue
	whereFilter.ValueRegEx, innerError = utils.CompileRegex(whereFilter.Value)
	return
}

func IsUnique(hashmap *slicemultimap.MultiMap, keyValue string) (unique bool, innerError error) {
	getLogger().Tracef("Checking element keyValue: '%s'...", keyValue)
	values, found := hashmap.Get(keyValue)

	if !found {
		innerError = getLogger().Errorf("%s. %s (keyValue: `%s`)", ERR_QUERY, MSG_QUERY_ERROR_ELEMENT_NOT_FOUND, keyValue)
		return
	}

	// if multi-hashmap has more than one occurrence "value", property is NOT unique
	numOccurrences := len(values)
	if numOccurrences > 1 {
		innerError = getLogger().Errorf("%s. %s (keyValue: `%s`, occurs: %v)", ERR_QUERY, MSG_QUERY_ERROR_ELEMENT_NOT_FOUND, keyValue, numOccurrences)
		return
	}
	// Note: redundant for now with errors; but, may want to make errors optional and emit warnings...
	unique = true
	return
}

func JsonArrayElementsHaveProperties(arrayOfMap []map[string]interface{}, properties []schema.ItemKeyValue) (exists bool, innerError error) {
	exists = false
	for _, jsonMap := range arrayOfMap {
		exists, innerError = JsonMapHasProperties(jsonMap, properties)
		if !exists {
			break
		}
	}
	return
}

func JsonMapHasProperties(jsonMap map[string]interface{}, properties []schema.ItemKeyValue) (exists bool, innerError error) {
	exists = false
	for _, property := range properties {
		exists = KeyValueExistsInMap(jsonMap, property.Key, property.Value)
		if !exists {
			innerError = getLogger().Errorf("property not found. Property key: `%s`, value: `%s`", property.Key, property.Value)
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

// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

// This validation function checks for custom composition requirements as follows:
// 1. Assure that the "metadata.component" does NOT have child Components
// 2. TODO: Assure that the "components" list is a "flat" list
// func validateCustomDocumentComposition(document *schema.BOM) (innerError error) {
// 	getLogger().Enter()
// 	defer getLogger().Exit(innerError)

// 	// retrieve top-level component data from metadata
// 	component := document.GetCdxMetadataComponent()

// 	// NOTE: The absence of a top-level component in the metadata
// 	// SHOULD be a composition error
// 	if component == nil {
// 		return
// 	}

// 	// Generate a (composition) validation error
// 	pComponent := component.Components
// 	if pComponent != nil && len(*pComponent) > 0 {
// 		var fields = []string{"metadata", "component", "components"}
// 		innerError = NewSBOMCompositionError(
// 			MSG_INVALID_METADATA_COMPONENT_COMPONENTS,
// 			document,
// 			fields)
// 		return
// 	}

// 	return
// }

// This validation function checks for custom metadata requirements are as follows:
// 1. required "Properties" exist and have valid values (against supplied regex)
// 2. Supplier field is filled out according to custom requirements
// 3. Manufacturer field is filled out according to custom requirements
// TODO: test for custom values in other metadata/fields:
// func validateCustomMetadata(document *schema.BOM) (err error) {
// 	getLogger().Enter()
// 	defer getLogger().Exit(err)

// 	// validate that the top-level pComponent is declared with all required values
// 	if pComponent := document.GetCdxMetadataComponent(); pComponent == nil {
// 		err := NewSBOMMetadataError(
// 			document,
// 			MSG_INVALID_METADATA_COMPONENT,
// 			*document.GetCdxMetadata())
// 		return err
// 	}

// 	// Validate required custom properties (by `name`) exist with appropriate values
// 	err = validateCustomMetadataProperties(document)
// 	if err != nil {
// 		return err
// 	}

// 	return err
// }

// This validation function checks for custom metadata property requirements (i.e., names, values)
// TODO: Evaluate need for this given new means to do this with JSON Schema v6 and 7
// func validateCustomMetadataProperties(document *schema.BOM) (err error) {
// 	getLogger().Enter()
// 	defer getLogger().Exit(err)

// 	validationProps := schema.CustomValidationChecks.GetCustomValidationMetadataProperties()
// 	if len(validationProps) == 0 {
// 		getLogger().Infof("No properties to validate")
// 		return
// 	}

// 	// TODO: move map to BOM object
// 	hashmap := slicemultimap.New()
// 	pProperties := document.GetCdxMetadataProperties()
// 	if pProperties != nil {
// 		err = hashMetadataProperties(hashmap, *pProperties)
// 		if err != nil {
// 			return
// 		}
// 	}

// 	for _, checks := range validationProps {
// 		getLogger().Tracef("Running validation checks: Property name: '%s', checks(s): '%v'...", checks.Name, checks)
// 		values, found := hashmap.Get(checks.Name)
// 		if !found {
// 			err = NewSbomMetadataPropertyError(
// 				document,
// 				MSG_PROPERTY_NOT_FOUND,
// 				&checks, nil)
// 			return err
// 		}

// 		// Check: (key) uniqueness
// 		// i.e., Multiple values with same "key" (specified), not provided
// 		// TODO: currently hashmap assumes "name" as the key; this could be dynamic (using reflect)
// 		if checks.CheckUnique != "" {
// 			getLogger().Tracef("CheckUnique: key: '%s', '%s', value(s): '%v'...", checks.Key, checks.CheckUnique, values)
// 			// if multi-hashmap has more than one value, property is NOT unique
// 			if len(values) > 1 {
// 				err := NewSbomMetadataPropertyError(
// 					document,
// 					MSG_PROPERTY_NOT_UNIQUE,
// 					&checks, nil)
// 				return err
// 			}
// 		}

// 		if checks.CheckRegex != "" {
// 			getLogger().Tracef("CheckRegex: field: '%s', regex: '%v'...", checks.CheckRegex, checks.Value)
// 			compiledRegex, errCompile := utils.CompileRegex(checks.Value)
// 			if errCompile != nil {
// 				return errCompile
// 			}

// 			// TODO: check multiple values if provided
// 			value := values[0]
// 			if stringValue, ok := value.(string); ok {
// 				getLogger().Debugf(">> Testing value: '%s'...", stringValue)
// 				matched := compiledRegex.Match([]byte(stringValue))
// 				if !matched {
// 					err = NewSbomMetadataPropertyError(
// 						document,
// 						MSG_PROPERTY_REGEX_FAILED,
// 						&checks, nil)
// 					return err
// 				} else {
// 					getLogger().Debugf("matched:  ")
// 				}

// 			} else {
// 				err = NewSbomMetadataPropertyError(
// 					document,
// 					MSG_PROPERTY_NOT_UNIQUE,
// 					&checks, nil)
// 				return err
// 			}

// 		}
// 	}
// 	return err
// }

func hashMetadataProperties(hashmap *slicemultimap.MultiMap, properties []schema.CDXProperty) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	if hashmap == nil {
		return getLogger().Errorf("invalid hashmap: %v", hashmap)
	}

	for _, prop := range properties {
		hashmap.Put(prop.Name, prop.Value)
	}

	return
}

// TODO: Assure that after hashing "license" data within the "components" array
// that at least one valid license is found
// TODO: Assure top-level "metadata.component"
// TODO support []WhereFilter
func validateLicenseData(document *schema.BOM, policyConfig *schema.LicensePolicyConfig) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	// Now we need to validate that the input file contains licenses
	// the license "hash" function does this validation checking for us...
	// TODO support []WhereFilter
	// NOTE: licenseFlags will be all defaults (should not matter for simple true/false validation)
	err = loadDocumentLicenses(document, policyConfig, nil, utils.GlobalFlags.LicenseFlags)

	if err != nil {
		return
	}

	// TODO: verify that the input file contained valid license data
	return
}
