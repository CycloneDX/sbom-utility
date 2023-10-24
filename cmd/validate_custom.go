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
	"regexp"

	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/CycloneDX/sbom-utility/utils"
	"github.com/jwangsadinata/go-multimap/slicemultimap"
)

// Validate all custom requirements that cannot be found be schema validation
// These custom requirements are categorized by the following areas:
// 1. Composition - document elements are organized as required (even though allowed by schema)
// 2. Metadata - Top-level, document metadata includes specific fields and/or values that match required criteria (e.g., regex)
// 3. License data - Components, Services (or any object that carries a License) meets specified requirements
func validateCustomCDXDocument(document *schema.BOM) (innerError error) {
	getLogger().Enter()
	defer getLogger().Exit(innerError)

	// Load custom validation file
	errCfg := schema.LoadCustomValidationConfig(utils.GlobalFlags.ConfigCustomValidationFile)
	if errCfg != nil {
		getLogger().Warningf("custom validation not possible: %s", errCfg.Error())
		innerError = errCfg
		return
	}

	// Validate all custom composition requirements for overall CDX SBOM are met
	if innerError = validateCustomDocumentComposition(document); innerError != nil {
		return
	}

	// Validate that at least required (e.g., valid, approved) "License" data exists
	if innerError = validateLicenseData(document); innerError != nil {
		return
	}

	// Validate all custom requirements for the CDX metadata structure
	// TODO: move up, as second test, once all custom test files have
	// required metadata
	if innerError = validateCustomMetadata(document); innerError != nil {
		return
	}
	return
}

// This validation function checks for custom composition requirements as follows:
// 1. Assure that the "metadata.component" does NOT have child Components
// 2. TODO: Assure that the "components" list is a "flat" list
func validateCustomDocumentComposition(document *schema.BOM) (innerError error) {
	getLogger().Enter()
	defer getLogger().Exit(innerError)

	// retrieve top-level component data from metadata
	component := document.GetCdxMetadataComponent()

	// NOTE: The absence of a top-level component in the metadata
	// SHOULD be a composition error
	if component == nil {
		return
	}

	// Generate a (composition) validation error
	pComponent := component.Components
	if pComponent != nil && len(*pComponent) > 0 {
		var fields = []string{"metadata", "component", "components"}
		innerError = NewSBOMCompositionError(
			MSG_INVALID_METADATA_COMPONENT_COMPONENTS,
			document,
			fields)
		return
	}

	return
}

// This validation function checks for custom metadata requirements are as follows:
// 1. required "Properties" exist and have valid values (against supplied regex)
// 2. Supplier field is filled out according to custom requirements
// 3. Manufacturer field is filled out according to custom requirements
// TODO: test for custom values in other metadata/fields:
func validateCustomMetadata(document *schema.BOM) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	// validate that the top-level component is declared with all required values
	if component := document.GetCdxMetadataComponent(); component == nil {
		err := NewSBOMMetadataError(
			document,
			MSG_INVALID_METADATA_COMPONENT,
			*document.GetCdxMetadata())
		return err
	}

	// Validate required custom properties (by `name`) exist with appropriate values
	err = validateCustomMetadataProperties(document)
	if err != nil {
		return err
	}

	return err
}

// This validation function checks for custom metadata property requirements (i.e., names, values)
// TODO: Evaluate need for this given new means to do this with JSON Schema v6 and 7
func validateCustomMetadataProperties(document *schema.BOM) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	validationProps := schema.CustomValidationChecks.GetCustomValidationMetadataProperties()
	if len(validationProps) == 0 {
		getLogger().Infof("No properties to validate")
		return
	}

	hashmap := slicemultimap.New()
	err = hashMetadataProperties(hashmap, document.GetCdxMetadataProperties())
	if err != nil {
		return
	}

	for _, checks := range validationProps {
		getLogger().Tracef("Running validation checks: Property name: `%s`, checks(s): `%v`...", checks.Name, checks)
		values, found := hashmap.Get(checks.Name)
		if !found {
			err = NewSbomMetadataPropertyError(
				document,
				MSG_PROPERTY_NOT_FOUND,
				&checks, nil)
			return err
		}

		// Check: (key) uniqueness
		// i.e., Multiple values with same "key" (specified), not provided
		// TODO: currently hashmap assumes "name" as the key; this could be dynamic (using reflect)
		if checks.CheckUnique != "" {
			getLogger().Tracef("CheckUnique: key: `%s`, `%s`, value(s): `%v`...", checks.Key, checks.CheckUnique, values)
			// if multi-hashmap has more than one value, property is NOT unique
			if len(values) > 1 {
				err := NewSbomMetadataPropertyError(
					document,
					MSG_PROPERTY_NOT_UNIQUE,
					&checks, nil)
				return err
			}
		}

		if checks.CheckRegex != "" {
			getLogger().Tracef("CheckRegex: field: `%s`, regex: `%v`...", checks.CheckRegex, checks.Value)
			compiledRegex, errCompile := compileRegex(checks.Value)
			if errCompile != nil {
				return errCompile
			}

			// TODO: check multiple values if provided
			value := values[0]
			if stringValue, ok := value.(string); ok {
				getLogger().Debugf(">> Testing value: `%s`...", stringValue)
				matched := compiledRegex.Match([]byte(stringValue))
				if !matched {
					err = NewSbomMetadataPropertyError(
						document,
						MSG_PROPERTY_REGEX_FAILED,
						&checks, nil)
					return err
				} else {
					getLogger().Debugf("matched:  ")
				}

			} else {
				err = NewSbomMetadataPropertyError(
					document,
					MSG_PROPERTY_NOT_UNIQUE,
					&checks, nil)
				return err
			}

		}
	}

	return err
}

// TODO: move to utils
func compileRegex(test string) (expression *regexp.Regexp, err error) {
	if test != "" {
		expression, err = regexp.Compile(test)
		if err != nil {
			getLogger().Errorf("invalid regular expression: `%s`", test)
		}
	}
	return
}

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
func validateLicenseData(document *schema.BOM) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	// Now we need to validate that the input file contains licenses
	// the license "hash" function does this validation checking for us...
	// TODO support []WhereFilter
	err = loadDocumentLicenses(document, nil)

	if err != nil {
		return
	}

	// TODO: verify that the input file contained valid license data

	return
}
