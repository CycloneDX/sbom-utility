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
	"encoding/json"
	"fmt"
	"os"

	"github.com/CycloneDX/sbom-utility/utils"
)

// Globals
var CustomValidationChecks CustomValidationConfig

// ---------------------------------------------------------------
// Custom Validation
// ---------------------------------------------------------------

func LoadCustomValidationConfig(filename string) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	cfgFilename, err := utils.FindVerifyConfigFileAbsPath(getLogger(), filename)

	if err != nil {
		return fmt.Errorf("unable to find custom validation config file: `%s`", filename)
	}

	// Note we actively supply informative error messages to help user
	// understand exactly how the load failed
	getLogger().Infof("Loading custom validation config file: `%s`...", cfgFilename)
	// #nosec G304 (suppress warning)
	buffer, err := os.ReadFile(cfgFilename)
	if err != nil {
		return fmt.Errorf("unable to `ReadFile`: `%s`", cfgFilename)
	}

	err = json.Unmarshal(buffer, &CustomValidationChecks)
	if err != nil {
		return fmt.Errorf("cannot `Unmarshal`: `%s`", cfgFilename)
	}

	return
}

// TODO: return copies
func (config *CustomValidationConfig) GetCustomValidationConfig() *CustomValidation {
	return &config.Validation
}

func (config *CustomValidationConfig) GetCustomValidationMetadata() *CustomValidationMetadata {

	if cfg := config.GetCustomValidationConfig(); cfg != nil {
		return &cfg.Metadata
	}
	return nil
}

func (config *CustomValidationConfig) GetCustomValidationMetadataProperties() []CustomValidationProperty {

	if metadata := config.GetCustomValidationMetadata(); metadata != nil {
		return metadata.Properties
	}
	return nil
}

type CustomValidationConfig struct {
	Validation CustomValidation `json:"validation"`
}

// Custom Validation config.
type CustomValidation struct {
	Metadata CustomValidationMetadata `json:"metadata"`
}

type CustomValidationMetadata struct {
	Properties []CustomValidationProperty `json:"properties"`
	Tools      []CustomValidationTool     `json:"tools"`
}

// NOTE: Assumes property "key" is the value in the "name" field
type CustomValidationProperty struct {
	CDXProperty
	Description string `json:"_validate_description"`
	Key         string `json:"_validate_key"`
	CheckUnique string `json:"_validate_unique"`
	CheckRegex  string `json:"_validate_regex"`
}

type CustomValidationTool struct {
	CDXTool
	Description string `json:"_validate_description"`
}
