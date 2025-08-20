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
	"encoding/json"
	"fmt"
	"os"

	"github.com/CycloneDX/sbom-utility/utils"
)

const (
	REGEX_MATCH_ANY = ".+"
)

type CustomValidationConfig struct {
	Validation CustomValidation `json:"validation"`
}

type ValidationAction struct {
	Id          string         `json:"id"`
	Description string         `json:"description"`
	Selector    ItemSelector   `json:"selector"`
	Functions   []string       `json:"functions"`
	Properties  []ItemKeyValue `json:"properties"`
}

type ItemSelector struct {
	Path       string       `json:"path"`
	PrimaryKey ItemKeyValue `json:"primaryKey"`
}

func (selector *ItemSelector) String() string {
	return fmt.Sprintf("{\"path\": \"%s\", \"primaryKey\": %s}", selector.Path, selector.PrimaryKey.String())
}

type ItemKeyValue struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func (kv *ItemKeyValue) String() string {
	return fmt.Sprintf("{\"key\": \"%s\", \"value\": \"%s\"}", kv.Key, kv.Value)
}

type CustomValidation struct {
	Metadata          CustomValidationMetadata `json:"metadata"`
	Description       string                   `json:"description"`
	ValidationActions []ValidationAction       `json:"actions"`
}

type CustomValidationMetadata struct {
	Properties []CustomValidationProperty `json:"properties"`
	//Tools      []CustomValidationTool     `json:"tools"`
}

// NOTE: Assumes property "key" is the value in the "name" field
type CustomValidationProperty struct {
	CDXProperty
	Description string `json:"_validate_description"`
	Key         string `json:"_validate_key"`
	CheckUnique string `json:"_validate_unique"`
	CheckRegex  string `json:"_validate_regex"`
}

// Interfaces
type ArrayActions interface {
	KeyValuesExist() bool
	IsElementUnique() bool
}

type MapActions interface {
	KeyValuesExist() bool
}

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
		return fmt.Errorf("unable to find custom validation config file: '%s'", filename)
	}

	// Note we actively supply informative error messages to help user
	// understand exactly how the load failed
	getLogger().Infof("Loading custom validation config file: '%s'...", cfgFilename)
	// #nosec G304 (suppress warning)
	buffer, err := os.ReadFile(cfgFilename)
	if err != nil {
		return fmt.Errorf("unable to `ReadFile`: '%s'", cfgFilename)
	}

	err = json.Unmarshal(buffer, &CustomValidationChecks)
	if err != nil {
		return fmt.Errorf("cannot `Unmarshal`: '%s'", cfgFilename)
	}

	getLogger().Tracef("CustomValidationChecks: '%v'", CustomValidationChecks)

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
