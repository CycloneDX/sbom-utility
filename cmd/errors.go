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
	"fmt"
	"reflect"

	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/xeipuuv/gojsonschema"
)

const (
	ERROR_APPLICATION = 1
	ERROR_VALIDATION  = 2
)

// General error messages
const (
	ERR_TYPE_INVALID_JSON_TYPE        = "invalid JSON type"
	ERR_TYPE_INVALID_JSON_ARRAY       = "invalid JSON array"
	ERR_TYPE_INVALID_JSON_MAP         = "invalid JSON map"
	ERR_TYPE_INVALID_SBOM             = "invalid SBOM"
	ERR_TYPE_SBOM_COMPONENT           = "component error"
	ERR_TYPE_SBOM_LICENSE             = "license error"
	ERR_TYPE_SBOM_COMPOSITION         = "composition error"
	ERR_TYPE_SBOM_METADATA            = "metadata error"
	ERR_TYPE_SBOM_METADATA_PROPERTY   = "metadata property error"
	ERR_TYPE_UNEXPECTED_ERROR         = "unexpected error"
	ERR_TYPE_UNSUPPORTED_OPERATION    = "unsupported operation"
	ERR_TYPE_IETF_RFC6902_TEST_FAILED = "IETF RFC6902 test operation error"
)

// Custom Validation messages
// TODO: Need to define a profile that supports these validation checks/messages
const (
	MSG_ELEMENT_NOT_UNIQUE  = "custom validation error. Element not unique"
	MSG_PROPERTY_NOT_UNIQUE = "check failed. Property not unique"
	// MSG_INVALID_METADATA_PROPERTIES = "field `metadata.properties` is missing or invalid"
	// MSG_INVALID_METADATA_COMPONENT_COMPONENTS = "field `metadata.component.components` array should be empty"
	// MSG_INVALID_METADATA_COMPONENT            = "field `metadata.component` is missing or invalid"
)

// Validation messages
const (
	MSG_FORMAT_TYPE                    = "format: '%s'"
	MSG_SCHEMA_ERRORS                  = "schema errors found"
	MSG_PROPERTY_NOT_FOUND             = "property not found"
	MSG_PROPERTY_REGEX_FAILED          = "check failed: property regex mismatch"
	MSG_IETF_RFC6902_OPERATION_SUCCESS = "IETF RFC6902 test operation success"
)

// Custom validation messages
const (
	ERR_ELEMENT_NOT_FOUND  = "custom validation error. Element not found unique (key: `%s`, value: `%s`)"
	ERR_ELEMENT_NOT_UNIQUE = "custom validation error. Element not unique (key: `%s`, value: `%s`)"
)

// License messages
const (
	MSG_LICENSE_INVALID_DATA   = "invalid license data"
	MSG_LICENSE_INVALID_POLICY = "invalid license policy"
	MSG_LICENSE_NOT_FOUND      = "license not found"
	MSG_LICENSES_NOT_FOUND     = "licenses not found"
	MSG_LICENSE_HASH_ERROR     = "hash of license failed"
)

// Query error details
const (
	ERR_QUERY                                  = "query error"
	MSG_QUERY_ERROR_SELECTOR                   = "invalid selector path into JSON document"
	MSG_QUERY_ERROR_ELEMENT_NOT_FOUND          = "element not found in JSON document"
	MSG_QUERY_ERROR_FROM_KEY_NOT_FOUND         = "key not found in path"
	MSG_QUERY_ERROR_FROM_KEY_SLICE_DEREFERENCE = "key attempts to dereference into an array"
	MSG_QUERY_ERROR_SELECT_WILDCARD            = "wildcard cannot be used with other values"
)

// formatting Error() interface
const (
	ERR_FORMAT_DETAIL_SEP = ": "
)

// ------------------------------------------------
// Application (sbom-utility) error types
// ------------------------------------------------

type BaseError struct {
	Type       string
	Message    string
	InputFile  string
	InnerError error
	Command    string
	Flags      string
	Details    string
}

// Support the error interface
func (err BaseError) Error() string {
	formattedMessage := fmt.Sprintf("%s: %s (%s)", err.Type, err.Message, err.InputFile)
	if err.Details != "" {
		return fmt.Sprintf("%s: %s", formattedMessage, err.Details)
	}
	return formattedMessage
}

func (err *BaseError) AppendMessage(addendum string) {
	if addendum != "" {
		err.Message += addendum
	}
}

// NOTE: use for unsupported features/subfunctions etc.
// Used primarily for "patch" operation implementations currently
type UnsupportedError struct {
	BaseError
	Operation string
}

func NewUnsupportedError(op string, m string) *UnsupportedError {
	var err = new(UnsupportedError)
	err.Type = ERR_TYPE_UNSUPPORTED_OPERATION
	err.Operation = op
	err.Message = m
	return err
}

func (err UnsupportedError) Error() string {
	formattedMessage := fmt.Sprintf("%s (%s). %s", err.Type, err.Operation, err.Message)
	return formattedMessage
}

// IETF RFC6902 "Test" error
type IETFRFC6902TestError struct {
	BaseError
	Operation string
	Record    string
	Value     interface{}
}

func NewIETFRFC6902TestError(record string, value interface{}) *IETFRFC6902TestError {
	var err = new(IETFRFC6902TestError)
	err.Type = ERR_TYPE_IETF_RFC6902_TEST_FAILED
	err.Record = record
	err.Value = value
	err.Message = fmt.Sprintf("test record: %s, actual value: %v", err.Record, err.Value)
	return err
}

func (err IETFRFC6902TestError) Error() string {
	formattedMessage := fmt.Sprintf("%s. %s", err.Type, err.Message)
	return formattedMessage
}

// ------------------------------------------------
// SBOM error types
// ------------------------------------------------

// Extend the base error type
type InvalidSBOMError struct {
	BaseError
	SBOM         *schema.BOM
	FieldKeys    []string // Keys used to dereference into JSON map where error found
	SchemaErrors []gojsonschema.ResultError
}

// NOTE: Current sub-type is "no license found"; other, more specific subtypes may be created
type SBOMLicenseError struct {
	InvalidSBOMError
}

// Define more specific invalid SBOM errors
// type SBOMCompositionError struct {
// 	InvalidSBOMError
// }

// Define more specific invalid SBOM errors
// type SBOMMetadataError struct {
// 	InvalidSBOMError
// 	Metadata schema.CDXMetadata
// }

type ItemIsUniqueError struct {
	BaseError
	ActionId        string
	Selector        schema.ItemSelector
	NumMatchesFound int
}

func NewItemIsUniqueError(action schema.ValidationAction, numMatches int) *ItemIsUniqueError {
	var err = new(ItemIsUniqueError)
	err.Message = "item not unique"
	err.ActionId = action.Id
	err.Selector = action.Selector
	err.NumMatchesFound = numMatches
	return err
}

type ItemHasPropertiesError struct {
	BaseError
	ActionId         string
	Selector         schema.ItemSelector
	ExpectedProperty schema.ItemKeyValue
}

func NewItemHasPropertiesError(action schema.ValidationAction, missingProperty schema.ItemKeyValue) *ItemHasPropertiesError {
	var err = new(ItemHasPropertiesError)
	err.Message = "item not unique"
	err.ActionId = action.Id
	err.Selector = action.Selector
	err.ExpectedProperty = missingProperty
	return err
}

// type SBOMMetadataPropertyError struct {
// 	SBOMMetadataError
// 	Expected *schema.CustomValidationProperty
// 	Actual   []schema.CDXProperty
// }

func NewInvalidSBOMError(sbom *schema.BOM, m string, errIn error, schemaErrors []gojsonschema.ResultError) *InvalidSBOMError {
	var err = new(InvalidSBOMError)
	err.Type = ERR_TYPE_INVALID_SBOM
	err.Message = m
	err.InnerError = errIn
	err.SBOM = sbom
	if sbom != nil {
		err.InputFile = sbom.GetFilename()
	}
	err.SchemaErrors = schemaErrors
	return err
}

func NewSbomLicenseNotFoundError(sbom *schema.BOM) *SBOMLicenseError {
	var err = new(SBOMLicenseError)
	err.Type = ERR_TYPE_SBOM_LICENSE
	err.Message = MSG_LICENSES_NOT_FOUND
	err.SBOM = sbom
	if sbom != nil {
		err.InputFile = sbom.GetFilename()
	}
	return err
}

func NewSbomLicenseDataError() *SBOMLicenseError {
	var err = new(SBOMLicenseError)
	err.Type = ERR_TYPE_SBOM_LICENSE
	err.Message = MSG_LICENSE_INVALID_DATA
	return err
}

// func NewSBOMCompositionError(m string, sbom *schema.BOM, fields []string) *SBOMCompositionError {
// 	var err = new(SBOMCompositionError)
// 	err.Type = ERR_TYPE_SBOM_COMPOSITION
// 	err.Message = m
// 	err.FieldKeys = fields
// 	err.SBOM = sbom
// 	if sbom != nil {
// 		err.InputFile = sbom.GetFilename()
// 	}
// 	return err
// }

// TODO: create Error() (interface) method that displays CDXMetadata
// func NewSBOMMetadataError(sbom *schema.BOM, m string, metadata schema.CDXMetadata) *SBOMMetadataError {
// 	var err = new(SBOMMetadataError)
// 	err.Type = ERR_TYPE_SBOM_METADATA
// 	err.Message = m
// 	err.SBOM = sbom
// 	err.Metadata = metadata
// 	if sbom != nil {
// 		err.InputFile = sbom.GetFilename()
// 	}
// 	return err
// }

// TODO: create Error() (interface) method that displays CDXProperty
// func NewSbomMetadataPropertyError(sbom *schema.BOM, m string,
// 	expected *schema.CustomValidationProperty,
// 	values []schema.CDXProperty) *SBOMMetadataPropertyError {

// 	var err = new(SBOMMetadataPropertyError)
// 	err.Type = ERR_TYPE_SBOM_METADATA_PROPERTY
// 	err.Message = m
// 	err.SBOM = sbom
// 	if sbom != nil {
// 		err.InputFile = sbom.GetFilename()
// 	}
// 	err.Expected = expected
// 	err.Actual = values
// 	return err
// }

// Support the error interface
// func (err SBOMCompositionError) Error() string {
// 	text := err.BaseError.Error()
// 	return fmt.Sprintf("%s: Field(s): %s", text, strings.Join(err.FieldKeys[:], "."))
// }

// ------------------------------------------------
// Error type checks (for convenience)
// ------------------------------------------------

// NOTE: err = nil will also fail if error was expected
func ErrorTypesMatch(err error, expected error) bool {
	return reflect.TypeOf(err) == reflect.TypeOf(expected)
}

func IsInvalidBOMError(err error) bool {
	_, ok := err.(*InvalidSBOMError)
	return ok
}

func IsBOMLicenseError(err error) (*SBOMLicenseError, bool) {
	sbomErr, ok := err.(*SBOMLicenseError)
	return sbomErr, ok
}
