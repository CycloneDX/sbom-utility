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
	"encoding/json"
	"reflect"
)

func IsInterfaceASlice(testValue interface{}) bool {
	if testValue != nil {
		if reflect.TypeOf(testValue).Kind() == reflect.Slice {
			return true
		}
	}
	return false
}

// --------------------------------------------------------------------------------
// Custom marshallers
// --------------------------------------------------------------------------------
// Objective:
// - Recreate a representation of the struct, but only include values in map
//   that are not empty.  Custom marshallers are needed as Golang does not
//   check if child structs are empty or not.  This is because they themselves
//   are complex types that do not have a a single empty value (e.g., ["", 0,], etc.).
// Note:
// - Custom marshallers do NOT take into account validity of struct fields
//   according to schema constraints (i.e., "OneOf", "AnyOf").  This means
//   all struct fields are marshalled regardless of such constraints.
// --------------------------------------------------------------------------------

var BYTE_ENCODED_ZERO_STRUCT = []byte("{}")
var ENCODED_EMPTY_SLICE_OF_STRUCT = []byte("[{}]")

// --------------------------
// CDXLicenseChoice structs
// --------------------------

func (value *CDXLicenseChoice) MarshalJSON() (marshalled []byte, err error) {
	temp := map[string]interface{}{}
	if value.Expression != "" {
		temp["expression"] = value.Expression
	}

	if !reflect.ValueOf(value.License).IsZero() {
		temp["license"] = value.License
	}

	return json.Marshal(temp)
}

// recreate a representation of the struct, but only include values in map that are not empty
func (value *CDXLicense) MarshalJSON() (bytes []byte, err error) {
	temp := map[string]interface{}{}
	if value.Id != "" {
		temp["id"] = value.Id
	}

	if value.Name != "" {
		temp["name"] = value.Name
	}

	if value.Url != "" {
		temp["url"] = value.Url
	}

	// CDXAttachment
	if !reflect.ValueOf(value.Text).IsZero() {
		temp["text"] = value.Text
	}

	// v1.5 properties follow:
	if value.BOMRef != nil && *value.BOMRef != "" {
		temp["bom-ref"] = value.BOMRef
	}

	if value.Properties != nil && len(*value.Properties) > 0 {
		temp["properties"] = value.Properties
	}

	if value.Licensing != nil {
		temp["licensing"] = value.Licensing
	}

	return json.Marshal(temp)
}

// recreate a representation of the struct, but only include values in map that are not empty
func (value *CDXAttachment) MarshalJSON() ([]byte, error) {
	temp := map[string]interface{}{}
	if value.ContentType != "" {
		temp["contentType"] = value.ContentType
	}

	if value.Encoding != "" {
		temp["encoding"] = value.Encoding
	}

	if value.Content != "" {
		temp["content"] = value.Content
	}
	// reuse built-in json encoder, which accepts a map primitive
	return json.Marshal(temp)
}

// --------------------------
// CDXVulnerability structs
// --------------------------

// recreate a representation of the struct, but only include values in map that are not empty
func (value *CDXVulnerability) MarshalJSON() ([]byte, error) {
	var testEmpty []byte
	temp := map[string]interface{}{}

	if value.BOMRef != nil && *value.BOMRef != "" {
		temp["bom-ref"] = value.BOMRef
	}

	if value.Id != "" {
		temp["id"] = value.Id
	}

	if value.Description != "" {
		temp["description"] = value.Description
	}

	if value.Detail != "" {
		temp["detail"] = value.Detail
	}

	if value.Recommendation != "" {
		temp["recommendation"] = value.Recommendation
	}

	if value.Created != "" {
		temp["created"] = value.Created
	}

	if value.Published != "" {
		temp["published"] = value.Published
	}

	if value.Updated != "" {
		temp["updated"] = value.Updated
	}

	// CDXVulnerabilitySource
	if value.Source != nil {
		testEmpty, _ = json.Marshal(value.Source)
		if !bytes.Equal(testEmpty, BYTE_ENCODED_ZERO_STRUCT) {
			temp["source"] = value.Source
		}
	}

	// CDXCredit (anon. type)
	if value.Credits != nil {
		testEmpty, _ = json.Marshal(value.Credits)
		if !bytes.Equal(testEmpty, BYTE_ENCODED_ZERO_STRUCT) {
			temp["credits"] = value.Credits
		}
	}

	// CDXAnalysis (anon. type)
	if value.Analysis != nil {
		testEmpty, _ = json.Marshal(value.Analysis)
		if !bytes.Equal(testEmpty, BYTE_ENCODED_ZERO_STRUCT) {
			temp["analysis"] = value.Analysis
		}
	}

	// CDXAffects
	if value.Affects != nil && len(*value.Affects) > 0 {
		testEmpty, _ = json.Marshal(value.Affects)
		if !bytes.Equal(testEmpty, ENCODED_EMPTY_SLICE_OF_STRUCT) {
			temp["affects"] = value.Affects
		}
	}

	if value.References != nil && len(*value.References) > 0 {
		temp["references"] = value.References
	}

	if value.Ratings != nil && len(*value.Ratings) > 0 {
		temp["ratings"] = value.Ratings
	}

	if value.Advisories != nil && len(*value.Advisories) > 0 {
		temp["advisories"] = value.Advisories
	}

	if value.Cwes != nil && len(*value.Cwes) > 0 {
		temp["cwes"] = value.Cwes
	}

	// v1.5 allows tools to be either an array of (legacy) tool object or a new tool object
	// TODO: author test for legacy (array) object vs. new tool object
	if IsInterfaceASlice(value.Tools) {
		arrayTools, ok := value.Tools.([]CDXLegacyCreationTool)
		if ok && len(arrayTools) > 0 {
			temp["tools"] = arrayTools
		}
	} else {
		tools, ok := value.Tools.(CDXCreationTools)
		if ok {
			temp["tools"] = tools
		}
	}

	if value.Properties != nil && len(*value.Properties) > 0 {
		temp["properties"] = value.Properties
	}

	// v1.5 properties follow
	if value.Rejected != "" {
		temp["rejected"] = value.Rejected
	}

	// reuse built-in json encoder, which accepts a map primitive
	return json.Marshal(temp)
}

func (value *CDXVulnerabilityReference) MarshalJSON() ([]byte, error) {
	temp := map[string]interface{}{}
	if len(value.Id) > 0 {
		temp["id"] = value.Id
	}
	if value.Source != nil && *value.Source != (CDXVulnerabilitySource{}) {
		temp["source"] = value.Source
	}
	// reuse built-in json encoder, which accepts a map primitive
	return json.Marshal(temp)
}

func (value *CDXVulnerabilitySource) MarshalJSON() ([]byte, error) {
	temp := map[string]interface{}{}
	if len(value.Url) > 0 {
		temp["url"] = value.Url
	}
	if len(value.Name) > 0 {
		temp["name"] = value.Name
	}
	// reuse built-in json encoder, which accepts a map primitive
	return json.Marshal(temp)
}

func (value *CDXCredit) MarshalJSON() ([]byte, error) {
	temp := map[string]interface{}{}
	if value.Individuals != nil && len(*value.Individuals) > 0 {
		temp["individuals"] = value.Individuals
	}
	if value.Organizations != nil && len(*value.Organizations) > 0 {
		temp["organizations"] = value.Organizations
	}
	if len(temp) == 0 {
		return BYTE_ENCODED_ZERO_STRUCT, nil
	}
	// reuse built-in json encoder, which accepts a map primitive
	return json.Marshal(temp)
}

func (value *CDXAffect) MarshalJSON() ([]byte, error) {
	temp := map[string]interface{}{}
	if value.Versions != nil && len(*value.Versions) > 0 {
		temp["versions"] = value.Versions
	}
	if len(temp) == 0 {
		return BYTE_ENCODED_ZERO_STRUCT, nil
	}
	// reuse built-in json encoder, which accepts a map primitive
	return json.Marshal(temp)
}

//	type CDXOrganizationalEntity struct {
//		Name    string                      `json:"name,omitempty"`
//		Url     []string                    `json:"url,omitempty"`
//		Contact *[]CDXOrganizationalContact `json:"contact,omitempty"`
//		BOMRef  *CDXRefType                 `json:"bom-ref,omitempty"` // v1.5 added
//	}
func (value *CDXOrganizationalEntity) MarshalJSON() ([]byte, error) {
	temp := map[string]interface{}{}
	if value.Name != "" {
		temp["name"] = value.Name
	}
	if len(value.Url) > 0 {
		temp["url"] = value.Url
	}
	if value.Contact != nil && len(*value.Contact) > 0 {
		temp["contact"] = value.Contact
	}
	if value.BOMRef != nil && *value.BOMRef != "" {
		temp["bom-ref"] = value.BOMRef
	}
	if len(temp) == 0 {
		return BYTE_ENCODED_ZERO_STRUCT, nil
	}
	// reuse built-in json encoder, which accepts a map primitive
	return json.Marshal(temp)
}

//	type CDXOrganizationalContact struct {
//		Name   string      `json:"name,omitempty"`
//		Email  string      `json:"email,omitempty"`
//		Phone  string      `json:"phone,omitempty"`
//		BOMRef *CDXRefType `json:"bom-ref,omitempty"` // v1.5 added
//	}
func (value *CDXOrganizationalContact) MarshalJSON() ([]byte, error) {
	temp := map[string]interface{}{}
	if value.Name != "" {
		temp["name"] = value.Name
	}
	if value.Email != "" {
		temp["email"] = value.Email
	}
	if value.Phone != "" {
		temp["phone"] = value.Phone
	}
	if value.BOMRef != nil && *value.BOMRef != "" {
		temp["bom-ref"] = value.BOMRef
	}
	if len(temp) == 0 {
		return BYTE_ENCODED_ZERO_STRUCT, nil
	}
	// reuse built-in json encoder, which accepts a map primitive
	return json.Marshal(temp)
}
