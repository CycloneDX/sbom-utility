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
)

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

var ENCODED_EMPTY_STRUCT = []byte("{}")

// --------------------------
// CDXLicenseChoice structs
// --------------------------
func (value *CDXLicenseChoice) MarshalJSON1() (bytes []byte, err error) {
	temp := map[string]interface{}{}
	if value.Expression != "" {
		temp["expression"] = value.Expression
	}

	// if the child struct is not "empty" we need to encode it as a map so to leverage the built-in
	// handling of the json encoding package
	if value.License != (CDXLicense{}) {
		var bData []byte
		bData, err = json.Marshal(&value.License)
		if err != nil {
			return
		}

		m := make(map[string]interface{})
		err = json.Unmarshal(bData, &m)
		if err != nil {
			getLogger().Warningf("Unmarshal error: %s", err)
			return
		}
		temp["license"] = m
	}
	// reuse built-in json encoder, which accepts a map primitive
	return json.Marshal(temp)
}

func (value *CDXLicenseChoice) MarshalJSON() (marshalled []byte, err error) {
	temp := map[string]interface{}{}
	if value.Expression != "" {
		temp["expression"] = value.Expression
	}

	if value.License != (CDXLicense{}) {
		temp["license"] = &value.License
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

	if value.Text != (CDXAttachment{}) {
		temp["text"] = &value.Text
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
	temp := map[string]interface{}{}

	if value.BomRef != "" {
		temp["bom-ref"] = value.BomRef
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

	// Source CDXVulnerabilitySource `json:"source,omitempty"`
	if value.Source != (CDXVulnerabilitySource{}) {
		temp["source"] = &value.Source
	}

	// Credits CDXCredit `json:"credits,omitempty"` // anon. type
	testEmpty, _ := json.Marshal(&value.Credits)
	if !bytes.Equal(testEmpty, ENCODED_EMPTY_STRUCT) {
		temp["credits"] = &value.Credits
	}

	// Analysis CDXAnalysis `json:"analysis,omitempty"` // anon. type
	// TODO: WARNING: This simple compare will not work if child struct has []string
	testEmpty, _ = json.Marshal(&value.Analysis)
	if !bytes.Equal(testEmpty, ENCODED_EMPTY_STRUCT) {
		temp["analysis"] = &value.Analysis
	}

	if len(value.References) > 0 {
		temp["references"] = &value.References
	}

	if len(value.Ratings) > 0 {
		temp["ratings"] = &value.Ratings
	}

	if len(value.Advisories) > 0 {
		temp["advisories"] = &value.Advisories
	}

	if len(value.Cwes) > 0 {
		temp["cwes"] = &value.Cwes
	}

	if len(value.Tools) > 0 {
		temp["tools"] = &value.Tools
	}

	if len(value.Affects) > 0 {
		temp["affects"] = &value.Affects
	}

	if len(value.Properties) > 0 {
		temp["properties"] = &value.Properties
	}

	// v1.5 properties follow
	if value.Rejected != "" {
		temp["rejected"] = value.Rejected
	}

	// reuse built-in json encoder, which accepts a map primitive
	return json.Marshal(temp)
}

func (value *CDXReference) MarshalJSON() ([]byte, error) {
	temp := map[string]interface{}{}
	if len(value.Id) > 0 {
		temp["id"] = &value.Id
	}
	if value.Source != (CDXVulnerabilitySource{}) {
		temp["source"] = &value.Source
	}
	// reuse built-in json encoder, which accepts a map primitive
	return json.Marshal(temp)
}

func (value *CDXVulnerabilitySource) MarshalJSON() ([]byte, error) {
	temp := map[string]interface{}{}
	if len(value.Url) > 0 {
		temp["url"] = &value.Url
	}
	if len(value.Name) > 0 {
		temp["name"] = &value.Name
	}
	// reuse built-in json encoder, which accepts a map primitive
	return json.Marshal(temp)
}

func (value *CDXCredit) MarshalJSON() ([]byte, error) {
	temp := map[string]interface{}{}
	if len(value.Individuals) > 0 {
		temp["individuals"] = &value.Individuals
	}
	if len(value.Organizations) > 0 {
		temp["organizations"] = &value.Organizations
	}
	if len(temp) == 0 {
		return ENCODED_EMPTY_STRUCT, nil
	}
	// reuse built-in json encoder, which accepts a map primitive
	return json.Marshal(temp)
}
