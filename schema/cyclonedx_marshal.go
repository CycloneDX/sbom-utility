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
)

// ------------------------
// Custom marshallers
// ------------------------

// recreate a representation of the struct, but only include values in map that are not empty
func (value *CDXLicenseChoice) MarshalJSON() ([]byte, error) {
	temp := map[string]interface{}{}
	if value.Expression != "" {
		temp["expression"] = value.Expression
	}

	// if the child struct is not "empty" we need to encode it as a map so to leverage the built-in
	// handling of the json encoding package
	if value.License != (CDXLicense{}) {
		// Marshal assumes a pointer
		bLicense, _ := json.Marshal(&value.License)
		m := make(map[string]string)
		json.Unmarshal(bLicense, &m)
		temp["license"] = m
	}
	// reuse built-in json encoder
	return json.Marshal(temp)
}

// recreate a representation of the struct, but only include values in map that are not empty
func (value *CDXLicense) MarshalJSON() ([]byte, error) {
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

	// if the child struct is not "empty" we need to encode it as a map so to leverage the built-in
	// handling of the json encoding package
	if value.Text != (CDXAttachment{}) {
		// Marshal assumes a pointer
		bText, _ := json.Marshal(&value.Text)
		m := make(map[string]string)
		json.Unmarshal(bText, &m)
		temp["text"] = m
	}
	// reuse built-in json encoder
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
	// reuse built-in json encoder
	return json.Marshal(temp)
}
