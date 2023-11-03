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
	"reflect"
)

// --------------------------------------------------------------------------------
// Custom unmarshallers
// --------------------------------------------------------------------------------

// --------------------------------------
// UnMarshal from JSON
// --------------------------------------

func UnMarshalDocument(data interface{}) (*CDXBom, error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// we need to marshal the data to normalize it to a []byte
	jsonString, errMarshal := json.Marshal(data)

	if errMarshal != nil {
		return nil, errMarshal
	}

	// optimistically, prepare the receiving structure and unmarshal
	var bom CDXBom
	errUnmarshal := json.Unmarshal(jsonString, &bom)

	if errUnmarshal != nil {
		getLogger().Warningf("unmarshal failed: %v", errUnmarshal)
	}

	//getLogger().Tracef("\n%s", getLogger().FormatStruct(lc))
	return &bom, errUnmarshal
}

func UnMarshalMetadata(data interface{}) (CDXMetadata, error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// we need to marshal the data to normalize it to a []byte
	jsonString, errMarshal := json.Marshal(data)

	if errMarshal != nil {
		return CDXMetadata{}, errMarshal
	}

	// optimistically, prepare the receiving structure and unmarshal
	metadata := CDXMetadata{}
	errUnmarshal := json.Unmarshal(jsonString, &metadata)

	if errUnmarshal != nil {
		getLogger().Warningf("unmarshal failed: %v", errUnmarshal)
	}

	//getLogger().Tracef("\n%s", getLogger().FormatStruct(lc))
	return metadata, errUnmarshal
}

func UnMarshalLicenseChoice(data interface{}) (CDXLicenseChoice, error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// we need to marshal the data to normalize it to a []byte
	jsonString, errMarshal := json.Marshal(data)

	if errMarshal != nil {
		return CDXLicenseChoice{}, errMarshal
	}

	// optimistically, prepare the receiving structure and unmarshal
	lc := CDXLicenseChoice{}
	errUnmarshal := json.Unmarshal(jsonString, &lc)

	if errUnmarshal != nil {
		getLogger().Warningf("unmarshal failed: %v", errUnmarshal)
	}

	//getLogger().Tracef("\n%s", getLogger().FormatStruct(lc))
	return lc, errUnmarshal
}

func UnMarshalComponent(data interface{}) (CDXComponent, error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// we need to marshal the data to normalize it to a []byte
	jsonString, errMarshal := json.Marshal(data)

	if errMarshal != nil {
		return CDXComponent{}, errMarshal
	}

	// optimistically, prepare the receiving structure and unmarshal
	component := CDXComponent{}
	errUnmarshal := json.Unmarshal(jsonString, &component)

	if errUnmarshal != nil {
		getLogger().Warningf("unmarshal failed: %v", errUnmarshal)
	}

	//getLogger().Tracef("\n%s", getLogger().FormatStruct(component))
	return component, errUnmarshal
}

func UnMarshalComponents(data interface{}) ([]CDXComponent, error) {
	getLogger().Enter()
	defer getLogger().Exit()

	var components []CDXComponent

	// we need to marshal the data to normalize it to a []byte
	jsonString, errMarshal := json.Marshal(data)
	if errMarshal != nil {
		return components, errMarshal
	}

	// unmarshal into custom structure
	errUnmarshal := json.Unmarshal(jsonString, &components)
	if errUnmarshal != nil {
		getLogger().Warningf("unmarshal failed: %v", errUnmarshal)
	}

	return components, errUnmarshal
}

func UnMarshalProperties(data interface{}) (properties []CDXProperty, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// we need to marshal the data to normalize it to a []byte
	jsonString, err := json.Marshal(data)
	if err != nil {
		return
	}

	// unmarshal into custom structure
	err = json.Unmarshal(jsonString, &properties)
	if err != nil {
		getLogger().Warningf("unmarshal failed: %v", err)
	}

	return
}

func UnMarshalProperty(data interface{}) (property CDXProperty, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// we need to marshal the data to normalize it to a []byte
	jsonString, err := json.Marshal(data)
	if err != nil {
		return
	}

	// unmarshal into custom structure
	err = json.Unmarshal(jsonString, &property)
	if err != nil {
		getLogger().Warningf("unmarshal failed: %v", err)
	}

	return
}

// --------------------------------------
// Utils
// --------------------------------------

func (property *CDXProperty) Equals(testProperty CDXProperty) bool {
	return reflect.DeepEqual(*property, testProperty)
}
