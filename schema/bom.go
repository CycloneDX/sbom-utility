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
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"

	"github.com/CycloneDX/sbom-utility/common"
	"github.com/CycloneDX/sbom-utility/utils"
	"github.com/jwangsadinata/go-multimap/slicemultimap"
)

// Candidate BOM document (context) information
type BOM struct {
	filename     string
	absFilename  string
	rawBytes     []byte
	JsonMap      map[string]interface{}
	FormatInfo   FormatSchema
	SchemaInfo   FormatSchemaInstance
	CdxBom       *CDXBom
	ResourceMap  *slicemultimap.MultiMap
	componentMap *slicemultimap.MultiMap
	serviceMap   *slicemultimap.MultiMap
}

func (bom *BOM) GetRawBytes() []byte {
	return bom.rawBytes
}

func NewBOM(inputFile string) *BOM {
	temp := BOM{
		filename: inputFile,
	}

	temp.ResourceMap = slicemultimap.New()
	// NOTE: the Map is allocated (i.e., using `make`) as part of `UnmarshalSBOM` method
	return &temp
}

func (bom *BOM) GetFilename() string {
	return bom.filename
}

func (bom *BOM) GetFilenameInterpolated() string {

	if bom.filename == INPUT_TYPE_STDIN {
		return "stdin"
	}
	return bom.filename
}

func (bom *BOM) GetJSONMap() map[string]interface{} {
	return bom.JsonMap
}

func (bom *BOM) GetCdxBom() (cdxBom *CDXBom) {
	return bom.CdxBom
}

func (bom *BOM) GetCdxMetadata() (metadata *CDXMetadata) {
	if bom := bom.GetCdxBom(); bom != nil {
		metadata = bom.Metadata
	}
	return metadata
}

func (bom *BOM) GetCdxMetadataProperties() (properties []CDXProperty) {
	if metadata := bom.GetCdxMetadata(); metadata != nil {
		properties = metadata.Properties
	}
	return properties
}

func (bom *BOM) GetCdxComponents() (components []CDXComponent) {
	if bom := bom.GetCdxBom(); bom != nil {
		if bom.Components != nil {
			components = *bom.Components
		} //else {
		//			fmt.Printf("[WARN: bom.Components=`%v`\n", bom.Components)
		//		}
	}
	return components
}

func (bom *BOM) GetCdxServices() (services []CDXService) {
	if bom := bom.GetCdxBom(); bom != nil {
		if bom.Services != nil {
			services = *bom.Services
		} //else {
		//			fmt.Printf("[WARN: bom.Services=`%v`\n", bom.Services)
		//		}
	}
	return services
}

func (bom *BOM) GetCdxMetadataComponent() (component *CDXComponent) {
	if metadata := bom.GetCdxMetadata(); metadata != nil {
		component = &metadata.Component
	}
	return component
}

func (bom *BOM) GetCdxMetadataLicenses() (licenses []CDXLicenseChoice) {
	if metadata := bom.GetCdxMetadata(); metadata != nil {
		licenses = metadata.Licenses
	}
	return licenses
}

func (bom *BOM) GetCdxVulnerabilities() (vulnerabilities []CDXVulnerability) {
	if bom := bom.GetCdxBom(); bom != nil {
		vulnerabilities = bom.Vulnerabilities
	}
	return vulnerabilities
}

func (bom *BOM) GetKeyValueAsString(key string) (sValue string, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	getLogger().Tracef("key: `%s`", key)

	if (bom.JsonMap) == nil {
		err := fmt.Errorf("document object does not have a Map allocated")
		getLogger().Error(err)
		return "", err
	}
	value := bom.JsonMap[key]

	if value == nil {
		getLogger().Tracef("key: `%s` not found in document map", key)
		return "", nil
	}

	getLogger().Tracef("value: `%v` (%T)", value, value)
	return value.(string), nil
}

func (bom *BOM) UnmarshalBOMAsJSONMap() (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// validate filename
	if len(bom.filename) == 0 {
		return fmt.Errorf("schema: invalid BOM filename: `%s`", bom.filename)
	}

	// Check to see of stdin is the BOM source data
	if bom.filename == INPUT_TYPE_STDIN {
		bom.rawBytes, err = io.ReadAll(os.Stdin)
		if err != nil {
			return
		}
	} else { // load the BOM data from relative filename
		// Conditionally append working directory if no abs. path detected
		if len(bom.filename) > 0 && !filepath.IsAbs(bom.filename) {
			bom.absFilename = filepath.Join(utils.GlobalFlags.WorkingDir, bom.filename)
		} else {
			bom.absFilename = bom.filename
		}

		// Open our jsonFile
		jsonFile, errOpen := os.Open(bom.absFilename)

		// if input file cannot be opened, log it and terminate
		if errOpen != nil {
			getLogger().Error(errOpen)
			return errOpen
		}

		// defer the closing of our jsonFile
		defer jsonFile.Close()

		// read our opened jsonFile as a byte array.
		var errReadAll error
		bom.rawBytes, errReadAll = io.ReadAll(jsonFile)
		if errReadAll != nil {
			getLogger().Error(errReadAll)
		}
	}

	getLogger().Tracef("read data from: `%s`", bom.filename)
	getLogger().Tracef("\n  >> rawBytes[:100]=[%s]", bom.rawBytes[:100])

	// Attempt to unmarshal the prospective JSON document to a map
	bom.JsonMap = make(map[string]interface{})
	errUnmarshal := json.Unmarshal(bom.rawBytes, &(bom.JsonMap))
	if errUnmarshal != nil {
		getLogger().Trace(errUnmarshal)
		if syntaxError, ok := errUnmarshal.(*json.SyntaxError); ok {
			line, character := CalcLineAndCharacterPos(bom.rawBytes, syntaxError.Offset)
			getLogger().Tracef("syntax error found at line,char=[%d,%d]", line, character)
		}
		return errUnmarshal
	}

	// Print the data type of result variable
	getLogger().Tracef("bom.jsonMap(%s)", reflect.TypeOf(bom.JsonMap))

	return nil
}

func (bom *BOM) UnmarshalCycloneDXBOM() (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Unmarshal as a JSON Map if not done already
	if bom.JsonMap == nil {
		if err = bom.UnmarshalBOMAsJSONMap(); err != nil {
			return
		}
	}

	// Use the JSON Map to unmarshal to CDX-specific types
	bom.CdxBom, err = UnMarshalDocument(bom.JsonMap)
	if err != nil {
		return
	}

	return
}

// This hashes all components regardless where in the BOM document structure
// they are declared.  This includes both the top-level metadata component
// (i.e., the subject of the BOM) as well as the components array.
func (bom *BOM) HashComponentResources(whereFilters []common.WhereFilter) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	// Hash the top-level component declared in the BOM metadata
	_, err = bom.HashComponent(*bom.GetCdxMetadataComponent(), whereFilters, true)
	if err != nil {
		return
	}

	// Hash all components found in the (root).components[] (+ "nested" components)
	if components := bom.GetCdxComponents(); len(components) > 0 {
		if err = bom.HashComponents(components, whereFilters, false); err != nil {
			return
		}
	}
	return
}

func (bom *BOM) HashComponents(components []CDXComponent, whereFilters []common.WhereFilter, root bool) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)
	for _, cdxComponent := range components {
		_, err = bom.HashComponent(cdxComponent, whereFilters, root)
		if err != nil {
			return
		}
	}
	return
}

// Hash a CDX Component and recursively those of any "nested" components
// TODO we should WARN if version is not a valid semver (e.g., examples/cyclonedx/BOM/laravel-7.12.0/bom.1.3.json)
func (bom *BOM) HashComponent(cdxComponent CDXComponent, whereFilters []common.WhereFilter, root bool) (ri *CDXResourceInfo, err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)
	var resourceInfo CDXResourceInfo
	ri = &resourceInfo

	if reflect.DeepEqual(cdxComponent, CDXComponent{}) {
		getLogger().Errorf("invalid component: missing or empty : %v ", cdxComponent)
		return
	}

	if cdxComponent.Name == "" {
		getLogger().Errorf("component missing required value `name` : %v ", cdxComponent)
	}

	if cdxComponent.Version == "" {
		getLogger().Warningf("component named `%s` missing `version`", cdxComponent.Name)
	}

	if cdxComponent.BOMRef == "" {
		getLogger().Warningf("component named `%s` missing `bom-ref`", cdxComponent.Name)
	}

	// hash any component w/o a license using special key name
	resourceInfo.IsRoot = root
	resourceInfo.Type = RESOURCE_TYPE_COMPONENT
	resourceInfo.Component = cdxComponent
	resourceInfo.Name = cdxComponent.Name
	resourceInfo.BOMRef = cdxComponent.BOMRef.String()
	resourceInfo.Version = cdxComponent.Version
	resourceInfo.SupplierProvider = cdxComponent.Supplier
	resourceInfo.Properties = cdxComponent.Properties

	var match bool = true
	if len(whereFilters) > 0 {
		mapResourceInfo, _ := utils.ConvertStructToMap(resourceInfo)
		match, _ = whereFilterMatch(mapResourceInfo, whereFilters)
	}

	if match {
		bom.ResourceMap.Put(resourceInfo.BOMRef, resourceInfo)

		getLogger().Tracef("Put: %s (`%s`), `%s`)",
			resourceInfo.Name,
			resourceInfo.Version,
			resourceInfo.BOMRef)
	}

	// Recursively hash licenses for all child components (i.e., hierarchical composition)
	if len(cdxComponent.Components) > 0 {
		err = bom.HashComponents(cdxComponent.Components, whereFilters, root)
		if err != nil {
			return
		}
	}
	return
}

// Note: Golang supports the RE2 regular exp. engine which does not support many
// features such as lookahead, lookbehind, etc.
// See: https://en.wikipedia.org/wiki/Comparison_of_regular_expression_engines
func whereFilterMatch(mapObject map[string]interface{}, whereFilters []common.WhereFilter) (match bool, err error) {
	var buf bytes.Buffer
	var key string

	// create a byte encoder
	enc := gob.NewEncoder(&buf)

	for _, filter := range whereFilters {

		key = filter.Key
		value, present := mapObject[key]
		getLogger().Debugf("testing object map[%s]: `%v`", key, value)

		if !present {
			match = false
			err = getLogger().Errorf("key `%s` not found ib object map", key)
			break
		}

		// Reset the encoder'a byte buffer on each iteration and
		// convert the value (an interface{}) to []byte we can use on regex. eval.
		buf.Reset()

		// Do not encode nil pointer values; replace with empty string
		if value == nil {
			value = ""
		}

		// Handle non-string data types in the map by converting them to string
		switch data := value.(type) {
		case bool:
			value = strconv.FormatBool(data)
		case int:
			value = strconv.Itoa(data)
		}

		err = enc.Encode(value)

		if err != nil {
			err = getLogger().Errorf("Unable to convert value: `%v`, to []byte", value)
			return
		}

		// Test that the field value matches the regex supplied in the current filter
		// Note: the regex compilation is performed during command param. processing
		if match = filter.ValueRegEx.Match(buf.Bytes()); !match {
			break
		}
	}

	return
}
