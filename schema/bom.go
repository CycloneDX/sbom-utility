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
	"io"
	"os"
	"path/filepath"
	"reflect"

	"github.com/CycloneDX/sbom-utility/utils"
	"github.com/jwangsadinata/go-multimap/slicemultimap"
)

// Candidate BOM document (context) information
type BOM struct {
	filename         string
	absFilename      string
	rawBytes         []byte
	JsonMap          map[string]interface{}
	FormatInfo       FormatSchema
	SchemaInfo       FormatSchemaInstance
	CdxBom           *CDXBom
	Statistics       *StatisticsInfo
	ResourceMap      *slicemultimap.MultiMap
	ComponentMap     *slicemultimap.MultiMap
	ServiceMap       *slicemultimap.MultiMap
	VulnerabilityMap *slicemultimap.MultiMap
	LicenseMap       *slicemultimap.MultiMap
}

const (
	COMPONENT_ID_NONE   = "None"
	COMPONENT_ID_NAME   = "name"
	COMPONENT_ID_BOMREF = "bom-ref"
	COMPONENT_ID_PURL   = "purl"
	COMPONENT_ID_CPE    = "cpe"
	COMPONENT_ID_SWID   = "swid"
)

type BOMComponentStats struct {
	Total          int
	MapIdentifiers map[string]int
	MapTypes       map[string]int
	MapMimeTypes   map[string]int
	// Number w/o licenses
	// Number not in dependency graph
}

const (
	SERVICE_ID_NONE   = "None"
	SERVICE_ID_BOMREF = "bom-ref"
)

type BOMServiceStats struct {
	Total        int
	MapEndpoints map[string]int // map["name"] len(endpoints)
	// Number Unauthenticated
	// Number w/o licenses
}

type BOMVulnerabilityStats struct {
	Total int
	// Number w/o mitigation or workaround or rejected
	MapSeverities map[string]int
}

type StatisticsInfo struct {
	ComponentStats     *BOMComponentStats
	ServiceStats       *BOMServiceStats
	VulnerabilityStats *BOMVulnerabilityStats
}

func (bom *BOM) GetRawBytes() []byte {
	return bom.rawBytes
}

func NewBOM(inputFile string) *BOM {
	temp := BOM{
		filename: inputFile,
	}

	// TODO: only allocate multi-maps when get() method (to be created) is called (on-demand)
	// NOTE: the CdxBom Map is allocated (i.e., using `make`) as part of `UnmarshalSBOM` method
	temp.ResourceMap = slicemultimap.New()
	temp.ComponentMap = slicemultimap.New()
	temp.ServiceMap = slicemultimap.New()
	temp.VulnerabilityMap = slicemultimap.New()
	temp.LicenseMap = slicemultimap.New()

	// Stats
	temp.Statistics = new(StatisticsInfo)
	temp.Statistics.ComponentStats = new(BOMComponentStats)

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

func (bom *BOM) GetCdxBom() (pCdxBom *CDXBom) {
	return bom.CdxBom
}

func (bom *BOM) GetCdxMetadata() (pMetadata *CDXMetadata) {
	if bom := bom.GetCdxBom(); bom != nil {
		pMetadata = bom.Metadata
	}
	return pMetadata
}

func (bom *BOM) GetCdxMetadataComponent() (pComponent *CDXComponent) {
	if metadata := bom.GetCdxMetadata(); metadata != nil {
		pComponent = metadata.Component
	}
	return pComponent
}

func (bom *BOM) GetCdxMetadataLicenses() (licenses *[]CDXLicenseChoice) {
	if metadata := bom.GetCdxMetadata(); metadata != nil {
		licenses = metadata.Licenses
	}
	return licenses
}

func (bom *BOM) GetCdxMetadataProperties() (pProperties *[]CDXProperty) {
	if metadata := bom.GetCdxMetadata(); metadata != nil {
		pProperties = metadata.Properties
	}
	return pProperties
}

func (bom *BOM) GetCdxComponents() (pComponents *[]CDXComponent) {
	if bom := bom.GetCdxBom(); bom != nil {
		pComponents = bom.Components
	}
	return pComponents
}

func (bom *BOM) GetCdxServices() (pServices *[]CDXService) {
	if bom := bom.GetCdxBom(); bom != nil {
		pServices = bom.Services
	}
	return pServices
}

func (bom *BOM) GetCdxProperties() (pProperties *[]CDXProperty) {
	if bom := bom.GetCdxBom(); bom != nil {
		pProperties = bom.Properties
	}
	return pProperties
}

func (bom *BOM) GetCdxExternalReferences() (pReferences *[]CDXExternalReference) {
	if bom := bom.GetCdxBom(); bom != nil {
		pReferences = bom.ExternalReferences
	}
	return pReferences
}

func (bom *BOM) GetCdxDependencies() (pDependencies *[]CDXDependency) {
	if bom := bom.GetCdxBom(); bom != nil {
		pDependencies = bom.Dependencies
	}
	return pDependencies
}

func (bom *BOM) GetCdxCompositions() (pCompositions *[]CDXCompositions) {
	if bom := bom.GetCdxBom(); bom != nil {
		pCompositions = bom.Compositions
	}
	return pCompositions
}

func (bom *BOM) GetCdxAnnotations() (pAnnotations *[]CDXAnnotation) {
	if bom := bom.GetCdxBom(); bom != nil {
		pAnnotations = bom.Annotations
	}
	return pAnnotations
}

func (bom *BOM) GetCdxFormula() (pFormula *[]CDXFormula) {
	if bom := bom.GetCdxBom(); bom != nil {
		pFormula = bom.Formulation
	}
	return pFormula
}

func (bom *BOM) GetCdxSignature() (pSignature *JSFSignature) {
	if bom := bom.GetCdxBom(); bom != nil {
		pSignature = bom.Signature
	}
	return pSignature
}

func (bom *BOM) GetCdxVulnerabilities() (pVulnerabilities *[]CDXVulnerability) {
	if bom := bom.GetCdxBom(); bom != nil {
		pVulnerabilities = bom.Vulnerabilities
	}
	return pVulnerabilities
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

func (bom *BOM) MarshalCycloneDXBOM(writer io.Writer, prefix string, indent string) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	var jsonBytes []byte
	jsonBytes, err = json.MarshalIndent(bom.CdxBom, prefix, indent)
	if err != nil {
		return
	}

	// TODO: Marshal escapes certain characters which is not desireable
	// the only alternative is to use an Encoder, but then we lose formatting/indent
	// TODO: unescape: \u0026 &, \u003c <, \u003e >
	// unescaped := bytes.Replace(jsonBytes, []byte("\u0026"), []byte("&"), -1)
	// unescaped = bytes.Replace(unescaped, []byte("\u003c"), []byte("<"), -1)
	// unescaped = bytes.Replace(unescaped, []byte("\u003e"), []byte(">"), -1)

	// write our opened jsonFile as a byte array.
	numBytes, errWrite := writer.Write(jsonBytes)
	if errWrite != nil {
		return errWrite
	}
	getLogger().Tracef("wrote [%v] bytes to output", numBytes)

	return
}
