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
	"crypto/sha256"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"

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
	GobDecodeBuffer  bytes.Buffer
	GobEncodeBuffer  bytes.Buffer
	GobDecoder       *gob.Decoder
	GobEncoder       *gob.Encoder
}

const (
	COMPONENT_ID_NONE   = "None"
	COMPONENT_ID_NAME   = "name"
	COMPONENT_ID_BOMREF = "bom-ref"
	COMPONENT_ID_PURL   = "purl"
	COMPONENT_ID_CPE    = "cpe"
	COMPONENT_ID_SWID   = "swid"
)

const (
	SERVICE_ID_NONE   = "None"
	SERVICE_ID_BOMREF = "bom-ref"
)

// Note: the SPDX spec. does not provide regex for an SPDX ID, but provides the following in ABNF:
//
//	string = 1*(ALPHA / DIGIT / "-" / "." )
//
// Currently, the regex below tests composition of of only
// alphanum, "-", and "." characters and disallows empty strings
// TODO:
//   - First and last chars are not "-" or "."
//   - Enforce reasonable min/max lengths
//     In theory, we can check overall length with positive lookahead
//     (e.g., min 3 max 128):  (?=.{3,128}$)
//     However, this does not appear to be supported in `regexp` package
//     or perhaps it must be a compiled expression TBD
const (
	REGEX_VALID_SPDX_ID = "^[a-zA-Z0-9.-]+$"
)

// compiled regexp. to save time
var spdxIdRegexp *regexp.Regexp

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

	// Create a GOB Encoder/Decoder
	temp.GobDecoder = gob.NewDecoder(&temp.GobDecodeBuffer)
	temp.GobEncoder = gob.NewEncoder(&temp.GobEncodeBuffer)

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
	return
}

func (bom *BOM) GetCdxMetadataComponent() (pComponent *CDXComponent) {
	if metadata := bom.GetCdxMetadata(); metadata != nil {
		pComponent = metadata.Component
	}
	return
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

	getLogger().Tracef("key: '%s'", key)

	if (bom.JsonMap) == nil {
		err := fmt.Errorf("document object does not have a Map allocated")
		getLogger().Error(err)
		return "", err
	}

	value := bom.JsonMap[key]
	if value == nil {
		getLogger().Tracef("key: '%s' not found in document map", key)
		return "", nil
	}

	getLogger().Tracef("value: '%v' (%T)", value, value)
	return value.(string), nil
}

func (bom *BOM) ReadRawBytes() (err error) {
	// validate filename
	if len(bom.filename) == 0 {
		return fmt.Errorf("schema: invalid filename: '%s'", bom.filename)
	}

	// Check to see of stdin is the BOM source data
	if bom.filename == INPUT_TYPE_STDIN {
		if bom.rawBytes, err = io.ReadAll(os.Stdin); err != nil {
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
		var jsonFile *os.File
		if jsonFile, err = os.Open(bom.absFilename); err != nil {
			return
		}

		// defer the closing of our jsonFile
		defer jsonFile.Close()

		// read our opened jsonFile as a byte array.
		if bom.rawBytes, err = io.ReadAll(jsonFile); err != nil {
			return
		}
	}

	getLogger().Tracef("read data from: '%s'", bom.filename)
	getLogger().Tracef("\n  >> rawBytes[:100]=[%s]", bom.rawBytes[:100])
	return
}

func (bom *BOM) UnmarshalBOMAsJSONMap() (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	if err = bom.ReadRawBytes(); err != nil {
		return
	}

	// Attempt to unmarshal the prospective JSON document to a map
	bom.JsonMap = make(map[string]interface{})
	errUnmarshal := json.Unmarshal(bom.rawBytes, &(bom.JsonMap))
	if errUnmarshal != nil {
		getLogger().Trace(errUnmarshal)
		if syntaxError, ok := errUnmarshal.(*json.SyntaxError); ok {
			line, character := utils.CalcLineAndCharacterPos(bom.rawBytes, syntaxError.Offset)
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

	// Unmarshal as a JSON Map, if not done already
	if bom.JsonMap == nil {
		if err = bom.UnmarshalBOMAsJSONMap(); err != nil {
			return
		}
	}

	// Use the JSON Map to unmarshal to CDX-specific types
	if bom.CdxBom, err = UnMarshalDocument(bom.JsonMap); err != nil {
		return
	}

	return
}

// NOTE: This method uses JSON Marshal() (i.e, from the json/encoding package)
// which, by default, encodes characters using Unicode for HTML transmission
// (assuming its primary use is for HTML servers).
// For example, this means the following characters are translated to Unicode
// if marshall() method is used:
// '&' is encoded as: \u0026
// '<' is encoded as: \u003c
// '>' is encoded as: \u003e
func (bom *BOM) MarshalCycloneDXBOM(writer io.Writer, prefix string, indent string) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	var jsonBytes []byte
	jsonBytes, err = json.MarshalIndent(bom.CdxBom, prefix, indent)
	if err != nil {
		return
	}

	numBytes, errWrite := writer.Write(jsonBytes)
	if errWrite != nil {
		return errWrite
	}
	getLogger().Tracef("wrote [%v] bytes to output", numBytes)

	return
}

// This method ensures the preservation of original characters (after any edits)
//
// It is needed because JSON Marshal() (i.e., the json/encoding package), by default,
// encodes chars (assumes JSON docs are being transmitted over HTML streams).
// This assumption by json/encoding is not true for BOM documents as stream (wire)
// transmission encodings are specified for both formats which do not use HTML encoding.
//
// For example, the following characters are lost using json/encoding:
// '&' is encoded as: \u0026
// '<' is encoded as: \u003c
// '>' is encoded as: \u003e
// Instead, this custom encoder method dutifully preserves the input byte values
// TODO: Support "--prefix string"; prefix parameter currently ignored
func (bom *BOM) WriteAsEncodedJSON(writer io.Writer, prefix string, indent string) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	var outputBuffer bytes.Buffer
	outputBuffer, err = utils.EncodeAnyToIndentedJSONStr(bom.CdxBom, indent)
	if err != nil {
		return
	}

	numBytes, errWrite := writer.Write(outputBuffer.Bytes())
	if errWrite != nil {
		return errWrite
	}
	getLogger().Tracef("wrote [%v] bytes to output", numBytes)

	return
}

func (bom *BOM) WriteAsEncodedJSONInt(writer io.Writer, numSpaces int) (err error) {
	_, err = utils.WriteAnyAsEncodedJSONInt(writer, bom.CdxBom, numSpaces)
	return
}

// Approach 1
func (bom *BOM) HashEntity(entity interface{}) (sha string) {
	bom.GobEncoder.Encode(entity)
	sha256 := sha256.Sum256(bom.GobEncodeBuffer.Bytes())
	return fmt.Sprintf("%x\n", sha256)
}

func (bom *BOM) HashJsonMap(entity interface{}) (sha string, err error) {
	bom.GobEncoder.Encode(entity)

	// Verify entity is a JSON map type
	if !utils.IsJsonMapType(entity) {
		err = fmt.Errorf("invalid type. Cannot hash non-struct type (%T)", entity)
		return
	}

	sha = bom.HashEntity(entity)
	return
}

func (bom *BOM) HashStruct(entity interface{}) (sha string, err error) {
	bom.GobEncoder.Encode(entity)

	// Verify entity is a Go struct type
	kind := reflect.ValueOf(entity).Kind()
	if kind != reflect.Struct {
		err = fmt.Errorf("invalid type. Cannot hash non-struct type (%T); kind: %v", entity, kind)
		return
	}

	sha = bom.HashEntity(entity)
	return
}

// Approach 2
// NOTE: Not yet needed
// TODO: allow multiple "writes" of a slice of entities
// func (bom *BOM) HashEntities(entities []interface{}) (sha []byte, err error) {

// 	bom.GobEncoder.Encode(entities)
// 	hasher := sha256.New()
// 	hasher.Write(bom.GobEncodeBuffer.Bytes())
// 	fmt.Printf("%x\n", hasher.Sum(nil))
// 	return
// }
