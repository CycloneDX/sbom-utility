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

	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/CycloneDX/sbom-utility/utils"
)

func LoadInputBOMFileAndDetectSchema() (document *schema.BOM, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	inputFile := utils.GlobalFlags.PersistentFlags.InputFile

	// check for required fields on command
	getLogger().Tracef("utils.Flags.InputFile: '%s'", inputFile)
	if inputFile == "" {
		return nil, fmt.Errorf("invalid input file (-%s): '%s' ", FLAG_FILENAME_INPUT_SHORT, inputFile)
	}

	// Construct a BOM document object around the input file
	document = schema.NewBOM(inputFile)

	// Load the raw, candidate BOM (file) as JSON data
	getLogger().Infof("Attempting to load and unmarshal data from: '%s'...", document.GetFilenameInterpolated())
	err = document.UnmarshalBOMAsJSONMap() // i.e., utils.Flags.InputFile
	if err != nil {
		return
	}
	getLogger().Infof("Successfully unmarshalled data from: '%s'", document.GetFilenameInterpolated())

	// Search the document keys/values for known BOM formats and schema in the config. file
	getLogger().Infof("Determining file's BOM format and version...")
	err = SupportedFormatConfig.FindFormatAndSchema(document)
	if err != nil {
		return
	}

	// Display detected format, version with (optional) schema variant (i.e., if requested on command line)
	getLogger().Infof("Determined BOM format, version (variant): '%s', '%s' %s",
		document.FormatInfo.CanonicalName,
		document.SchemaInfo.Version,
		schema.FormatSchemaVariant(document.SchemaInfo.Variant))
	getLogger().Infof("Matching BOM schema (for validation): %s", document.SchemaInfo.File)
	return
}

func LoadBOMFile(inputFile string) (document *schema.BOM, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	if inputFile == "" {
		return nil, fmt.Errorf("invalid input file (-%s): '%s'", FLAG_FILENAME_INPUT_SHORT, inputFile)
	}

	// Construct a BOM document object around the input file
	document = schema.NewBOM(inputFile)

	// Load the raw, candidate BOM (file) as JSON data
	getLogger().Infof("Attempting to load and unmarshal data from: '%s'...", document.GetFilenameInterpolated())
	err = document.UnmarshalBOMAsJSONMap() // i.e., utils.Flags.InputFile
	if err != nil {
		return
	}
	getLogger().Infof("Successfully unmarshalled data from: '%s'", document.GetFilenameInterpolated())

	// Search the document keys/values for known BOM formats and schema in the config. file
	getLogger().Infof("Determining file's BOM format and version...")
	err = SupportedFormatConfig.FindFormatAndSchema(document)
	if err != nil {
		return
	}

	// Display detected format, version with (optional) schema variant (i.e., if requested on command line)
	getLogger().Infof("Determined BOM format, version (variant): '%s', '%s' %s",
		document.FormatInfo.CanonicalName,
		document.SchemaInfo.Version,
		schema.FormatSchemaVariant(document.SchemaInfo.Variant))
	getLogger().Infof("Matching BOM schema (for validation): %s", document.SchemaInfo.File)
	return
}
