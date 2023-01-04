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

	"github.com/scs/sbom-utility/schema"
	"github.com/scs/sbom-utility/utils"
)

func LoadInputSbomFileAndDetectSchema() (document *schema.Sbom, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// check for required fields on command
	getLogger().Tracef("utils.Flags.InputFile: `%s`", utils.GlobalFlags.InputFile)
	if utils.GlobalFlags.InputFile == "" {
		return nil, fmt.Errorf("invalid input file (-%s): `%s` ", FLAG_FILENAME_INPUT_SHORT, utils.GlobalFlags.InputFile)
	}

	// Construct an Sbom object around the input file
	document = schema.NewSbom(utils.GlobalFlags.InputFile)

	// Load the raw, candidate SBOM (file) as JSON data
	getLogger().Infof("Attempting to load and unmarshal file `%s`...", utils.GlobalFlags.InputFile)
	err = document.UnmarshalSBOMAsJsonMap() // i.e., utils.Flags.InputFile
	if err != nil {
		return
	}
	getLogger().Infof("Successfully unmarshalled data from: `%s`", utils.GlobalFlags.InputFile)

	// Search the document keys/values for known SBOM formats and schema in the config. file
	getLogger().Infof("Determining file's SBOM format and version...")
	err = document.FindFormatAndSchema()
	if err != nil {
		return
	}

	// Display detected format, version with (optional) schema variant (i.e., if requested on command line)
	getLogger().Infof("Determined SBOM format, version (variant): `%s`, `%s` %s",
		document.FormatInfo.CanonicalName,
		document.SchemaInfo.Version,
		schema.FormatSchemaVariant(document.SchemaInfo.Variant))
	getLogger().Infof("Matching SBOM schema (for validation): %s", document.SchemaInfo.File)
	return
}
