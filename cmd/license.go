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
	"os"

	"github.com/jwangsadinata/go-multimap/slicemultimap"
	"github.com/scs/sbom-utility/schema"
	"github.com/spf13/cobra"
)

const (
	SUBCOMMAND_LICENSE_LIST   = "list"
	SUBCOMMAND_LICENSE_POLICY = "policy"
)

var VALID_SUBCOMMANDS = []string{SUBCOMMAND_LICENSE_LIST, SUBCOMMAND_LICENSE_POLICY}

// License list default values
const (
	LICENSE_LIST_NOT_APPLICABLE = "N/A"
)

// LicenseChoice - Choice type
const (
	LC_TYPE_INVALID = iota
	LC_TYPE_ID
	LC_TYPE_NAME
	LC_TYPE_EXPRESSION
)

const (
	LC_LOC_UNKNOWN = iota
	LC_LOC_METADATA_COMPONENT
	LC_LOC_METADATA
	LC_LOC_COMPONENTS
	LC_LOC_SERVICES
)

var CDX_LICENSE_LOCATION_NAMES = map[int]string{
	LC_LOC_UNKNOWN:            "unknown",
	LC_LOC_METADATA_COMPONENT: "metadata.component",
	LC_LOC_METADATA:           "metadata.licenses",
	LC_LOC_COMPONENTS:         "components",
	LC_LOC_SERVICES:           "services",
}

// Declare a fixed-sized array for LC type names
var LC_TYPE_NAMES = [...]string{"invalid", "id", "name", "expression"}

type LicenseInfo struct {
	LicenseLocation   int
	LicenseChoiceType int
	LicenseChoice     schema.CDXLicenseChoice
	EntityRef         string
	EntityName        string
	Component         schema.CDXComponent
	Service           schema.CDXService
}

// License hashmaps
var licenseMap = slicemultimap.New()

func ClearGlobalLicenseHashMap() {
	licenseMap.Clear()
}

func NewCommandLicense() *cobra.Command {
	getLogger().Enter()
	defer getLogger().Exit()
	var command = new(cobra.Command)
	command.Use = "license [subcommand] [flags]"
	command.Short = "Process licenses found in SBOM input file"
	command.Long = "Process licenses found in SBOM input file"
	command.RunE = licenseCmdImpl
	command.ValidArgs = VALID_SUBCOMMANDS
	command.PreRunE = func(cmd *cobra.Command, args []string) error {
		// the license command requires at least 1 valid subcommand (argument)
		getLogger().Tracef("args: %v\n", args)
		if len(args) == 0 {
			return getLogger().Errorf("Missing required argument(s).")
		} else if len(args) > 1 {
			return getLogger().Errorf("Too many arguments provided. %v", args)
		}

		for _, cmd := range VALID_SUBCOMMANDS {
			if args[0] == cmd {
				getLogger().Tracef("Valid subcommand `%v` found", args[0])
				return nil
			}
		}
		return getLogger().Errorf("Argument provided is not valid: `%v`", args[0])
	}
	return command
}

// TODO: Remove this if Cobra does not reference since we assume subcommands
func licenseCmdImpl(cmd *cobra.Command, args []string) error {
	getLogger().Enter(args)
	defer getLogger().Exit()
	// No-op for now. The pre-check function should prevent this from being called
	getLogger().Debugf("NO-OP: Empty function")
	os.Exit(ERROR_APPLICATION)
	return nil
}

//------------------------------------
// CDX License hashing functions
//------------------------------------

// Hash ALL licenses found in the SBOM document
// Note: CDX spec. allows for licenses to be declared in the following places:
// 1. (root).metadata.licenses[]
// 2. (root).metadata.component.licenses[] + all "nested" components
// 3. (root).components[](.license[]) (each component + all "nested" components)
// 4. (root).services[](.license[]) (each service + all "nested" services)
func hashDocumentLicenses(document *schema.Sbom) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	// At this time, fail SPDX format SBOMs as "unsupported" (for "any" format)
	if !document.FormatInfo.IsCycloneDx() {
		err = schema.NewUnsupportedFormatForCommandError(
			document.FormatInfo.CanonicalName,
			document.GetFilename(),
			CMD_LICENSE, "<any>")
		return
	}

	// Clear out any old (global)hashmap data (NOTE: 'go test' needs this)
	ClearGlobalLicenseHashMap()

	// Before looking for license data, fully unmarshal the SBOM
	// into named structures
	if err = document.UnmarshalCDXSbom(); err != nil {
		return
	}

	// 1. Hash all licenses in the SBOM metadata (i.e., (root).metadata.component)
	// Note: this SHOULD represent a summary of all licenses that apply
	// to the component being described in the SBOM
	if err = hashMetadataLicenses(document, LC_LOC_METADATA); err != nil {
		return
	}

	// 2. Hash all licenses in (root).metadata.component (+ "nested" components)
	if err = hashMetadataComponentLicenses(document, LC_LOC_METADATA_COMPONENT); err != nil {
		return
	}

	// 3. Hash all component licenses found in the (root).components[] (+ "nested" components)
	if components := document.GetCdxComponents(); len(components) > 0 {
		if err = hashComponentsLicenses(components, LC_LOC_COMPONENTS); err != nil {
			return
		}
	}

	// 4. Hash all service licenses found in the (root).services[] (array) (+ "nested" components)
	if services := document.GetCdxServices(); len(services) > 0 {
		if err = hashServicesLicenses(services, LC_LOC_SERVICES); err != nil {
			return
		}
	}

	return
}

// Hash the license found in the (root).metadata.licenses[] array
func hashMetadataLicenses(document *schema.Sbom, location int) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	licenses := document.GetCdxMetadataLicenses()

	if licenses == nil {
		sbomError := NewInvalidSBOMError(
			document,
			fmt.Sprintf("%s (%s)",
				MSG_LICENSES_NOT_FOUND,
				CDX_LICENSE_LOCATION_NAMES[location]),
			nil, nil)
		// Issue a warning as an SBOM without at least one  top-level license
		// (in the metadata license summary) SHOULD be noted.
		// Note: An actual error SHOULD ONLY be returned by
		// the custom validation code.
		getLogger().Warning(sbomError)
		return
	}

	var licenseInfo LicenseInfo
	for _, lc := range licenses {
		getLogger().Tracef("hashing license: id: `%s`, name: `%s`",
			lc.License.Id, lc.License.Name)

		licenseInfo.LicenseChoice = lc
		licenseInfo.LicenseLocation = location
		licenseInfo.EntityName = LICENSE_LIST_NOT_APPLICABLE
		licenseInfo.EntityRef = LICENSE_LIST_NOT_APPLICABLE
		err = hashLicenseInfo(licenseInfo)

		if err != nil {
			return
		}
	}

	return
}

// Hash the license found in the (root).metadata.component object (and any "nested" components)
func hashMetadataComponentLicenses(document *schema.Sbom, location int) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	component := document.GetCdxMetadataComponent()

	if component == nil {
		sbomError := NewInvalidSBOMError(
			document,
			fmt.Sprintf("%s (%s)",
				MSG_LICENSES_NOT_FOUND,
				CDX_LICENSE_LOCATION_NAMES[location]),
			nil, nil)
		// Issue a warning as an SBOM without at least one
		// top-level component license declared SHOULD be noted.
		// Note: An actual error SHOULD ONLY be returned by
		// the custom validation code.
		getLogger().Warning(sbomError)
		return
	}

	_, err = hashComponentLicense(*component, location)

	return
}

// Hash all licenses found in an array of CDX Components
// TODO use array of pointer to CDXComponent
func hashComponentsLicenses(components []schema.CDXComponent, location int) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	for _, cdxComponent := range components {
		_, err = hashComponentLicense(cdxComponent, location)
		if err != nil {
			return
		}
	}
	return
}

// Hash all licenses found in an array of CDX Services
// TODO use array of pointer to CDXService
func hashServicesLicenses(services []schema.CDXService, location int) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	for _, cdxServices := range services {
		err = hashServiceLicense(cdxServices, location)
		if err != nil {
			return
		}
	}
	return
}

// Hash a CDX Component's licenses and recursively those of any "nested" components
func hashComponentLicense(cdxComponent schema.CDXComponent, location int) (li *LicenseInfo, err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)
	var licenseInfo LicenseInfo

	if len(cdxComponent.Licenses) == 0 {
		getLogger().Tracef("%s: %s (`%s`, %s, %s)",
			"No license found for component. bomRef",
			cdxComponent.BomRef,
			cdxComponent.Name,
			cdxComponent.Version,
			cdxComponent.Purl)
	}

	for _, licenseChoice := range cdxComponent.Licenses {
		getLogger().Debugf("licenseChoice: %s", getLogger().FormatStruct(licenseChoice))
		getLogger().Tracef("hashing license for component=`%s`", cdxComponent.Name)

		licenseInfo.LicenseChoice = licenseChoice
		licenseInfo.Component = cdxComponent
		licenseInfo.LicenseLocation = location
		licenseInfo.EntityName = cdxComponent.Name
		licenseInfo.EntityRef = cdxComponent.BomRef
		err = hashLicenseInfo(licenseInfo)

		if err != nil {
			return
		}
	}

	// Recursively hash licenses for all child components (i.e., hierarchical composition)
	if len(cdxComponent.Components) > 0 {
		err = hashComponentsLicenses(cdxComponent.Components, location)
		if err != nil {
			return
		}
	}

	return
}

// Hash all licenses found in a CDX Service
// TODO use pointer to CDXService
func hashServiceLicense(cdxService schema.CDXService, location int) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	var licenseInfo LicenseInfo

	if len(cdxService.Licenses) == 0 {
		getLogger().Warningf("%s: %s (`%s`, %s)",
			"No license found for service. bomRef",
			cdxService.BomRef,
			cdxService.Name,
			cdxService.Version)
	}

	for _, licenseChoice := range cdxService.Licenses {
		getLogger().Debugf("licenseChoice: %s", getLogger().FormatStruct(licenseChoice))
		getLogger().Tracef("Hashing license for service=`%s`", cdxService.Name)
		licenseInfo.LicenseChoice = licenseChoice
		licenseInfo.Service = cdxService
		licenseInfo.EntityName = cdxService.Name
		licenseInfo.EntityRef = cdxService.BomRef
		licenseInfo.LicenseLocation = location
		err = hashLicenseInfo(licenseInfo)

		if err != nil {
			return
		}
	}

	// Recursively hash licenses for all child components (i.e., hierarchical composition)
	if len(cdxService.Services) > 0 {
		err = hashServicesLicenses(cdxService.Services, location)
		if err != nil {
			return
		}
	}

	return
}

// Wrap the license data itself in a "licenseInfo" object which tracks:
// 1. What type of information do we have about the license (i.e., SPDX ID, Name or expression)
// 2. Where the license was found within the SBOM
// 3. The entity name (e.g., service or component name) that declared the license
// 4. The entity local BOM reference (i.e., "bomRef")
func hashLicenseInfo(licenseInfo LicenseInfo) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	// TODO: make a pointer
	licenseChoice := licenseInfo.LicenseChoice

	if licenseChoice.License.Id != "" {
		licenseInfo.LicenseChoiceType = LC_TYPE_ID
		licenseMap.Put(licenseChoice.License.Id, licenseInfo)
	} else if licenseChoice.License.Name != "" {
		licenseInfo.LicenseChoiceType = LC_TYPE_NAME
		licenseMap.Put(licenseChoice.License.Name, licenseInfo)
	} else {
		if licenseChoice.Expression != "" {
			licenseInfo.LicenseChoiceType = LC_TYPE_EXPRESSION
			licenseMap.Put(licenseChoice.Expression, licenseInfo)
		} else {
			// Note: This code path only executes if hashing is performed
			// without schema validation (which would find this as an error)
			// Note: licenseInfo.LicenseChoiceType = 0 // default, invalid
			baseError := NewSbomLicenseDataError()
			baseError.AppendMessage(fmt.Sprintf(": for entity: `%s` (%s)",
				licenseInfo.EntityRef,
				licenseInfo.EntityName))
			err = baseError
		}

	}
	return
}
