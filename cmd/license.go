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

	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/jwangsadinata/go-multimap/slicemultimap"
	"github.com/spf13/cobra"
)

const (
	SUBCOMMAND_LICENSE_LIST   = "list"
	SUBCOMMAND_LICENSE_POLICY = "policy"
)

var VALID_SUBCOMMANDS_LICENSE = []string{SUBCOMMAND_LICENSE_LIST, SUBCOMMAND_LICENSE_POLICY}

// License list default values
const (
	LICENSE_LIST_NOT_APPLICABLE = "N/A"
	LICENSE_NONE                = "NOASSERTION"
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

// Note: the "License" property is used as hashmap key
type LicenseInfo struct {
	UsagePolicy       string `json:"usage-policy"`
	LicenseChoiceType int    `json:"type"`
	License           string `json:"license"`
	ResourceName      string `json:"resource-name"`
	BomRef            string `json:"bom-ref"`
	BomLocation       int    `json:"bom-location"`
	LicenseChoice     schema.CDXLicenseChoice
	Policy            LicensePolicy
	Component         schema.CDXComponent
	Service           schema.CDXService
}

// License hashmap
// Holds resources (e.g., components, services) declared license(s)
var licenseMap = slicemultimap.New()
var licenseSlice []LicenseInfo

func ClearGlobalLicenseData() {
	licenseMap.Clear()
	licenseSlice = nil
}

func AppendLicenseInfo(key string, licenseInfo LicenseInfo) {
	// Append to slice
	policy, err := FindPolicy(licenseInfo)

	if err != nil {
		// Show intent to not check for error returns as there is no recovery
		_ = getLogger().Errorf("%s", MSG_LICENSE_INVALID_DATA)
		os.Exit(ERROR_VALIDATION)
	}
	licenseInfo.Policy = policy
	licenseInfo.UsagePolicy = policy.UsagePolicy
	licenseInfo.License = key
	licenseSlice = append(licenseSlice, licenseInfo)

	// Hash by license key
	licenseMap.Put(key, licenseInfo)
}

func NewCommandLicense() *cobra.Command {
	var command = new(cobra.Command)
	command.Use = "license"
	command.Short = "Process licenses found in SBOM input file"
	command.Long = "Process licenses found in SBOM input file"
	command.RunE = licenseCmdImpl
	command.ValidArgs = VALID_SUBCOMMANDS_LICENSE
	command.PreRunE = func(cmd *cobra.Command, args []string) (err error) {
		// the license command requires at least 1 valid subcommand (argument)
		getLogger().Tracef("args: %v\n", args)
		if len(args) == 0 {
			return getLogger().Errorf("Missing required argument(s).")
		} else if len(args) > 1 {
			return getLogger().Errorf("Too many arguments provided: %v", args)
		}
		// Make sure subcommand is known
		if !preRunTestForSubcommand(command, VALID_SUBCOMMANDS_LICENSE, args[0]) {
			return getLogger().Errorf("Subcommand provided is not valid: `%v`", args[0])
		}
		return
	}
	return command
}

func licenseCmdImpl(cmd *cobra.Command, args []string) error {
	getLogger().Enter(args)
	defer getLogger().Exit()
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
func findDocumentLicenses(document *schema.Sbom) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	// NOTE: DEBUG: use this to debug license policy hashmaps have appropriate # of entries
	//licensePolicyConfig.Debug()

	// At this time, fail SPDX format SBOMs as "unsupported" (for "any" format)
	if !document.FormatInfo.IsCycloneDx() {
		err = schema.NewUnsupportedFormatForCommandError(
			document.GetFilename(),
			document.FormatInfo.CanonicalName,
			CMD_LICENSE, FORMAT_ANY)
		return
	}

	// Clear out any old (global)hashmap data (NOTE: 'go test' needs this)
	ClearGlobalLicenseData()

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

	// 4. Hash all service licenses found in the (root).services[] (array) (+ "nested" services)
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
		// Issue a warning as an SBOM without at least one, top-level license
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
		licenseInfo.BomLocation = location
		licenseInfo.ResourceName = LICENSE_LIST_NOT_APPLICABLE
		licenseInfo.BomRef = LICENSE_LIST_NOT_APPLICABLE
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
		// hash any component w/o a license using special key name
		licenseInfo.Component = cdxComponent
		licenseInfo.BomLocation = location
		licenseInfo.ResourceName = cdxComponent.Name
		licenseInfo.BomRef = cdxComponent.BomRef
		AppendLicenseInfo(LICENSE_NONE, licenseInfo)

		getLogger().Warningf("%s: %s (name:`%s`, version: `%s`, package-url: `%s`)",
			"No license found for component. bomRef",
			cdxComponent.BomRef,
			cdxComponent.Name,
			cdxComponent.Version,
			cdxComponent.Purl)
		// No actual licenses to process
		return
	}

	for _, licenseChoice := range cdxComponent.Licenses {
		getLogger().Debugf("licenseChoice: %s", getLogger().FormatStruct(licenseChoice))
		getLogger().Tracef("hashing license for component=`%s`", cdxComponent.Name)

		licenseInfo.LicenseChoice = licenseChoice
		licenseInfo.Component = cdxComponent
		licenseInfo.BomLocation = location
		licenseInfo.ResourceName = cdxComponent.Name
		licenseInfo.BomRef = cdxComponent.BomRef
		err = hashLicenseInfo(licenseInfo)

		if err != nil {
			// Show intent to not check for error returns as there no intent to recover
			_ = getLogger().Errorf("Unable to hash empty license: %v", licenseInfo)
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
		// hash any service w/o a license using special key name
		licenseInfo.Service = cdxService
		licenseInfo.BomLocation = location
		licenseInfo.ResourceName = cdxService.Name
		licenseInfo.BomRef = cdxService.BomRef
		AppendLicenseInfo(LICENSE_NONE, licenseInfo)

		getLogger().Warningf("%s: %s (name: `%s`, version: `%s`)",
			"No license found for service. bomRef",
			cdxService.BomRef,
			cdxService.Name,
			cdxService.Version)

		// No actual licenses to process
		return
	}

	for _, licenseChoice := range cdxService.Licenses {
		getLogger().Debugf("licenseChoice: %s", getLogger().FormatStruct(licenseChoice))
		getLogger().Tracef("Hashing license for service=`%s`", cdxService.Name)
		licenseInfo.LicenseChoice = licenseChoice
		licenseInfo.Service = cdxService
		licenseInfo.ResourceName = cdxService.Name
		licenseInfo.BomRef = cdxService.BomRef
		licenseInfo.BomLocation = location
		err = hashLicenseInfo(licenseInfo)

		if err != nil {
			return
		}
	}

	// Recursively hash licenses for all child components (i.e., hierarchical composition)
	if len(cdxService.Services) > 0 {
		err = hashServicesLicenses(cdxService.Services, location)
		if err != nil {
			// Show intent to not check for error returns as there is no recovery
			_ = getLogger().Errorf("Unable to hash empty license: %v", licenseInfo)
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
		AppendLicenseInfo(licenseChoice.License.Id, licenseInfo)
	} else if licenseChoice.License.Name != "" {
		licenseInfo.LicenseChoiceType = LC_TYPE_NAME
		AppendLicenseInfo(licenseChoice.License.Name, licenseInfo)
	} else if licenseChoice.Expression != "" {
		licenseInfo.LicenseChoiceType = LC_TYPE_EXPRESSION
		AppendLicenseInfo(licenseChoice.Expression, licenseInfo)
	} else {
		// Note: This code path only executes if hashing is performed
		// without schema validation (which would find this as an error)
		// Note: licenseInfo.LicenseChoiceType = 0 // default, invalid
		baseError := NewSbomLicenseDataError()
		baseError.AppendMessage(fmt.Sprintf(": for entity: `%s` (%s)",
			licenseInfo.BomRef,
			licenseInfo.ResourceName))
		err = baseError
	}

	return
}
