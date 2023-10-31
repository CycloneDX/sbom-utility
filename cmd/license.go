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

	"github.com/CycloneDX/sbom-utility/common"
	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/CycloneDX/sbom-utility/utils"
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
	LICENSE_NO_ASSERTION        = "NOASSERTION"
)

// LicenseChoice - corresponding (name) values for license choice types
const (
	LC_VALUE_INVALID    = "invalid"
	LC_VALUE_ID         = "id"
	LC_VALUE_NAME       = "name"
	LC_VALUE_EXPRESSION = "expression"
)

// Declare a fixed-sized array for LC type name indexed lookup
var LC_TYPE_NAMES = [...]string{LC_VALUE_INVALID, LC_VALUE_ID, LC_VALUE_NAME, LC_VALUE_EXPRESSION}

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
func loadDocumentLicenses(bom *schema.BOM, policyConfig *schema.LicensePolicyConfig, whereFilters []common.WhereFilter) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	// NOTE: DEBUG: use this to debug license policy hashmaps have appropriate # of entries
	//licensePolicyConfig.Debug()

	// At this time, fail SPDX format SBOMs as "unsupported" (for "any" format)
	if !bom.FormatInfo.IsCycloneDx() {
		err = schema.NewUnsupportedFormatForCommandError(
			bom.GetFilename(),
			bom.FormatInfo.CanonicalName,
			CMD_LICENSE, FORMAT_ANY)
		return
	}

	// Before looking for license data, fully unmarshal the SBOM
	// into named structures
	if err = bom.UnmarshalCycloneDXBOM(); err != nil {
		return
	}

	// 1. Hash all licenses in the SBOM metadata (i.e., (root).metadata.component)
	// Note: this SHOULD represent a summary of all licenses that apply
	// to the component being described in the SBOM
	if err = hashMetadataLicenses(bom, policyConfig, LC_LOC_METADATA, whereFilters); err != nil {
		return
	}

	// 2. Hash all licenses in (root).metadata.component (+ "nested" components)
	if err = hashMetadataComponentLicenses(bom, policyConfig, LC_LOC_METADATA_COMPONENT, whereFilters); err != nil {
		return
	}

	// 3. Hash all component licenses found in the (root).components[] (+ "nested" components)
	pComponents := bom.GetCdxComponents()
	if pComponents != nil && len(*pComponents) > 0 {
		if err = hashComponentsLicenses(bom, policyConfig, *pComponents, LC_LOC_COMPONENTS, whereFilters); err != nil {
			return
		}
	}

	// 4. Hash all service licenses found in the (root).services[] (array) (+ "nested" services)
	pServices := bom.GetCdxServices()
	if pServices != nil && len(*pServices) > 0 {
		if err = hashServicesLicenses(bom, policyConfig, *pServices, LC_LOC_SERVICES, whereFilters); err != nil {
			return
		}
	}

	return
}

// Hash the license found in the (root).metadata.licenses[] array
func hashMetadataLicenses(bom *schema.BOM, policyConfig *schema.LicensePolicyConfig, location int, whereFilters []common.WhereFilter) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	pLicenses := bom.GetCdxMetadataLicenses()
	if pLicenses == nil {
		sbomError := NewInvalidSBOMError(
			bom,
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

	var licenseInfo schema.LicenseInfo
	for _, lc := range *pLicenses {
		getLogger().Tracef("hashing license: id: `%s`, name: `%s`",
			lc.License.Id, lc.License.Name)

		licenseInfo.LicenseChoice = lc
		licenseInfo.BOMLocationValue = location
		licenseInfo.ResourceName = LICENSE_LIST_NOT_APPLICABLE
		licenseInfo.BOMRef = LICENSE_LIST_NOT_APPLICABLE
		err = hashLicenseInfoByLicenseType(bom, policyConfig, licenseInfo, whereFilters)

		if err != nil {
			return
		}
	}

	return
}

// Hash the license found in the (root).metadata.component object (and any "nested" components)
func hashMetadataComponentLicenses(bom *schema.BOM, policyConfig *schema.LicensePolicyConfig, location int, whereFilters []common.WhereFilter) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	component := bom.GetCdxMetadataComponent()
	if component == nil {
		sbomError := NewInvalidSBOMError(
			bom,
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

	_, err = hashComponentLicense(bom, policyConfig, *component, location, whereFilters)

	return
}

// Hash all licenses found in an array of CDX Components
// TODO use array of pointer to []CDXComponent
func hashComponentsLicenses(bom *schema.BOM, policyConfig *schema.LicensePolicyConfig, components []schema.CDXComponent, location int, whereFilters []common.WhereFilter) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	for _, cdxComponent := range components {
		_, err = hashComponentLicense(bom, policyConfig, cdxComponent, location, whereFilters)
		if err != nil {
			return
		}
	}
	return
}

// Hash all licenses found in an array of CDX Services
// TODO use array of pointer to []CDXService
func hashServicesLicenses(bom *schema.BOM, policyConfig *schema.LicensePolicyConfig, services []schema.CDXService, location int, whereFilters []common.WhereFilter) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	for _, cdxServices := range services {
		err = hashServiceLicense(bom, policyConfig, cdxServices, location, whereFilters)
		if err != nil {
			return
		}
	}
	return
}

// Hash a CDX Component's licenses and recursively those of any "nested" components
func hashComponentLicense(bom *schema.BOM, policyConfig *schema.LicensePolicyConfig, cdxComponent schema.CDXComponent, location int, whereFilters []common.WhereFilter) (li *schema.LicenseInfo, err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)
	var licenseInfo schema.LicenseInfo

	pLicenses := cdxComponent.Licenses
	if pLicenses != nil && len(*pLicenses) > 0 {
		for _, licenseChoice := range *pLicenses {
			getLogger().Debugf("licenseChoice: %s", getLogger().FormatStruct(licenseChoice))
			getLogger().Tracef("hashing license for component=`%s`", cdxComponent.Name)

			licenseInfo.LicenseChoice = licenseChoice
			licenseInfo.Component = cdxComponent
			licenseInfo.BOMLocationValue = location
			licenseInfo.ResourceName = cdxComponent.Name
			if cdxComponent.BOMRef != nil {
				licenseInfo.BOMRef = *cdxComponent.BOMRef
			}
			err = hashLicenseInfoByLicenseType(bom, policyConfig, licenseInfo, whereFilters)

			if err != nil {
				// Show intent to not check for error returns as there no intent to recover
				_ = getLogger().Errorf("Unable to hash empty license: %v", licenseInfo)
				return
			}
		}
	} else {
		// Account for component with no license with an "UNDEFINED" entry
		// hash any component w/o a license using special key name
		licenseInfo.Component = cdxComponent
		licenseInfo.BOMLocationValue = location
		licenseInfo.ResourceName = cdxComponent.Name
		if cdxComponent.BOMRef != nil {
			licenseInfo.BOMRef = *cdxComponent.BOMRef
		}
		HashLicenseInfo(bom, policyConfig, LICENSE_NO_ASSERTION, licenseInfo, whereFilters)

		getLogger().Warningf("%s: %s (name:`%s`, version: `%s`, package-url: `%s`)",
			"No license found for component. bomRef",
			cdxComponent.BOMRef,
			cdxComponent.Name,
			cdxComponent.Version,
			cdxComponent.Purl)
		// No actual licenses to process
		return
	}

	// Recursively hash licenses for all child components (i.e., hierarchical composition)
	pComponents := cdxComponent.Components
	if pComponents != nil && len(*pComponents) > 0 {
		err = hashComponentsLicenses(bom, policyConfig, *pComponents, location, whereFilters)
		if err != nil {
			return
		}
	}

	return
}

// Hash all licenses found in a CDX Service
// TODO use pointer to CDXService
func hashServiceLicense(bom *schema.BOM, policyConfig *schema.LicensePolicyConfig, cdxService schema.CDXService, location int, whereFilters []common.WhereFilter) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	var licenseInfo schema.LicenseInfo

	pLicenses := cdxService.Licenses
	if pLicenses != nil && len(*pLicenses) > 0 {
		for _, licenseChoice := range *pLicenses {
			getLogger().Debugf("licenseChoice: %s", getLogger().FormatStruct(licenseChoice))
			getLogger().Tracef("Hashing license for service=`%s`", cdxService.Name)
			licenseInfo.LicenseChoice = licenseChoice
			licenseInfo.Service = cdxService
			licenseInfo.ResourceName = cdxService.Name
			if cdxService.BOMRef != nil {
				licenseInfo.BOMRef = *cdxService.BOMRef
			}
			licenseInfo.BOMLocationValue = location
			err = hashLicenseInfoByLicenseType(bom, policyConfig, licenseInfo, whereFilters)

			if err != nil {
				return
			}
		}
	} else {
		// Account for service with no license with an "UNDEFINED" entry
		// hash any service w/o a license using special key name
		licenseInfo.Service = cdxService
		licenseInfo.BOMLocationValue = location
		licenseInfo.ResourceName = cdxService.Name
		if cdxService.BOMRef != nil {
			licenseInfo.BOMRef = *cdxService.BOMRef
		}
		HashLicenseInfo(bom, policyConfig, LICENSE_NO_ASSERTION, licenseInfo, whereFilters)

		getLogger().Warningf("%s: %s (name: `%s`, version: `%s`)",
			"No license found for service. bomRef",
			cdxService.BOMRef,
			cdxService.Name,
			cdxService.Version)

		// No actual licenses to process
		return
	}

	// Recursively hash licenses for all child components (i.e., hierarchical composition)
	pServices := cdxService.Services
	if pServices != nil && len(*pServices) > 0 {
		err = hashServicesLicenses(bom, policyConfig, *pServices, location, whereFilters)
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
func hashLicenseInfoByLicenseType(bom *schema.BOM, policyConfig *schema.LicensePolicyConfig, licenseInfo schema.LicenseInfo, whereFilters []common.WhereFilter) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	// TODO: make a pointer
	licenseChoice := licenseInfo.LicenseChoice

	if licenseChoice.License.Id != "" {
		licenseInfo.LicenseChoiceTypeValue = schema.LC_TYPE_ID
		HashLicenseInfo(bom, policyConfig, licenseChoice.License.Id, licenseInfo, whereFilters)
	} else if licenseChoice.License.Name != "" {
		licenseInfo.LicenseChoiceTypeValue = schema.LC_TYPE_NAME
		HashLicenseInfo(bom, policyConfig, licenseChoice.License.Name, licenseInfo, whereFilters)
	} else if licenseChoice.Expression != "" {
		licenseInfo.LicenseChoiceTypeValue = schema.LC_TYPE_EXPRESSION
		HashLicenseInfo(bom, policyConfig, licenseChoice.Expression, licenseInfo, whereFilters)
	} else {
		// Note: This code path only executes if hashing is performed
		// without schema validation (which would find this as an error)
		// Note: licenseInfo.LicenseChoiceType = 0 // default, invalid
		baseError := NewSbomLicenseDataError()
		baseError.AppendMessage(fmt.Sprintf(": for entity: `%s` (%s)",
			licenseInfo.BOMRef,
			licenseInfo.ResourceName))
		err = baseError
	}

	return
}

func HashLicenseInfo(bom *schema.BOM, policyConfig *schema.LicensePolicyConfig, key string, licenseInfo schema.LicenseInfo, whereFilters []common.WhereFilter) {
	// Find license usage policy by either license Id, Name or Expression
	policy, err := policyConfig.FindPolicy(licenseInfo)

	if err != nil {
		// Show intent to not check for error returns as there is no recovery
		_ = getLogger().Errorf("%s", MSG_LICENSE_INVALID_DATA)
		os.Exit(ERROR_VALIDATION)
	}
	licenseInfo.License = key
	licenseInfo.Policy = policy
	licenseInfo.UsagePolicy = policy.UsagePolicy
	// Derive values for report filtering
	licenseInfo.LicenseChoiceType = LC_TYPE_NAMES[licenseInfo.LicenseChoiceTypeValue]
	licenseInfo.BOMLocation = CDX_LICENSE_LOCATION_NAMES[licenseInfo.BOMLocationValue]

	var match bool = true
	if len(whereFilters) > 0 {
		mapInfo, _ := utils.ConvertStructToMap(licenseInfo)
		match, _ = whereFilterMatch(mapInfo, whereFilters)
	}

	if match {
		// Hash LicenseInfo by license key (i.e., id|name|expression)
		bom.LicenseMap.Put(key, licenseInfo)

		getLogger().Tracef("Put: %s (`%s`), `%s`)",
			licenseInfo.ResourceName,
			licenseInfo.UsagePolicy,
			licenseInfo.BOMRef)
	}
}
