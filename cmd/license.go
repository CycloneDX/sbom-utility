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

func NewCommandLicense() *cobra.Command {
	var command = new(cobra.Command)
	command.Use = "license"
	command.Short = "Process licenses found in the BOM input file"
	command.Long = "Process licenses found in the BOM input file"
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
		if !preRunTestForSubcommand(VALID_SUBCOMMANDS_LICENSE, args[0]) {
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
func loadDocumentLicenses(bom *schema.BOM, policyConfig *schema.LicensePolicyConfig, whereFilters []common.WhereFilter, licenseFlags utils.LicenseCommandFlags) (err error) {
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
	if err = hashMetadataLicenses(bom, policyConfig, schema.LC_LOC_METADATA, whereFilters, licenseFlags); err != nil {
		return
	}

	// 2. Hash all licenses in (root).metadata.component (+ "nested" components)
	if err = hashMetadataComponentLicenses(bom, policyConfig, schema.LC_LOC_METADATA_COMPONENT, whereFilters, licenseFlags); err != nil {
		return
	}

	// 3. Hash all component licenses found in the (root).components[] (+ "nested" components)
	pComponents := bom.GetCdxComponents()
	if pComponents != nil && len(*pComponents) > 0 {
		if err = hashComponentsLicenses(bom, policyConfig, pComponents, schema.LC_LOC_COMPONENTS, whereFilters, licenseFlags); err != nil {
			return
		}
	}

	// 4. Hash all service licenses found in the (root).services[] (array) (+ "nested" services)
	pServices := bom.GetCdxServices()
	if pServices != nil && len(*pServices) > 0 {
		if err = hashServicesLicenses(bom, policyConfig, pServices, schema.LC_LOC_SERVICES, whereFilters, licenseFlags); err != nil {
			return
		}
	}
	return
}

// Note: An actual error SHOULD ONLY be returned by the custom validation code.
func warnNoLicenseFound(bom *schema.BOM, location int) {
	message := fmt.Sprintf("%s (%s)",
		MSG_LICENSES_NOT_FOUND, // "licenses not found"
		schema.GetLicenseChoiceLocationName(location))
	sbomError := NewInvalidSBOMError(bom, message, nil, nil)
	getLogger().Warning(sbomError)
}

// Note: An actual error SHOULD ONLY be returned by the custom validation code.
func warnInvalidResourceLicense(resourceType string, bomRef string, name string, version string) {
	getLogger().Warningf("%s. resourceType: `%s`: bomRef: `%s`, name:`%s`, version: `%s`",
		MSG_LICENSE_NOT_FOUND,
		resourceType, bomRef, name, version)
}

// Hash the license found in the (root).metadata.licenses[] array
func hashMetadataLicenses(bom *schema.BOM, policyConfig *schema.LicensePolicyConfig, location int, whereFilters []common.WhereFilter, licenseFlags utils.LicenseCommandFlags) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	pLicenses := bom.GetCdxMetadataLicenses()
	// Issue a warning that the SBOM does not declare at least one, top-level component license.
	if pLicenses == nil {
		warnNoLicenseFound(bom, location)
		return
	}

	var licenseInfo schema.LicenseInfo
	for _, pLicenseChoice := range *pLicenses {
		getLogger().Tracef("hashing license: id: `%s`, name: `%s`",
			pLicenseChoice.License.Id, pLicenseChoice.License.Name)

		licenseInfo.LicenseChoice = pLicenseChoice
		licenseInfo.BOMLocationValue = location
		licenseInfo.ResourceName = LICENSE_LIST_NOT_APPLICABLE
		licenseInfo.BOMRef = LICENSE_LIST_NOT_APPLICABLE
		err = hashLicenseInfoByLicenseType(bom, policyConfig, licenseInfo, whereFilters, licenseFlags)
		if err != nil {
			return
		}
	}
	return
}

// Hash the license found in the (root).metadata.component object (and any "nested" components)
func hashMetadataComponentLicenses(bom *schema.BOM, policyConfig *schema.LicensePolicyConfig, location int, whereFilters []common.WhereFilter, licenseFlags utils.LicenseCommandFlags) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	pComponent := bom.GetCdxMetadataComponent()
	if pComponent == nil {
		warnNoLicenseFound(bom, location)
		return
	}
	_, err = hashComponentLicense(bom, policyConfig, *pComponent, location, whereFilters, licenseFlags)
	return
}

// Hash all licenses found in an array of CDX Components
func hashComponentsLicenses(bom *schema.BOM, policyConfig *schema.LicensePolicyConfig, pComponents *[]schema.CDXComponent, location int, whereFilters []common.WhereFilter, licenseFlags utils.LicenseCommandFlags) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	if pComponents != nil {
		for _, cdxComponent := range *pComponents {
			_, err = hashComponentLicense(bom, policyConfig, cdxComponent, location, whereFilters, licenseFlags)
			if err != nil {
				return
			}
		}
	}
	return
}

// Hash all licenses found in an array of CDX Services
func hashServicesLicenses(bom *schema.BOM, policyConfig *schema.LicensePolicyConfig, pServices *[]schema.CDXService, location int, whereFilters []common.WhereFilter, licenseFlags utils.LicenseCommandFlags) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	if pServices != nil {
		for _, cdxServices := range *pServices {
			err = hashServiceLicense(bom, policyConfig, cdxServices, location, whereFilters, licenseFlags)
			if err != nil {
				return
			}
		}
	}
	return
}

// Hash a CDX Component's licenses and recursively those of any "nested" components
func hashComponentLicense(bom *schema.BOM, policyConfig *schema.LicensePolicyConfig, cdxComponent schema.CDXComponent, location int, whereFilters []common.WhereFilter, licenseFlags utils.LicenseCommandFlags) (li *schema.LicenseInfo, err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)
	var licenseInfo schema.LicenseInfo

	pLicenses := cdxComponent.Licenses
	if pLicenses != nil && len(*pLicenses) > 0 {
		for _, licenseChoice := range *pLicenses {
			getLogger().Debugf("licenseChoice: %s", getLogger().FormatStruct(licenseChoice))
			getLogger().Tracef("hashing license for component=`%s`", cdxComponent.Name)

			licenseInfo = *schema.NewLicenseInfoFromComponent(cdxComponent, licenseChoice, location)
			err = hashLicenseInfoByLicenseType(bom, policyConfig, licenseInfo, whereFilters, licenseFlags)

			if err != nil {
				// Show intent to not check for error returns as there no intent to recover
				_ = getLogger().Errorf("%s. license: %+v", MSG_LICENSE_HASH_ERROR, licenseInfo)
				return
			}
		}
	} else {
		// Account for component with no license with an "UNDEFINED" entry
		licenseInfo = *schema.NewLicenseInfoFromComponent(cdxComponent, schema.CDXLicenseChoice{}, location)
		_, err = bom.HashmapLicenseInfo(policyConfig, LICENSE_NO_ASSERTION, licenseInfo, whereFilters, licenseFlags)

		// Issue a warning that the component had no license; use "safe" BOMRef string value
		warnInvalidResourceLicense(schema.RESOURCE_TYPE_COMPONENT, licenseInfo.BOMRef.String(), cdxComponent.Name, cdxComponent.Version)
		// No actual licenses to process
		return
	}

	// Recursively hash licenses for all child components (i.e., hierarchical composition)
	pComponents := cdxComponent.Components
	if pComponents != nil && len(*pComponents) > 0 {
		err = hashComponentsLicenses(bom, policyConfig, pComponents, location, whereFilters, licenseFlags)
		if err != nil {
			return
		}
	}
	return
}

// Hash all licenses found in a CDX Service
func hashServiceLicense(bom *schema.BOM, policyConfig *schema.LicensePolicyConfig, cdxService schema.CDXService, location int, whereFilters []common.WhereFilter, licenseFlags utils.LicenseCommandFlags) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	var licenseInfo schema.LicenseInfo

	pLicenses := cdxService.Licenses
	if pLicenses != nil && len(*pLicenses) > 0 {
		for _, licenseChoice := range *pLicenses {
			getLogger().Debugf("licenseChoice: %s", getLogger().FormatStruct(licenseChoice))
			getLogger().Tracef("Hashing license for service=`%s`", cdxService.Name)
			licenseInfo = *schema.NewLicenseInfoFromService(cdxService, licenseChoice, location)
			err = hashLicenseInfoByLicenseType(bom, policyConfig, licenseInfo, whereFilters, licenseFlags)
			if err != nil {
				// Show intent to not check for error returns as there no intent to recover
				_ = getLogger().Errorf("%s. license: %+v", MSG_LICENSE_HASH_ERROR, licenseInfo)
				return
			}
		}
	} else {
		// Account for service with no license with an "UNDEFINED" entry
		// hash any service w/o a license using special key name
		licenseInfo = *schema.NewLicenseInfoFromService(cdxService, schema.CDXLicenseChoice{}, location)
		_, err = bom.HashmapLicenseInfo(policyConfig, LICENSE_NO_ASSERTION, licenseInfo, whereFilters, licenseFlags)

		// Issue a warning that the service had no license; use "safe" BOMRef string value
		warnInvalidResourceLicense(schema.RESOURCE_TYPE_SERVICE, licenseInfo.BOMRef.String(), cdxService.Name, cdxService.Version)

		// No actual licenses to process
		return
	}

	// Recursively hash licenses for all child components (i.e., hierarchical composition)
	pServices := cdxService.Services
	if pServices != nil && len(*pServices) > 0 {
		err = hashServicesLicenses(bom, policyConfig, pServices, location, whereFilters, licenseFlags)
		if err != nil {
			// Show intent to not check for error returns as there no intent to recover
			_ = getLogger().Errorf("%s. license: %+v", MSG_LICENSE_HASH_ERROR, licenseInfo)
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
func hashLicenseInfoByLicenseType(bom *schema.BOM, policyConfig *schema.LicensePolicyConfig, licenseInfo schema.LicenseInfo, whereFilters []common.WhereFilter, licenseFlags utils.LicenseCommandFlags) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	licenseChoice := licenseInfo.LicenseChoice
	pLicense := licenseChoice.License

	if pLicense != nil && pLicense.Id != "" {
		licenseInfo.LicenseChoiceTypeValue = schema.LC_TYPE_ID
		_, err = bom.HashmapLicenseInfo(policyConfig, pLicense.Id, licenseInfo, whereFilters, licenseFlags)
	} else if pLicense != nil && pLicense.Name != "" {
		licenseInfo.LicenseChoiceTypeValue = schema.LC_TYPE_NAME
		_, err = bom.HashmapLicenseInfo(policyConfig, pLicense.Name, licenseInfo, whereFilters, licenseFlags)
	} else if licenseChoice.Expression != "" {
		licenseInfo.LicenseChoiceTypeValue = schema.LC_TYPE_EXPRESSION
		_, err = bom.HashmapLicenseInfo(policyConfig, licenseChoice.Expression, licenseInfo, whereFilters, licenseFlags)
	} else {
		// Note: This code path only executes if hashing is performed
		// without schema validation (which would find this as an error)
		// Note: licenseInfo.LicenseChoiceType = 0 // default, invalid
		baseError := NewSbomLicenseDataError()
		baseError.AppendMessage(fmt.Sprintf(": for entity: `%s` (%s)",
			licenseInfo.BOMRef,
			licenseInfo.ResourceName))
		err = baseError
		return
	}

	if err != nil {
		baseError := NewSbomLicenseDataError()
		baseError.AppendMessage(fmt.Sprintf(": for entity: `%s` (%s)",
			licenseInfo.BOMRef,
			licenseInfo.ResourceName))
		err = baseError
	}
	return
}
