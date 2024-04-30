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
	"fmt"
	"reflect"
	"runtime/debug"
	"strings"

	"github.com/CycloneDX/sbom-utility/common"
	"github.com/CycloneDX/sbom-utility/utils"
)

// -------------------
// Components
// -------------------

// This hashes all components regardless where in the BOM document structure
// they are declared.  This includes both the top-level metadata component
// (i.e., the subject of the BOM) as well as the components array.
func (bom *BOM) HashmapComponentResources(whereFilters []common.WhereFilter) (err error) {
	getLogger().Enter()
	defer func() {
		if panicInfo := recover(); panicInfo != nil {
			fmt.Printf("%v, %s", panicInfo, string(debug.Stack()))
		}
	}()
	defer getLogger().Exit(err)

	// Hash the top-level component declared in the BOM metadata
	pMetadataComponent := bom.GetCdxMetadataComponent()
	if pMetadataComponent != nil {
		_, err = bom.HashmapComponent(*pMetadataComponent, whereFilters, true)
		if err != nil {
			return
		}
	}

	// Hash all components found in the (root).components[] (+ "nested" components)
	pComponents := bom.GetCdxComponents()
	if pComponents != nil && len(*pComponents) > 0 {
		//if components := bom.GetCdxComponents(); len(*components) > 0 {
		if err = bom.HashmapComponents(*pComponents, whereFilters, false); err != nil {
			return
		}
	}
	return
}

// TODO: use pointer for []CDXComponent
func (bom *BOM) HashmapComponents(components []CDXComponent, whereFilters []common.WhereFilter, root bool) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)
	for _, cdxComponent := range components {
		_, err = bom.HashmapComponent(cdxComponent, whereFilters, root)
		if err != nil {
			return
		}
	}
	return
}

// Hash a CDX Component and recursively those of any "nested" components
// TODO: we should WARN if version is not a valid semver (e.g., examples/cyclonedx/BOM/laravel-7.12.0/bom.1.3.json)
// TODO: Use pointer for CDXComponent
func (bom *BOM) HashmapComponent(cdxComponent CDXComponent, whereFilters []common.WhereFilter, root bool) (hashed bool, err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)
	var resourceInfo CDXResourceInfo

	if reflect.DeepEqual(cdxComponent, CDXComponent{}) {
		getLogger().Warning("empty component object found")
		return
	}

	if cdxComponent.Name == "" {
		getLogger().Warningf("component missing required value `name` : %v ", cdxComponent)
	}

	if cdxComponent.Version == "" {
		getLogger().Warningf("component named `%s` missing `version`", cdxComponent.Name)
	}

	if cdxComponent.BOMRef != nil && *cdxComponent.BOMRef == "" {
		getLogger().Warningf("component named `%s` missing `bom-ref`", cdxComponent.Name)
	}

	// hash any component w/o a license using special key name
	resourceInfo.IsRoot = root
	resourceInfo.Type = RESOURCE_TYPE_COMPONENT
	resourceInfo.Component = cdxComponent
	resourceInfo.Name = cdxComponent.Name
	if cdxComponent.BOMRef != nil {
		ref := *cdxComponent.BOMRef
		resourceInfo.BOMRef = ref.String()
	}
	resourceInfo.Version = cdxComponent.Version
	if cdxComponent.Supplier != nil {
		resourceInfo.SupplierProvider = cdxComponent.Supplier
	}
	resourceInfo.Properties = cdxComponent.Properties

	var match bool = true
	if len(whereFilters) > 0 {
		mapResourceInfo, _ := utils.MarshalStructToJsonMap(resourceInfo)
		match, _ = whereFilterMatch(mapResourceInfo, whereFilters)
	}

	if match {
		hashed = true
		bom.ComponentMap.Put(resourceInfo.BOMRef, resourceInfo)
		bom.ResourceMap.Put(resourceInfo.BOMRef, resourceInfo)

		getLogger().Tracef("Put: %s (`%s`), `%s`)",
			resourceInfo.Name,
			resourceInfo.Version,
			resourceInfo.BOMRef)
	}

	// Recursively hash licenses for all child components (i.e., hierarchical composition)
	pComponent := cdxComponent.Components
	if pComponent != nil && len(*pComponent) > 0 {
		err = bom.HashmapComponents(*cdxComponent.Components, whereFilters, root)
		if err != nil {
			return
		}
	}
	return
}

// -------------------
// Services
// -------------------

func (bom *BOM) HashmapServiceResources(whereFilters []common.WhereFilter) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	pServices := bom.GetCdxServices()
	if pServices != nil && len(*pServices) > 0 {
		if err = bom.HashmapServices(*pServices, whereFilters); err != nil {
			return
		}
	}
	return
}

// TODO: use pointer for []CDXService
func (bom *BOM) HashmapServices(services []CDXService, whereFilters []common.WhereFilter) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	for _, cdxService := range services {
		_, err = bom.HashmapService(cdxService, whereFilters)
		if err != nil {
			return
		}
	}
	return
}

// Hash a CDX Component and recursively those of any "nested" components
// TODO: use pointer for CDXService
func (bom *BOM) HashmapService(cdxService CDXService, whereFilters []common.WhereFilter) (hashed bool, err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)
	var resourceInfo CDXResourceInfo

	if reflect.DeepEqual(cdxService, CDXService{}) {
		getLogger().Warning("empty service object found")
		return
	}

	if cdxService.Name == "" {
		getLogger().Warningf("service missing required value `name` : %v ", cdxService)
	}

	if cdxService.Version == "" {
		getLogger().Warningf("service named `%s` missing `version`", cdxService.Name)
	}

	if cdxService.BOMRef == nil || *cdxService.BOMRef != "" {
		getLogger().Warningf("service named `%s` missing `bom-ref`", cdxService.Name)
	}

	// hash any component w/o a license using special key name
	resourceInfo.Type = RESOURCE_TYPE_SERVICE
	resourceInfo.Service = cdxService
	resourceInfo.Name = cdxService.Name
	if cdxService.BOMRef != nil {
		resourceInfo.BOMRef = cdxService.BOMRef.String()
	}
	resourceInfo.Version = cdxService.Version
	if cdxService.Provider != nil {
		resourceInfo.SupplierProvider = cdxService.Provider
	}
	resourceInfo.Properties = cdxService.Properties

	var match bool = true
	if len(whereFilters) > 0 {
		mapResourceInfo, _ := utils.MarshalStructToJsonMap(resourceInfo)
		match, _ = whereFilterMatch(mapResourceInfo, whereFilters)
	}

	if match {
		// TODO: AppendLicenseInfo(LICENSE_NONE, resourceInfo)
		hashed = true
		bom.ServiceMap.Put(resourceInfo.BOMRef, resourceInfo)
		bom.ResourceMap.Put(resourceInfo.BOMRef, resourceInfo)

		getLogger().Tracef("Put: [`%s`] %s (`%s`), `%s`)",
			resourceInfo.Type,
			resourceInfo.Name,
			resourceInfo.Version,
			resourceInfo.BOMRef,
		)
	}

	// Recursively hash licenses for all child components (i.e., hierarchical composition)
	pServices := cdxService.Services
	if pServices != nil && len(*pServices) > 0 {
		err = bom.HashmapServices(*pServices, whereFilters)
		if err != nil {
			return
		}
	}
	return
}

// -------------------
// Licenses
// -------------------

func (bom *BOM) HashmapLicenseInfo(policyConfig *LicensePolicyConfig, key string, licenseInfo LicenseInfo, whereFilters []common.WhereFilter, licenseFlags utils.LicenseCommandFlags) (hashed bool, err error) {
	if reflect.DeepEqual(licenseInfo, LicenseInfo{}) {
		getLogger().Warning("empty license object found")
		return
	}

	// Find license usage policy by either license Id, Name or Expression
	if policyConfig != nil {
		licenseInfo.Policy, err = policyConfig.FindPolicy(licenseInfo)
		if err != nil {
			return
		}
		// Note: FindPolicy(), at worst, will return an empty LicensePolicy object
		licenseInfo.UsagePolicy = licenseInfo.Policy.UsagePolicy
	}
	licenseInfo.License = key
	// Derive values for report filtering
	licenseInfo.LicenseChoiceType = GetLicenseChoiceTypeName(licenseInfo.LicenseChoiceTypeValue)
	licenseInfo.BOMLocation = GetLicenseChoiceLocationName(licenseInfo.BOMLocationValue)

	// If we need to include all license fields, they need to be copied to from
	// wherever they appear into base LicenseInfo struct (for JSON tag/where filtering)
	// i.e., "License.Id", "License.Name", "License.Url", "Expression",
	//       "License.Text.ContentType", "License.Text.Encoding", "License.Text.Content"
	if !licenseFlags.Summary {
		copyExtendedLicenseChoiceFieldData(&licenseInfo)
	}

	var match bool = true
	if len(whereFilters) > 0 {
		mapInfo, _ := utils.MarshalStructToJsonMap(licenseInfo)
		match, _ = whereFilterMatch(mapInfo, whereFilters)
	}

	if match {
		hashed = true
		// Hash LicenseInfo by license key (i.e., id|name|expression)
		bom.LicenseMap.Put(key, licenseInfo)
		getLogger().Tracef("Put: %s (`%s`), `%s`)",
			licenseInfo.ResourceName,
			licenseInfo.UsagePolicy,
			licenseInfo.BOMRef)
	}
	return
}

func copyExtendedLicenseChoiceFieldData(pLicenseInfo *LicenseInfo) {
	if pLicenseInfo == nil {
		getLogger().Tracef("invalid *LicenseInfo")
		return
	}

	var lcType = pLicenseInfo.LicenseChoiceType
	if lcType == LC_VALUE_ID || lcType == LC_VALUE_NAME {
		if pLicenseInfo.LicenseChoice.License == nil {
			getLogger().Tracef("invalid *CDXLicense")
			return
		}
		pLicenseInfo.LicenseId = pLicenseInfo.LicenseChoice.License.Id
		pLicenseInfo.LicenseName = pLicenseInfo.LicenseChoice.License.Name
		pLicenseInfo.LicenseUrl = pLicenseInfo.LicenseChoice.License.Url

		if pLicenseInfo.LicenseChoice.License.Text != nil {
			// NOTE: always copy full context text; downstream display functions
			// can truncate later
			pLicenseInfo.LicenseTextContent = pLicenseInfo.LicenseChoice.License.Text.Content
			pLicenseInfo.LicenseTextContentType = pLicenseInfo.LicenseChoice.License.Text.ContentType
			pLicenseInfo.LicenseTextEncoding = pLicenseInfo.LicenseChoice.License.Text.Encoding
		}
	} else if lcType == LC_VALUE_EXPRESSION {
		pLicenseInfo.LicenseExpression = pLicenseInfo.LicenseChoice.Expression
	}
}

// -------------------
// Vulnerabilities
// -------------------

func (bom *BOM) HashmapVulnerabilityResources(whereFilters []common.WhereFilter) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	pVulnerabilities := bom.GetCdxVulnerabilities()

	if pVulnerabilities != nil && len(*pVulnerabilities) > 0 {
		if err = bom.HashmapVulnerabilities(*pVulnerabilities, whereFilters); err != nil {
			return
		}
	}
	return
}

// We need to hash our own informational structure around the CDX data in order
// to simplify --where queries to command line users
func (bom *BOM) HashmapVulnerabilities(vulnerabilities []CDXVulnerability, whereFilters []common.WhereFilter) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	for _, cdxVulnerability := range vulnerabilities {
		_, err = bom.HashmapVulnerability(cdxVulnerability, whereFilters)
		if err != nil {
			return
		}
	}
	return
}

// Hash a CDX Component and recursively those of any "nested" components
// TODO we should WARN if version is not a valid semver (e.g., examples/cyclonedx/BOM/laravel-7.12.0/bom.1.3.json)
func (bom *BOM) HashmapVulnerability(cdxVulnerability CDXVulnerability, whereFilters []common.WhereFilter) (hashed bool, err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)
	var vulnInfo VulnerabilityInfo

	// Note: the CDX Vulnerability type has no required fields
	if reflect.DeepEqual(cdxVulnerability, CDXVulnerability{}) {
		getLogger().Warning("empty vulnerability object found")
		return
	}

	if cdxVulnerability.Id == "" {
		getLogger().Warningf("vulnerability missing required value `id` : %v ", cdxVulnerability)
	}

	if cdxVulnerability.Published == "" {
		getLogger().Warningf("vulnerability (`%s`) missing `published` date", cdxVulnerability.Id)
	}

	if cdxVulnerability.Created == "" {
		getLogger().Warningf("vulnerability (`%s`) missing `created` date", cdxVulnerability.Id)
	}

	if cdxVulnerability.Ratings == nil || len(*cdxVulnerability.Ratings) == 0 {
		getLogger().Warningf("vulnerability (`%s`) missing `ratings`", cdxVulnerability.Id)
	}

	// hash any component w/o a license using special key name
	vulnInfo.Vulnerability = cdxVulnerability
	if cdxVulnerability.BOMRef != nil && *cdxVulnerability.BOMRef != "" {
		vulnInfo.BOMRef = cdxVulnerability.BOMRef.String()
	}
	vulnInfo.Id = cdxVulnerability.Id

	// Truncate dates from 2023-02-02T00:00:00.000Z to 2023-02-02
	// Note: if validation errors are found by the "truncate" function,
	// it will emit an error and return the original (failing) value
	dateTime, _ := utils.TruncateTimeStampISO8601Date(cdxVulnerability.Created)
	vulnInfo.Created = dateTime

	dateTime, _ = utils.TruncateTimeStampISO8601Date(cdxVulnerability.Published)
	vulnInfo.Published = dateTime

	dateTime, _ = utils.TruncateTimeStampISO8601Date(cdxVulnerability.Updated)
	vulnInfo.Updated = dateTime

	dateTime, _ = utils.TruncateTimeStampISO8601Date(cdxVulnerability.Rejected)
	vulnInfo.Rejected = dateTime

	vulnInfo.Description = cdxVulnerability.Description

	// Source object: retrieve report fields from nested objects
	if cdxVulnerability.Source != nil {
		source := *cdxVulnerability.Source
		vulnInfo.Source = source
		vulnInfo.SourceName = source.Name
		vulnInfo.SourceUrl = source.Url
	}

	// TODO: replace empty Analysis values with "UNDEFINED"
	if cdxVulnerability.Analysis != nil {
		vulnInfo.AnalysisState = cdxVulnerability.Analysis.State
		if vulnInfo.AnalysisState == "" {
			vulnInfo.AnalysisState = VULN_ANALYSIS_STATE_EMPTY
		}

		vulnInfo.AnalysisJustification = cdxVulnerability.Analysis.Justification
		if vulnInfo.AnalysisJustification == "" {
			vulnInfo.AnalysisJustification = VULN_ANALYSIS_STATE_EMPTY
		}

		vulnInfo.AnalysisResponse = *cdxVulnerability.Analysis.Response
		if len(vulnInfo.AnalysisResponse) == 0 {
			vulnInfo.AnalysisResponse = []string{VULN_ANALYSIS_STATE_EMPTY}
		}
	} else {
		vulnInfo.AnalysisState = VULN_ANALYSIS_STATE_EMPTY
		vulnInfo.AnalysisJustification = VULN_ANALYSIS_STATE_EMPTY
		vulnInfo.AnalysisResponse = []string{VULN_ANALYSIS_STATE_EMPTY}
	}

	// Convert []int to []string for --where filter
	// TODO see if we can eliminate this conversion and handle while preparing report data
	// as this SHOULD appear there as []interface{}
	if cdxVulnerability.Cwes != nil && len(*cdxVulnerability.Cwes) > 0 {
		// strip off slice/array brackets
		vulnInfo.CweIds = strings.Fields(strings.Trim(fmt.Sprint(cdxVulnerability.Cwes), "[]"))
	}

	// CVSS Score 	Qualitative Rating
	// 0.0 	        None
	// 0.1 – 3.9 	Low
	// 4.0 – 6.9 	Medium
	// 7.0 – 8.9 	High
	// 9.0 – 10.0 	Critical

	// TODO: if summary report, see if more than one severity can be shown without clogging up column data
	if cdxVulnerability.Ratings != nil && len(*cdxVulnerability.Ratings) > 0 {
		//var sourceMatch int
		for _, rating := range *cdxVulnerability.Ratings {
			// defer to same source as the top-level vuln. declares
			fSeverity := fmt.Sprintf("%s: %v (%s)", rating.Method, rating.Score, rating.Severity)
			// give listing priority to ratings that matches top-level vuln. reporting source
			if rating.Source.Name == cdxVulnerability.Source.Name {
				// prepend to slice
				vulnInfo.CvssSeverity = append([]string{fSeverity}, vulnInfo.CvssSeverity...)
				continue
			}
			vulnInfo.CvssSeverity = append(vulnInfo.CvssSeverity, fSeverity)
		}
	} else {
		// Set first entry to empty value (i.e., "none")
		vulnInfo.CvssSeverity = append(vulnInfo.CvssSeverity, VULN_RATING_EMPTY)
	}

	var match bool = true
	if len(whereFilters) > 0 {
		mapVulnInfo, _ := utils.MarshalStructToJsonMap(vulnInfo)
		match, _ = whereFilterMatch(mapVulnInfo, whereFilters)
	}

	if match {
		hashed = true
		bom.VulnerabilityMap.Put(vulnInfo.Id, vulnInfo)
		getLogger().Tracef("Put: %s (`%s`), `%s`)",
			vulnInfo.Id, vulnInfo.Description, vulnInfo.BOMRef)
	}

	return
}
