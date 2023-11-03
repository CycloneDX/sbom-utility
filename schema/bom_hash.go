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
	"fmt"
	"reflect"
	"runtime/debug"
	"strconv"
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
func (bom *BOM) HashComponentResources(whereFilters []common.WhereFilter) (err error) {
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
		_, err = bom.HashComponent(*pMetadataComponent, whereFilters, true)
		if err != nil {
			return
		}
	}

	// Hash all components found in the (root).components[] (+ "nested" components)
	pComponents := bom.GetCdxComponents()
	if pComponents != nil && len(*pComponents) > 0 {
		//if components := bom.GetCdxComponents(); len(*components) > 0 {
		if err = bom.HashComponents(*pComponents, whereFilters, false); err != nil {
			return
		}
	}
	return
}

// TODO: use pointer for []CDXComponent
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
// TODO: we should WARN if version is not a valid semver (e.g., examples/cyclonedx/BOM/laravel-7.12.0/bom.1.3.json)
// TODO: Use pointer for CDXComponent
func (bom *BOM) HashComponent(cdxComponent CDXComponent, whereFilters []common.WhereFilter, root bool) (ri *CDXResourceInfo, err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)
	var resourceInfo CDXResourceInfo
	ri = &resourceInfo

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
		mapResourceInfo, _ := utils.ConvertStructToMap(resourceInfo)
		match, _ = whereFilterMatch(mapResourceInfo, whereFilters)
	}

	if match {
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
		err = bom.HashComponents(*cdxComponent.Components, whereFilters, root)
		if err != nil {
			return
		}
	}
	return
}

// -------------------
// Services
// -------------------

func (bom *BOM) HashServiceResources(whereFilters []common.WhereFilter) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	pServices := bom.GetCdxServices()
	if pServices != nil && len(*pServices) > 0 {
		if err = bom.HashServices(*pServices, whereFilters); err != nil {
			return
		}
	}
	return
}

// TODO: use pointer for []CDXService
func (bom *BOM) HashServices(services []CDXService, whereFilters []common.WhereFilter) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	for _, cdxService := range services {
		_, err = bom.HashService(cdxService, whereFilters)
		if err != nil {
			return
		}
	}
	return
}

// Hash a CDX Component and recursively those of any "nested" components
// TODO: use pointer for CDXService
func (bom *BOM) HashService(cdxService CDXService, whereFilters []common.WhereFilter) (ri *CDXResourceInfo, err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)
	var resourceInfo CDXResourceInfo
	ri = &resourceInfo

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
		mapResourceInfo, _ := utils.ConvertStructToMap(resourceInfo)
		match, _ = whereFilterMatch(mapResourceInfo, whereFilters)
	}

	if match {
		// TODO: AppendLicenseInfo(LICENSE_NONE, resourceInfo)
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
		err = bom.HashServices(*pServices, whereFilters)
		if err != nil {
			return
		}
	}
	return
}

// -------------------
// Licenses
// -------------------

// -------------------
// Vulnerabilities
// -------------------

func (bom *BOM) HashVulnerabilityResources(whereFilters []common.WhereFilter) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	pVulnerabilities := bom.GetCdxVulnerabilities()

	if pVulnerabilities != nil && len(*pVulnerabilities) > 0 {
		if err = bom.HashVulnerabilities(*pVulnerabilities, whereFilters); err != nil {
			return
		}
	}
	return
}

// We need to hash our own informational structure around the CDX data in order
// to simplify --where queries to command line users
func (bom *BOM) HashVulnerabilities(vulnerabilities []CDXVulnerability, whereFilters []common.WhereFilter) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	for _, cdxVulnerability := range vulnerabilities {
		_, err = bom.HashVulnerability(cdxVulnerability, whereFilters)
		if err != nil {
			return
		}
	}
	return
}

// Hash a CDX Component and recursively those of any "nested" components
// TODO we should WARN if version is not a valid semver (e.g., examples/cyclonedx/BOM/laravel-7.12.0/bom.1.3.json)
func (bom *BOM) HashVulnerability(cdxVulnerability CDXVulnerability, whereFilters []common.WhereFilter) (vi *VulnerabilityInfo, err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)
	var vulnInfo VulnerabilityInfo
	vi = &vulnInfo

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

	if len(cdxVulnerability.Ratings) == 0 {
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
	vulnInfo.AnalysisState = cdxVulnerability.Analysis.State
	if vulnInfo.AnalysisState == "" {
		vulnInfo.AnalysisState = VULN_ANALYSIS_STATE_EMPTY
	}

	vulnInfo.AnalysisJustification = cdxVulnerability.Analysis.Justification
	if vulnInfo.AnalysisJustification == "" {
		vulnInfo.AnalysisJustification = VULN_ANALYSIS_STATE_EMPTY
	}
	vulnInfo.AnalysisResponse = cdxVulnerability.Analysis.Response
	if len(vulnInfo.AnalysisResponse) == 0 {
		vulnInfo.AnalysisResponse = []string{VULN_ANALYSIS_STATE_EMPTY}
	}

	// Convert []int to []string for --where filter
	// TODO see if we can eliminate this conversion and handle while preparing report data
	// as this SHOULD appear there as []interface{}
	if len(cdxVulnerability.Cwes) > 0 {
		vulnInfo.CweIds = strings.Fields(strings.Trim(fmt.Sprint(cdxVulnerability.Cwes), "[]"))
	}

	// CVSS Score 	Qualitative Rating
	// 0.0 	        None
	// 0.1 – 3.9 	Low
	// 4.0 – 6.9 	Medium
	// 7.0 – 8.9 	High
	// 9.0 – 10.0 	Critical

	// TODO: if summary report, see if more than one severity can be shown without clogging up column data
	numRatings := len(cdxVulnerability.Ratings)
	if numRatings > 0 {
		//var sourceMatch int
		for _, rating := range cdxVulnerability.Ratings {
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
		mapVulnInfo, _ := utils.ConvertStructToMap(vulnInfo)
		match, _ = whereFilterMatch(mapVulnInfo, whereFilters)
	}

	if match {
		bom.VulnerabilityMap.Put(vulnInfo.Id, vulnInfo)

		getLogger().Tracef("Put: %s (`%s`), `%s`)",
			vulnInfo.Id, vulnInfo.Description, vulnInfo.BOMRef)
	}

	return
}

// -------------------
// Misc
// -------------------

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
