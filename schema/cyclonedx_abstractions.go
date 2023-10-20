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

import "golang.org/x/exp/slices"

// -------------------
// Resources
// -------------------

// resource types
const (
	RESOURCE_TYPE_DEFAULT   = "" // i.e., all resource types
	RESOURCE_TYPE_COMPONENT = "component"
	RESOURCE_TYPE_SERVICE   = "service"
)

var VALID_RESOURCE_TYPES = []string{RESOURCE_TYPE_DEFAULT, RESOURCE_TYPE_COMPONENT, RESOURCE_TYPE_SERVICE}

func IsValidResourceType(value string) bool {
	return slices.Contains(VALID_RESOURCE_TYPES, value)
}

// TODO: need to strip `-` from `bom-ref` for where filter
// To be clear, we need the "json:" annotations to enable "where" filter
// "key=value" matches when hashing resources since we apply it to a
// JSON map:
//
//	mapResourceInfo, _ := utils.ConvertStructToMap(resourceInfo)
//	match, _ = whereFilterMatch(mapResourceInfo, whereFilters)
//
// If we could normalize to lowercase and remove "-" chars we may not
// need to use any JSON annotations.
// Please note that the JSON annotations MUST match those declared by
// the CDX types CDXComponent and CDXService.
type CDXResourceInfo struct {
	IsRoot           bool
	Type             string `json:"type"`
	BOMRef           string `json:"bom-ref"`
	Name             string `json:"name"`
	Version          string `json:"version"`
	SupplierProvider CDXOrganizationalEntity
	Properties       []CDXProperty
	Component        CDXComponent
	Service          CDXService
}

// -------------------
// Vulnerabilities
// -------------------

// default / "empty" values
const (
	VULN_DATE_EMPTY           = "none"
	VULN_ANALYSIS_STATE_EMPTY = "UNDEFINED"
	VULN_RATING_EMPTY         = "none"
)

// This data consolidates nested information into a flattened version more suitable for report listings
type VulnerabilityInfo struct {
	Id                    string                 `json:"id"`
	BOMRef                string                 `json:"bom-ref"`
	CvssSeverity          []string               `json:"cvss-severity"`
	Created               string                 `json:"created"`
	Published             string                 `json:"published"`
	Updated               string                 `json:"updated"`
	Rejected              string                 `json:"rejected"`
	Description           string                 `json:"description"`
	SourceUrl             string                 `json:"source-url"`
	SourceName            string                 `json:"source-name"`
	AnalysisState         string                 `json:"analysis-state"`
	AnalysisJustification string                 `json:"analysis-justification"`
	AnalysisResponse      []string               `json:"analysis-response"`
	CweIds                []string               `json:"cwe-ids"`
	Source                CDXVulnerabilitySource `json:"source"`
	Vulnerability         CDXVulnerability
}
