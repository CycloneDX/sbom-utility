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
