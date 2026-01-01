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

// v1.6: added
// v1.7: Patents can either be a patent or a patentFamily type
type CDXDefinition struct {
	Standards *[]CDXStandard `json:"standards,omitempty" cdx:"+1.6"` // v1.6 added
	Patents   *[]any         `json:"patents,omitempty" cdx:"+1.7"`   // v1.7 added
}

// v1.6: added
// NOTE: The "Owner" field SHOULD be a CDXOrganizationalEntity OR CDXOrganizationalContact
// We have structures that already support this concept!!!
type CDXStandard struct {
	BOMRef             *CDXRefType             `json:"bom-ref,omitempty" cdx:"+1.6"`            // v1.6 added
	Name               string                  `json:"name,omitempty" cdx:"+1.6"`               // v1.6 added
	Version            string                  `json:"version,omitempty" cdx:"+1.6"`            // v1.6 added
	Description        string                  `json:"description,omitempty" cdx:"+1.6"`        // v1.6 added
	Owner              string                  `json:"owner,omitempty" cdx:"+1.6"`              // v1.6 added
	Requirements       *[]CDXRequirement       `json:"requirements,omitempty" cdx:"+1.6"`       // v1.6 added
	Levels             *[]CDXLevel             `json:"levels,omitempty" cdx:"+1.6"`             // v1.6 added
	ExternalReferences *[]CDXExternalReference `json:"externalReferences,omitempty" cdx:"+1.6"` // v1.6 added
	Signature          *JSFSignature           `json:"signature,omitempty" cdx:"+1.6"`          // v1.6 added
}

// v1.6: added
type CDXRequirement struct {
	BOMRef             *CDXRefType             `json:"bom-ref,omitempty" cdx:"+1.6"`            // v1.6 added
	Identifier         string                  `json:"identifier,omitempty" cdx:"+1.6"`         // v1.6 added
	Title              string                  `json:"title,omitempty" cdx:"+1.6"`              // v1.6 added
	Text               string                  `json:"text,omitempty" cdx:"+1.6"`               // v1.6 added
	Descriptions       *[]string               `json:"descriptions,omitempty" cdx:"+1.6"`       // v1.6 added
	OpenCre            *[]string               `json:"openCre,omitempty" cdx:"+1.6"`            // v1.6 added
	Parent             *CDXRefLinkType         `json:"parent,omitempty" cdx:"+1.6"`             // v1.6 added
	Properties         *[]CDXProperty          `json:"properties,omitempty" cdx:"+1.6"`         // v1.6 added
	ExternalReferences *[]CDXExternalReference `json:"externalReferences,omitempty" cdx:"+1.6"` // v1.6 added
}

// v1.6: added
type CDXLevel struct {
	BOMRef       *CDXRefType       `json:"bom-ref,omitempty" cdx:"+1.6"`      // v1.6 added
	Identifier   string            `json:"identifier,omitempty" cdx:"+1.6"`   // v1.6 added
	Title        string            `json:"title,omitempty" cdx:"+1.6"`        // v1.6 added
	Description  string            `json:"description,omitempty" cdx:"+1.6"`  // v1.6 added
	Requirements *[]CDXRefLinkType `json:"requirements,omitempty" cdx:"+1.6"` // v1.6 added
}
