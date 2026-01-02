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

// v1.7: added
// "enum": [ "CLEAR", "GREEN", "AMBER", "AMBER_AND_STRICT", "RED" ],
type CDXTlpClassification string

type CDXDistributionConstraints struct {
	Tlp CDXTlpClassification `json:"tlp,omitempty" cdx:"+1.7"`
}

// v1.7: added
// Note: this is an in-line (anon.) type
// Note: Asserter is OneOf organizationEntity, OrganizationalContact or refLinkType
// TODO: Notes implies array, but the defn. is a single string
type CDXPatentAssertion struct {
	BOMRef        *CDXRefType   `json:"bom-ref,omitempty" cdx:"+1.7"`
	AssertionType string        `json:"assertionType,omitempty" cdx:"+1.7"`
	PatentRefs    *[]CDXRefType `json:"patentRefs,omitempty" cdx:"+1.7"`
	Asserter      interface{}   `json:"asserter,omitempty" cdx:"+1.7"`
	Notes         string        `json:"notes,omitempty" cdx:"+1.7"`
}

// v1.7: added
// Note: "pattern": "^[A-Za-z0-9][A-Za-z0-9\\-/.()\\s]{0,28}[A-Za-z0-9]$"
type CDXPatentNumber string
type CDXPatentApplicationNumber CDXPatentNumber
type CDXPublicationNumber CDXPatentNumber

// v1.7: added
// Note: "pattern": "^[A-Z]{2}$"
type CDXPatentJurisdiction string

// v1.7: added
type CDXPriorityApplication struct {
	ApplicationNumber CDXPatentApplicationNumber `json:"applicationNumber,omitempty" cdx:"+1.7"`
	Jurisdiction      CDXPatentJurisdiction      `json:"jurisdiction,omitempty" cdx:"+1.7"`
	FilingDate        string                     `json:"filingDate,omitempty" cdx:"+1.7"`
}

// v1.7: added
type CDXPatentFamily struct {
	FamilyId            string                  `json:"familyId,omitempty" cdx:"+1.7"`
	BOMRef              *CDXRefType             `json:"bom-ref,omitempty" cdx:"+1.7"`
	PriorityApplication *CDXPriorityApplication `json:"priorityApplication,omitempty" cdx:"+1.7"`
	Members             *[]CDXRefLinkType       `json:"members,omitempty" cdx:"+1.7"`
	ExternalReferences  *[]CDXExternalReference `json:"externalReferences,omitempty" cdx:"+1.7"`
}

// v1.7: added
type CDXPatent struct {
	BOMRef                  *CDXRefType                `json:"bom-ref,omitempty" cdx:"+1.7"`
	PatentNumber            CDXPatentNumber            `json:"patentNumber,omitempty" cdx:"+1.7"`
	PatentApplicationNumber CDXPatentApplicationNumber `json:"patentApplicationNumber,omitempty" cdx:"+1.7"`
	Jurisdiction            CDXPatentJurisdiction      `json:"jurisdiction,omitempty" cdx:"+1.7"`
	PriorityApplication     *CDXPriorityApplication    `json:"priorityApplication,omitempty" cdx:"+1.7"`
	PublicationNumber       CDXPublicationNumber       `json:"publicationNumber,omitempty" cdx:"+1.7"`
	Title                   string                     `json:"title,omitempty" cdx:"+1.7"`
	Abstract                string                     `json:"abstract,omitempty" cdx:"+1.7"`
	FilingDate              string                     `json:"filingDate,omitempty" cdx:"+1.7"`
	GrantDate               string                     `json:"grantDate,omitempty" cdx:"+1.7"`
	PatentExpirationDate    string                     `json:"patentExpirationDate,omitempty" cdx:"+1.7"`
	PatentLegalStatus       string                     `json:"patentLegalStatus,omitempty" cdx:"+1.7"`
	PatentAssignee          *CDXLegalParty             `json:"patentAssignee,omitempty" cdx:"+1.7"`
	ExternalReferences      *[]CDXExternalReference    `json:"externalReferences,omitempty" cdx:"+1.7"`
}

// v1.7: added
// Note: copy of CDXLicenseLegalParty type; make an abstract type
type CDXLegalParty struct {
	Organization *CDXOrganizationalEntity  `json:"organization,omitempty"`
	Individual   *CDXOrganizationalContact `json:"individual,omitempty"`
}
