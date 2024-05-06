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

// v1.6: added "declarations"
type CDXDeclaration struct {
	Assessors    *[]CDXAssessor             `json:"assessors,omitempty" cdx:"+1.6"`    // v1.6 added
	Attestations *[]CDXAttestation          `json:"attestations,omitempty" cdx:"+1.6"` // v1.6 added
	Claims       *[]CDXClaim                `json:"claims,omitempty" cdx:"+1.6"`       // v1.6 added
	Evidence     *[]CDXEvidence             `json:"evidence,omitempty" cdx:"+1.6"`     // v1.6 added
	Targets      *[]CDXOrganizationalEntity `json:"targets,omitempty" cdx:"+1.6"`      // v1.6 added
	Affirmation  *CDXAffirmation            `json:"affirmation,omitempty" cdx:"+1.6"`  // v1.6 added
	Signature    *JSFSignature              `json:"signature,omitempty" cdx:"+1.6"`    // v1.6 added
}

// v1.6: added
type CDXAssessor struct {
	BOMRef       *CDXRefType              `json:"bom-ref,omitempty" cdx:"+1.6"`      // v1.6 added
	ThirdParty   bool                     `json:"thirdParty,omitempty" cdx:"+1.6"`   // v1.6 added
	Organization *CDXOrganizationalEntity `json:"organization,omitempty" cdx:"+1.6"` // v1.6 added
}

// v1.6: added
type CDXAttestation struct {
	Summary   string               `json:"summary,omitempty" cdx:"+1.6"`   // v1.6 added
	Assessor  *CDXRefType          `json:"assessor,omitempty" cdx:"+1.6"`  // v1.6 added
	Map       *[]CDXAttestationMap `json:"map,omitempty" cdx:"+1.6"`       // v1.6 added
	Signature *JSFSignature        `json:"signature,omitempty" cdx:"+1.6"` // v1.6 added
}

// v1.6: added
type CDXAttestationMap struct {
	Requirement   *CDXRefLinkType   `json:"requirement,omitempty" cdx:"+1.6"`   // v1.6 added
	Claims        *[]CDXRefLinkType `json:"claims,omitempty" cdx:"+1.6"`        // v1.6 added
	CounterClaims *[]CDXRefLinkType `json:"counterClaims,omitempty" cdx:"+1.6"` // v1.6 added
	Conformance   *CDXConformance   `json:"conformance,omitempty" cdx:"+1.6"`   // v1.6 added
	Confidence    *CDXConfidence    `json:"confidence,omitempty" cdx:"+1.6"`    // v1.6 added
}

// v1.6: added
// TODO: NOTE: overlap in fields with CDXConfidence
type CDXConformance struct {
	Score                float64           `json:"score,omitempty" cdx:"+1.6"`                // v1.6 added
	Rationale            string            `json:"rationale,omitempty" cdx:"+1.6"`            // v1.6 added
	MitigationStrategies *[]CDXRefLinkType `json:"mitigationStrategies,omitempty" cdx:"+1.6"` // v1.6 added
}

// v1.6: added
// TODO: NOTE: overlap in fields with CDXConformance
type CDXConfidence struct {
	Score     float64 `json:"score,omitempty" cdx:"+1.6"`     // v1.6 added
	Rationale string  `json:"rationale,omitempty" cdx:"+1.6"` // v1.6 added
}

// v1.6: added
type CDXClaim struct {
	BOMRef               *CDXRefType             `json:"bom-ref,omitempty" cdx:"+1.6"`              // v1.6 added
	Target               *[]CDXRefLinkType       `json:"target,omitempty" cdx:"+1.6"`               // v1.6 added
	Predicate            string                  `json:"predicate,omitempty" cdx:"+1.6"`            // v1.6 added
	MitigationStrategies *[]CDXRefLinkType       `json:"mitigationStrategies,omitempty" cdx:"+1.6"` // v1.6 added
	Reasoning            string                  `json:"reasoning,omitempty" cdx:"+1.6"`            // v1.6 added
	Evidence             *[]CDXRefLinkType       `json:"evidence,omitempty" cdx:"+1.6"`             // v1.6 added
	CounterEvidence      *[]CDXRefLinkType       `json:"counterEvidence,omitempty" cdx:"+1.6"`      // v1.6 added
	ExternalReferences   *[]CDXExternalReference `json:"externalReferences,omitempty" cdx:"+1.6"`   // v1.6 added
	Signature            *JSFSignature           `json:"signature,omitempty" cdx:"+1.6"`            // v1.6 added
}

// v1.6: added
type CDXEvidence struct {
	BOMRef       *CDXRefType               `json:"bom-ref,omitempty" cdx:"+1.6"`      // v1.6 added
	PropertyName string                    `json:"propertyName,omitempty" cdx:"+1.6"` // v1.6 added
	Description  string                    `json:"description,omitempty" cdx:"+1.6"`  // v1.6 added
	Data         *[]CDXData                `json:"data,omitempty" cdx:"+1.6"`         // v1.6 added
	Created      string                    `json:"created,omitempty" cdx:"+1.6"`      // v1.6 added
	Expires      string                    `json:"expires,omitempty" cdx:"+1.6"`      // v1.6 added
	Author       *CDXOrganizationalContact `json:"author,omitempty" cdx:"+1.6"`       // v1.6 added
	Reviewer     *CDXOrganizationalContact `json:"reviewer,omitempty" cdx:"+1.6"`     // v1.6 added
	Signature    *JSFSignature             `json:"signature,omitempty" cdx:"+1.6"`    // v1.6 added
}

// v1.6: added
// NOTE: The "Contents" field defines a structure that is identical to the CDXContent
// used in CDXComponentData, but does NOT have a "properties" field.
// we will reuse it here as it does NOT impact JSON encoding/decoding
// NOTE: The "Classification" field is actually an "enum" type in the JSON schema
type CDXData struct {
	Name           string         `json:"name,omitempty" cdx:"+1.6"`           // v1.6 added
	Contents       *CDXContent    `json:"contents,omitempty" cdx:"+1.6"`       // v1.6 added
	Classification string         `json:"classification,omitempty" cdx:"+1.6"` // v1.6 added
	SensitiveData  *[]string      `json:"sensitiveData,omitempty" cdx:"+1.6"`  // v1.6 added
	Governance     *CDXGovernance `json:"governance,omitempty" cdx:"+1.6"`     // v1.6 added
}

// v1.6: added
type CDXGovernance struct {
	Custodians *[]CDXDataGovernanceResponsibleParty `json:"custodians,omitempty" cdx:"+1.6"` // v1.6 added
	Stewards   *[]CDXDataGovernanceResponsibleParty `json:"stewards,omitempty" cdx:"+1.6"`   // v1.6 added
	Owners     *[]CDXDataGovernanceResponsibleParty `json:"owners,omitempty" cdx:"+1.6"`     // v1.6 added
}

// v1.6: added
type CDXAffirmation struct {
	Statement   string          `json:"statement,omitempty" cdx:"+1.6"`   // v1.6 added
	Signatories *[]CDXSignatory `json:"signatories,omitempty" cdx:"+1.6"` // v1.6 added
}

// v1.6: added
type CDXSignatory struct {
	Name string `json:"name,omitempty" cdx:"+1.6"` // v1.6 added
	Role string `json:"role,omitempty" cdx:"+1.6"` // v1.6 added
	// TODO:
	Signature          interface{}              `json:"signature,omitempty" cdx:"+1.6"`          // v1.6 added
	Organization       *CDXOrganizationalEntity `json:"organization,omitempty" cdx:"+1.6"`       // v1.6 added
	ExternalReferences *[]CDXExternalReference  `json:"externalReferences,omitempty" cdx:"+1.6"` // v1.6 added
}
