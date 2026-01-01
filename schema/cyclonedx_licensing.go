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

// v1.5: added as an anon. object under component->license
type CDXLicensing struct {
	AltIds        *[]string             `json:"altIds,omitempty" cdx:"added:1.5"`
	Licensor      *CDXLicenseLegalParty `json:"licensor,omitempty" cdx:"added:1.5"`
	Licensee      *CDXLicenseLegalParty `json:"licensee,omitempty" cdx:"added:1.5"`
	Purchaser     *CDXLicenseLegalParty `json:"purchaser,omitempty" cdx:"added:1.5"`
	PurchaseOrder string                `json:"purchaseOrder,omitempty" cdx:"added:1.5"`
	LicenseTypes  *[]string             `json:"licenseTypes,omitempty" cdx:"added:1.5"`
	LastRenewal   string                `json:"lastRenewal,omitempty" cdx:"added:1.5"`
	Expiration    string                `json:"expiration,omitempty" cdx:"added:1.5"`
}

// v1.5: created for reuse in "licensing" schema for "licensee" and "licensor"
// TODO: reuse on "annotator" as well?
// TODO: copied to CDXLegalParty for patents... make abstract and reuse
type CDXLicenseLegalParty struct {
	Organization *CDXOrganizationalEntity  `json:"organization,omitempty"`
	Individual   *CDXOrganizationalContact `json:"individual,omitempty"`
}
