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
// NOTE: This is an enum. (e.g., "algorithm", "certificate", "protocol", etc.)
type CDXAssetType struct {
	AssetType                       string                              `json:"assetType,omitempty" cdx:"+1.6"`                       // v1.6 added
	AlgorithmProperties             *CDXAlgorithmProperties             `json:"algorithmProperties,omitempty" cdx:"+1.6"`             // v1.6 added
	CertificateProperties           *CDXCertificateProperties           `json:"certificateProperties,omitempty" cdx:"+1.6"`           // v1.6 added
	RelatedCryptoMaterialProperties *CDXRelatedCryptoMaterialProperties `json:"relatedCryptoMaterialProperties,omitempty" cdx:"+1.6"` // v1.6 added
	ProtocolProperties              *CDXProtocolProperties              `json:"protocolProperties,omitempty" cdx:"+1.6"`              // v1.6 added
	Oid                             string                              `json:"oid,omitempty" cdx:"+1.6"`                             // v1.6 added
}

// v1.6: added
type CDXAlgorithmProperties struct {
	Primitive                string    `json:"primitive,omitempty" cdx:"+1.6"`                // v1.6 added
	ParameterSetIdentifier   string    `json:"parameterSetIdentifier,omitempty" cdx:"+1.6"`   // v1.6 added
	Curve                    string    `json:"curve,omitempty" cdx:"+1.6"`                    // v1.6 added
	ExecutionEnvironment     string    `json:"executionEnvironment,omitempty" cdx:"+1.6"`     // v1.6 added
	ImplementationPlatform   string    `json:"implementationPlatform,omitempty" cdx:"+1.6"`   // v1.6 added
	CertificationLevel       *[]string `json:"certificationLevel,omitempty" cdx:"+1.6"`       // v1.6 added
	Mode                     string    `json:"mode,omitempty" cdx:"+1.6"`                     // v1.6 added
	Padding                  string    `json:"padding,omitempty" cdx:"+1.6"`                  // v1.6 added
	CryptoFunctions          *[]string `json:"cryptoFunctions,omitempty" cdx:"+1.6"`          // v1.6 added
	ClassicalSecurityLevel   int       `json:"classicalSecurityLevel,omitempty" cdx:"+1.6"`   // v1.6 added
	NistQuantumSecurityLevel int       `json:"nistQuantumSecurityLevel,omitempty" cdx:"+1.6"` // v1.6 added                           `json:"oid,omitempty" cdx:"+1.6"`                             // v1.6 added
}

// v1.6: added
type CDXCertificateProperties struct {
	SubjectName           string      `json:"subjectName,omitempty" cdx:"+1.6"`           // v1.6 added
	IssuerName            string      `json:"issuerName,omitempty" cdx:"+1.6"`            // v1.6 added
	NotValidBefore        string      `json:"notValidBefore,omitempty" cdx:"+1.6"`        // v1.6 added
	NotValidAfter         string      `json:"notValidAfter,omitempty" cdx:"+1.6"`         // v1.6 added
	SignatureAlgorithmRef *CDXRefType `json:"signatureAlgorithmRef,omitempty" cdx:"+1.6"` // v1.6 added
	SubjectPublicKeyRef   *CDXRefType `json:"subjectPublicKeyRef,omitempty" cdx:"+1.6"`   // v1.6 added
	CertificateFormat     string      `json:"certificateFormat,omitempty" cdx:"+1.6"`     // v1.6 added
	CertificateExtension  string      `json:"certificateExtension,omitempty" cdx:"+1.6"`  // v1.6 added
}

type CDXRelatedCryptoMaterialProperties struct {
	Type           string        `json:"type,omitempty" cdx:"+1.6"`           // v1.6 added
	Id             string        `json:"id,omitempty" cdx:"+1.6"`             // v1.6 added
	State          string        `json:"state,omitempty" cdx:"+1.6"`          // v1.6 added
	AlgorithmRef   *CDXRefType   `json:"algorithmRef,omitempty" cdx:"+1.6"`   // v1.6 added
	CreationDate   string        `json:"creationDate,omitempty" cdx:"+1.6"`   // v1.6 added
	ActivationDate string        `json:"activationDate,omitempty" cdx:"+1.6"` // v1.6 added
	UpdateDate     string        `json:"updateDate,omitempty" cdx:"+1.6"`     // v1.6 added
	ExpirationDate string        `json:"expirationDate,omitempty" cdx:"+1.6"` // v1.6 added
	Value          string        `json:"value,omitempty" cdx:"+1.6"`          // v1.6 added
	Size           int           `json:"size,omitempty" cdx:"+1.6"`           // v1.6 added
	Format         string        `json:"format,omitempty" cdx:"+1.6"`         // v1.6 added
	SecuredBy      *CDXSecuredBy `json:"securedBy,omitempty" cdx:"+1.6"`      // v1.6 added
}

// v1.6: added
type CDXProtocolProperties struct {
	Type                string                  `json:"type,omitempty" cdx:"+1.6"`                // v1.6 added
	Version             string                  `json:"version,omitempty" cdx:"+1.6"`             // v1.6 added
	CipherSuites        *[]CDXCipherSuite       `json:"cipherSuites,omitempty" cdx:"+1.6"`        // v1.6 added
	Ikev2TransformTypes *CDXIkevV2TransformType `json:"ikev2TransformTypes,omitempty" cdx:"+1.6"` // v1.6 added
	CryptoRefArray      *CDXCryptoRefArray      `json:"cryptoRefArray,omitempty" cdx:"+1.6"`      // v1.6 added
}

// v1.6: added
type CDXCipherSuite struct {
	Name        string        `json:"name,omitempty" cdx:"+1.6"`        // v1.6 added
	Algorithms  *[]CDXRefType `json:"algorithms,omitempty" cdx:"+1.6"`  // v1.6 added
	Identifiers *[]string     `json:"identifiers,omitempty" cdx:"+1.6"` // v1.6 added
}

// v1.6: added
type CDXIkevV2TransformType struct {
	Encr  *CDXCryptoRefArray `json:"encr,omitempty" cdx:"+1.6"`  // v1.6 added
	Prf   *CDXCryptoRefArray `json:"prf,omitempty" cdx:"+1.6"`   // v1.6 added
	Integ *CDXCryptoRefArray `json:"integ,omitempty" cdx:"+1.6"` // v1.6 added
	Ke    *CDXCryptoRefArray `json:"ke,omitempty" cdx:"+1.6"`    // v1.6 added
	Esn   bool               `json:"esn,omitempty" cdx:"+1.6"`   // v1.6 added
	Auth  *CDXCryptoRefArray `json:"auth,omitempty" cdx:"+1.6"`  // v1.6 added
}

// v1.6: added
// TODO: NOTE: This is a first-of-kind, alias for a slice
// it SHOULD NOT exist unless this is adopted EVERYWHERE
type CDXCryptoRefArray []CDXRefType

// v1.6: added
type CDXSecuredBy struct {
	Mechanism    string      `json:"mechanism,omitempty" cdx:"+1.6"`    // v1.6 added
	AlgorithmRef *CDXRefType `json:"algorithmRef,omitempty" cdx:"+1.6"` // v1.6 added
}
