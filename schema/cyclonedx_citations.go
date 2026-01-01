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
// Note: TODO: support 3 signer options (i.e., Signer (string), chain ([]object), CDXSignature )
type CDXCitation struct {
	BOMRef       *CDXRefType `json:"bom-ref,omitempty" cdx:"+1.7"`
	Timestamp    string      `json:"timestamp,omitempty" scvs:"bom:core:timestamp" cdx:"+1.7"`
	Pointers     *[]string   `json:"pointers,omitempty" cdx:"+1.7"`
	AttributedTo string      `json:"attributedTo,omitempty" cdx:"+1.7"`
	Process      string      `json:"process,omitempty" cdx:"+1.7"`
	Note         string      `json:"note,omitempty" cdx:"+1.7"`
	Signature    interface{} `json:"signature,omitempty" cdx:"+1.7"`
}

// v1.7: added
type CDXSigner struct {
	Algorithm       string        `json:"algorithm,omitempty" cdx:"+1.7"`
	KeyId           string        `json:"keyId,omitempty" cdx:"+1.7"`
	PublicKey       *CDXPublicKey `json:"publicKey,omitempty" cdx:"+1.7"`
	CertificatePath *[]string     `json:"certificatePath,omitempty" cdx:"+1.7"`
	Excludes        *[]string     `json:"excludes,omitempty" cdx:"+1.7"`
	Value           string        `json:"value,omitempty" cdx:"+1.7"`
}

// v1.7: added
type CDXPublicKey struct {
	Kty string `json:"kty,omitempty" cdx:"+1.7"` // option 1, 2, 3
	Crv string `json:"crv,omitempty" cdx:"+1.7"` // option 1 ,2
	X   string `json:"x,omitempty" cdx:"+1.7"`   // option 1, 2
	Y   string `json:"y,omitempty" cdx:"+1.7"`   // option 1
	N   string `json:"n,omitempty" cdx:"+1.7"`   // option 3
	E   string `json:"e,omitempty" cdx:"+1.7"`   // option 3
}
