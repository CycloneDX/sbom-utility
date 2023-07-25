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

// See: https://github.com/CycloneDX/specification/blob/master/schema/jsf-0.82.schema.json

// Note: struct will contain "oneOf": []"Signers", "Chain", "Signature"]
type JSFSignature struct {
	// "Unique top level property for Multiple Signatures."
	Signers []JSFSigner `json:"signers,omitempty"`
	// "Unique top level property for Signature Chains."
	Chain []JSFSigner `json:"chain,omitempty"`
	// "Unique top level property for simple signatures."
	Signature JSFSigner `json:"signature,omitempty"`
}

// Algorithm: "Signature algorithm. The currently recognized JWA [RFC7518] and RFC8037
//   - constraint: "enum": ["RS256","RS384","RS512","PS256","PS384","PS512",
//     "ES256","ES384","ES512","Ed25519","Ed448","HS256","HS384","HS512"]
//   - OR contains a URI for custom algorithm (name)
//
// KeyId: "Optional. Application specific string identifying the signature key."
// PublicKey: "Optional. Public key object."
// CertificatePath: "Optional. Sorted array of X.509 [RFC5280] certificates, where the first element must contain the signature certificate. The certificate path must be contiguous but is not required to be complete."
// Excludes: "Optional. Array holding the names of one or more application level properties that must be excluded from the signature process. Note that the \"excludes\" property itself, must also be excluded from the signature process. Since both the \"excludes\" property and the associated data it points to are unsigned, a conforming JSF implementation must provide options for specifying which properties to accept."
// Value: "The signature data. Note that the binary representation must follow the JWA [RFC7518] specifications."
type JSFSigner struct {
	Algorithm       string       `json:"algorithm,omitempty"`
	KeyId           string       `json:"keyId,omitempty"`
	PublicKey       JSFPublicKey `json:"publicKey,omitempty"`
	CertificatePath []string     `json:"certificatePath,omitempty"`
	Excludes        []string     `json:"excludes,omitempty"`
	Value           string       `json:"value,omitempty"`
}

// constraint: "enum": ["EC","OKP","RSA"]
type JSFKeyType string

// if kty (key type)== "EC"
//   - required: "crv" (EC curve name), "x", "y"
//   - constraint "crv": "enum": ["P-256","P-384","P-521"]
//
// else if kty == "OKP"
//   - required: "crv" (EdDSA curve name), "x"
//   - constraint "crv" : "enum": ["Ed25519","Ed448"]
//
// else if kty == "RSA"
//   - required: n, e
type JSFPublicKey struct {
	Kty JSFKeyType `json:"kty,omitempty"` // Key Type
	Crv string     `json:"crv,omitempty"` // EC/OKP curve name
	X   string     `json:"x,omitempty"`   // X coordinate
	Y   string     `json:"y,omitempty"`   // Y coordinate
	N   string     `json:"n,omitempty"`   // RSA modulus
	E   string     `json:"e,omitempty"`   // RSA exponent

}
