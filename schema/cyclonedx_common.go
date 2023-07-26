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

// v1.4 added
// v1.5 added Constraints: "minLength": 1
type CDXRefType string

// v1.5 added Stringer interface
func (ref CDXRefType) String() string {
	return string(ref)
}

// v1.5 added
type CDXRefLinkType CDXRefType // "allOf": [{"$ref": "#/definitions/refType"}]

// v1.5 added Stringer interface
func (ref CDXRefLinkType) String() string {
	return string(ref)
}

// v1.5 added. Constraints: "format": "iri-reference", "pattern": "^urn:cdx: ... "
type CDXBomLinkDocumentType string

// v1.5 added Stringer interface
func (link CDXBomLinkDocumentType) String() string {
	return string(link)
}

// v1.5 added. Constraints: "format": "iri-reference", "pattern": "^urn:cdx: ... "
type CDXBomLinkElementType string

// v1.5 added Stringer interface
func (link CDXBomLinkElementType) String() string {
	return string(link)
}

// v1.5 added. Constraints: "anyOf": ["#/definitions/bomLinkDocumentType", "#/definitions/bomLinkElementType"]
// TODO see what happens if we use a struct with the 2 possible types (i.e., an interface{})
type CDXBomLink string

func (link CDXBomLink) String() string {
	return string(link)
}

// v1.2: existed
type CDXAttachment struct {
	ContentType string `json:"contentType,omitempty"`
	Encoding    string `json:"encoding,omitempty"`
	Content     string `json:"content,omitempty"`
}

// v1.2: existed
// Note: "alg" is of type "hash-alg" which is a constrained `string` type
// Note: "content" is of type "hash-content" which is a constrained `string` type
type CDXHash struct {
	Alg     string `json:"alg,omitempty"`
	Content string `json:"content,omitempty"`
}

// v1.5 new type for "metadata"
type CDXNameDescription struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// v1.4: created "note" defn.
// Note: "locale" is of type "localeType" which is a constrained `string`
type CDXNote struct {
	Locale string        `json:"locale,omitempty"`
	Text   CDXAttachment `json:"attachment,omitempty"`
}

// v1.2: existed
// v1.5: added "bom-ref"
type CDXOrganizationalEntity struct {
	Name    string                     `json:"name,omitempty"`
	Url     []string                   `json:"url,omitempty"`
	Contact []CDXOrganizationalContact `json:"contact,omitempty"`
	BomRef  CDXRefType                 `json:"bom-ref,omitempty"` // v1.5 added
}

// v1.2: existed
// v1.5: added "bom-ref"
type CDXOrganizationalContact struct {
	Name   string     `json:"name,omitempty"`
	Email  string     `json:"email,omitempty"`
	Phone  string     `json:"phone,omitempty"`
	BomRef CDXRefType `json:"bom-ref,omitempty"` // v1.5 added
}

// v1.3: created "property" defn.
type CDXProperty struct {
	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`
}

// v1.5: created for reuse in "licensing" schema for "licensee" and "licensor"
// TODO: reuse on "annotator" as well?
type CDXLicenseLegalParty struct {
	Organization CDXOrganizationalEntity  `json:"organization,omitempty"`
	Individual   CDXOrganizationalContact `json:"individual,omitempty"`
}
