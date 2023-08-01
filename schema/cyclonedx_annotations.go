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

// v1.5 "annotations" and sub-schema added ("required": ["subjects","annotator","timestamp","text"])
type CDXAnnotation struct {
	BOMRef    CDXRefType   `json:"bom-ref,omitempty"`   // v1.5
	Subjects  []CDXSubject `json:"subjects,omitempty"`  // v1.5
	Annotator CDXAnnotator `json:"annotator,omitempty"` // v1.5
	Timestamp string       `json:"timestamp,omitempty"` // v1.5
	Text      string       `json:"text,omitempty"`      // v1.5
	Signature JSFSignature `json:"signature,omitempty"` // v1.5
}

// v1.5 added to represent the anonymous type defined in the "annotations" object
// Note: Since CDXSubject can be one of 2 other types (i.e., "#/definitions/refLinkType"
// and "#/definitions/bomLinkElementType") which both are "string" types
// we can also make it a "string" type as it does not affect constraint validation.
type CDXSubject string // v1.5

// v1.5 added to represent the anonymous type defined in the "annotations" object
// required" oneOf: organization, individual, component, service
type CDXAnnotator struct {
	Organization CDXOrganizationalEntity  `json:"organization,omitempty"` // v1.5
	Individual   CDXOrganizationalContact `json:"individual,omitempty"`   // v1.5
	Component    CDXComponent             `json:"component,omitempty"`    // v1.5
	Service      CDXService               `json:"service,omitempty"`      // v1.5
}
