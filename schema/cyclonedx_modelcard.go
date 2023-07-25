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

// Note: "Model card" support in CycloneDX is derived from TensorFlow Model Card Toolkit released
// under the Apache 2.0 license and available from:
// https://github.com/tensorflow/model-card-toolkit/blob/main/model_card_toolkit/schema/v0.0.2/model_card.schema.json. In addition, CycloneDX model card support includes portions of VerifyML, also released under the Apache 2.0 license and available from https://github.com/cylynx/verifyml/blob/main/verifyml/model_card_toolkit/schema/v0.0.4/model_card.schema.json.",

// v1.5 added
// "Learning types describing the learning problem or hybrid learning problem."
// "enum": ["supervised","unsupervised","reinforcement-learning","semi-supervised","self-supervised"]
type CDXApproach struct {
	Type string `json:"type,omitempty"`
}

// v1.5 added
type CDXModelParameters struct {
	Approach           CDXApproach `json:"approach,omitempty"`
	Task               string      `json:"task,omitempty"`
	ArchitectureFamily string      `json:"architectureFamily,omitempty"`
	ModelArchitecture  string      `json:"modelArchitecture,omitempty"`

	// 		  "datasets": {
	// 			"type": "array",
	// 			"title": "Datasets",
	// 			"description": "The datasets used to train and evaluate the model.",
	// 			"items" : {
	// 			  "oneOf" : [
	// 				{
	//                 "title": "Inline Component Data",
	//                 "$ref": "#/definitions/componentData"
	// 				},
	// 				{"type": "object",
	//                "properties": {
	// 					"ref": {
	// 					  "anyOf": [
	// 						{
	// 						  "title": "Ref",
	// 						  "$ref": "#/definitions/refLinkType"
	// 						},
	// 						{
	// 						  "title": "BOM-Link Element",
	// 						  "$ref": "#/definitions/bomLinkElementType"
	// 						}
	// 					  ],
	// 					  "title": "Reference",
	// 					  "description": "References a data component by the components bom-ref attribute"
	// 					}}
	// 				}
	// 			  ]
	// 			}
	// 		  },
	// 		  "inputs": {
	// 			"type": "array",
	// 			"title": "Inputs",
	// 			"description": "The input format(s) of the model",
	// 			"items": { "$ref": "#/definitions/inputOutputMLParameters" }
	// 		  },
	// 		  "outputs": {
	// 			"type": "array",
	// 			"title": "Outputs",
	// 			"description": "The output format(s) from the model",
	// 			"items": { "$ref": "#/definitions/inputOutputMLParameters" }
	// 		  }
}

// v1.5: added (anonymous type)
type CDXQuantitativeAnalysis struct {
	PerformanceMetrics []CDXPerformanceMetric `json:"performanceMetrics,omitempty"`
	Graphics           CDXGraphicsCollection  `json:"graphics,omitempty"`
}

// v1.5: added (anonymous type)
// Considerations that should be taken into account regarding the model's construction,
// training, and application
type CDXConsiderations struct {
	Users                 []string                `json:"users,omitempty"`
	UseCases              []string                `json:"useCases,omitempty"`
	TechnicalLimitations  []string                `json:"technicalLimitations,omitempty"`
	PerformanceTradeoffs  []string                `json:"performanceTradeoffs,omitempty"`
	EthicalConsiderations []string                `json:"ethicalConsiderations,omitempty"`
	FairnessAssessments   []CDXFairnessAssessment `json:"fairnessAssessments,omitempty"`
}

// v1.5 added
type CDXModelCard struct {
	BomRef               CDXRefType              `json:"bom-ref,omitempty"`
	ModelParameters      CDXModelParameters      `json:"modelParameters,omitempty"`
	QuantitativeAnalysis CDXQuantitativeAnalysis `json:"quantitativeAnalysis,omitempty"`
	Considerations       CDXConsiderations       `json:"considerations,omitempty"`
	Properties           []CDXProperty           `json:"properties,omitempty"`
}

// v1.5 added
// "The data format for input/output to the model.
// Example formats include string, image, time-series",
type CDXInputOutputMLParameters struct {
	Format string `json:"format,omitempty"`
}

// v1.5 added
type CDXContents struct {
	Attachment CDXAttachment `json:"attachment,omitempty"`
	Url        string        `json:"url,omitempty"`
	Properties []CDXProperty `json:"properties,omitempty"`
}

// v1.5 added
// Data classification tags data according to its type, sensitivity, and value if altered,
// stolen, or destroyed.
type CDXDataClassification string

// v1.5 added
// The general theme or subject matter of the data being specified.
//
//	__source-code__ = Any type of code, code snippet, or data-as-code.
//	__configuration__ = Parameters or settings that may be used by other components.
//	__dataset__ = A collection of data.
//	__definition__ = Data that can be used to create new instances of what the definition defines.
//	__other__ = Any other type of data that does not fit into existing definitions.,
//
// "type": "enum": ["source-code","configuration","dataset","definition","other"]
type CDXComponentData struct {
	BomRef         CDXRefType            `json:"bom-ref,omitempty"`
	Type           string                `json:"type,omitempty"`
	Name           string                `json:"name,omitempty"`
	Contents       CDXContents           `json:"contents,omitempty"`
	Classification CDXDataClassification `json:"classification,omitempty"`
	SensitiveData  []string              `json:"sensitiveData,omitempty"`
	Graphics       CDXGraphicsCollection `json:"graphics,omitempty"`
	Governance     CDXDataGovernance     `json:"governance,omitempty"`
}

// v1.5 added
type CDXDataGovernance struct {
	Custodians []CDXDataGovernanceResponsibleParty   `json:"custodians,omitempty"`
	Stewards   [][]CDXDataGovernanceResponsibleParty `json:"stewards,omitempty"`
	Owners     [][]CDXDataGovernanceResponsibleParty `json:"owners,omitempty"`
}

// v1.5 added. Constraints: "oneOf": ["organization", "contact"]
type CDXDataGovernanceResponsibleParty struct {
	Organization CDXOrganizationalEntity  `json:"organization,omitempty"`
	Contact      CDXOrganizationalContact `json:"contact,omitempty"`
}

// v1.5 added
type CDXGraphicsCollection struct {
	Description string       `json:"description,omitempty"`
	Collection  []CDXGraphic `json:"collection,omitempty"`
}

// v1.5 added
type CDXGraphic struct {
	Name  string        `json:"name,omitempty"`
	Image CDXAttachment `json:"image,omitempty"`
}

// v1.5 added
type CDXConfidenceInterval struct {
	LowerBound string `json:"lowerBound,omitempty"`
	UpperBound string `json:"upperBound,omitempty"`
}

// v1.5 added
type CDXPerformanceMetric struct {
	Type               string                `json:"type,omitempty"`
	Value              string                `json:"value,omitempty"`
	Slice              string                `json:"slice,omitempty"`
	ConfidenceInterval CDXConfidenceInterval `json:"confidenceInterval,omitempty"`
}

// v1.5 added
type CDXRisk struct {
	Name               string `json:"name,omitempty"`
	MitigationStrategy string `json:"mitigationStrategy,omitempty"`
}

// v1.5 added
// Information about the benefits and harms of the model to an identified at risk group.
type CDXFairnessAssessment struct {
	GroupAtRisk        string `json:"groupAtRisk,omitempty"`
	Benefits           string `json:"benefits,omitempty"`
	Harms              string `json:"harms,omitempty"`
	MitigationStrategy string `json:"mitigationStrategy,omitempty"`
}
