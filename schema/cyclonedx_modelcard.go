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

// v1.5: added
type CDXModelCard struct {
	BomRef               CDXRefType              `json:"bom-ref,omitempty"`
	ModelParameters      CDXModelParameters      `json:"modelParameters,omitempty"`
	QuantitativeAnalysis CDXQuantitativeAnalysis `json:"quantitativeAnalysis,omitempty"`
	Considerations       CDXConsiderations       `json:"considerations,omitempty"`
	Properties           []CDXProperty           `json:"properties,omitempty"`
}

// ========================================
// Model Parameters
// ========================================

// v1.5: added
type CDXModelParameters struct {
	Approach           CDXApproach                  `json:"approach,omitempty"`
	Task               string                       `json:"task,omitempty"`
	ArchitectureFamily string                       `json:"architectureFamily,omitempty"`
	ModelArchitecture  string                       `json:"modelArchitecture,omitempty"`
	Datasets           []CDXDataset                 `json:"datasets,omitempty"`
	Inputs             []CDXInputOutputMLParameters `json:"inputs,omitempty"`
	Outputs            []CDXInputOutputMLParameters `json:"outputs,omitempty"`
}

// v1.5: added
// "Learning types describing the learning problem or hybrid learning problem."
// "enum": ["supervised","unsupervised","reinforcement-learning","semi-supervised","self-supervised"]
type CDXApproach struct {
	Type string `json:"type,omitempty"`
}

// v1.5: added
// Constraint: "oneOf": ["#/definitions/componentData", "ref"]
// TODO: actually, "Ref" should be its own anonymous type with "anyOf": ["#/definitions/refLinkType", "#/definitions/bomLinkElementType"]
type CDXDataset struct {
	CDXComponentData
	Ref CDXRefLinkType `json:"ref,omitempty"`
}

// v1.5: added
// "The data format for input/output to the model.
// Example formats include string, image, time-series",
type CDXInputOutputMLParameters struct {
	Format string `json:"format,omitempty"`
}

// ========================================
// Quantitative Analysis
// ========================================

// v1.5: added (anonymous type)
type CDXQuantitativeAnalysis struct {
	PerformanceMetrics []CDXPerformanceMetric `json:"performanceMetrics,omitempty"`
	Graphics           CDXGraphicsCollection  `json:"graphics,omitempty"`
}

// v1.5: added
type CDXPerformanceMetric struct {
	Type               string                `json:"type,omitempty"`
	Value              string                `json:"value,omitempty"`
	Slice              string                `json:"slice,omitempty"`
	ConfidenceInterval CDXConfidenceInterval `json:"confidenceInterval,omitempty"`
}

// v1.5: added
type CDXConfidenceInterval struct {
	LowerBound string `json:"lowerBound,omitempty"`
	UpperBound string `json:"upperBound,omitempty"`
}

// v1.5: added
type CDXGraphicsCollection struct {
	Description string       `json:"description,omitempty"`
	Collection  []CDXGraphic `json:"collection,omitempty"`
}

// v1.5: added
type CDXGraphic struct {
	Name  string        `json:"name,omitempty"`
	Image CDXAttachment `json:"image,omitempty"`
}

// ========================================
// Considerations
// ========================================

// v1.5: added (anonymous type)
// Considerations that should be taken into account regarding the model's construction,
// training, and application
type CDXConsiderations struct {
	Users                 []string                `json:"users,omitempty"`
	UseCases              []string                `json:"useCases,omitempty"`
	TechnicalLimitations  []string                `json:"technicalLimitations,omitempty"`
	PerformanceTradeoffs  []string                `json:"performanceTradeoffs,omitempty"`
	EthicalConsiderations []CDXRisk               `json:"ethicalConsiderations,omitempty"`
	FairnessAssessments   []CDXFairnessAssessment `json:"fairnessAssessments,omitempty"`
}

// v1.5: added
type CDXRisk struct {
	Name               string `json:"name,omitempty"`
	MitigationStrategy string `json:"mitigationStrategy,omitempty"`
}

// v1.5: added
// Information about the benefits and harms of the model to an identified at risk group.
type CDXFairnessAssessment struct {
	GroupAtRisk        string `json:"groupAtRisk,omitempty"`
	Benefits           string `json:"benefits,omitempty"`
	Harms              string `json:"harms,omitempty"`
	MitigationStrategy string `json:"mitigationStrategy,omitempty"`
}
