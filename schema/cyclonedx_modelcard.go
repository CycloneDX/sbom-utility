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

// Note: "Model card" support in CycloneDX is derived from TensorFlow Model Card Toolkit released
// under the Apache 2.0 license and available from:
// https://github.com/tensorflow/model-card-toolkit/blob/main/model_card_toolkit/schema/v0.0.2/model_card.schema.json. In addition, CycloneDX model card support includes portions of VerifyML, also released under the Apache 2.0 license and available from https://github.com/cylynx/verifyml/blob/main/verifyml/model_card_toolkit/schema/v0.0.4/model_card.schema.json.",

// v1.5: added
// NOTE: CDXRefType is a named `string` type as of v1.5
type CDXModelCard struct {
	BOMRef               *CDXRefType              `json:"bom-ref,omitempty" cdx:"+1.5"`              // v1.5
	ModelParameters      *CDXModelParameters      `json:"modelParameters,omitempty" cdx:"+1.5"`      // v1.5
	QuantitativeAnalysis *CDXQuantitativeAnalysis `json:"quantitativeAnalysis,omitempty" cdx:"+1.5"` // v1.5
	Considerations       *CDXConsiderations       `json:"considerations,omitempty" cdx:"+1.5"`       // v1.5
	Properties           *[]CDXProperty           `json:"properties,omitempty" cdx:"+1.5"`           // v1.5
}

// ========================================
// Model Parameters
// ========================================

// v1.5: added
type CDXModelParameters struct {
	Approach           *CDXApproach                  `json:"approach,omitempty" cdx:"+1.5"`           // v1.5
	Task               string                        `json:"task,omitempty" cdx:"+1.5"`               // v1.5
	ArchitectureFamily string                        `json:"architectureFamily,omitempty" cdx:"+1.5"` // v1.5
	ModelArchitecture  string                        `json:"modelArchitecture,omitempty" cdx:"+1.5"`  // v1.5
	Datasets           *[]CDXDataset                 `json:"datasets,omitempty" cdx:"+1.5"`           // v1.5
	Inputs             *[]CDXInputOutputMLParameters `json:"inputs,omitempty" cdx:"+1.5"`             // v1.5
	Outputs            *[]CDXInputOutputMLParameters `json:"outputs,omitempty" cdx:"+1.5"`            // v1.5
}

// v1.5: added
// "Learning types describing the learning problem or hybrid learning problem."
// "enum": ["supervised","unsupervised","reinforcement-learning","semi-supervised","self-supervised"]
type CDXApproach struct {
	Type string `json:"type,omitempty" cdx:"+1.5"` // v1.5
}

// v1.5: added.
// v1.5: Note: "ref" is a constrained "string" which can be "anyOf": ["#/definitions/refLinkType", "#/definitions/bomLinkElementType"]
// TODO: actually, "Ref" should be its own anonymous type with "anyOf": ["#/definitions/refLinkType", "#/definitions/bomLinkElementType"]
type CDXDataset struct {
	CDXComponentData
	Ref *CDXRefLinkType `json:"ref,omitempty" cdx:"+1.5"` // v1.5
}

// v1.5: added
// "The data format for input/output to the model.
// Example formats include string, image, time-series",
type CDXInputOutputMLParameters struct {
	Format string `json:"format,omitempty" cdx:"+1.5"` // v1.5
}

// ========================================
// Quantitative Analysis
// ========================================

// v1.5: added (anonymous type)
type CDXQuantitativeAnalysis struct {
	PerformanceMetrics *[]CDXPerformanceMetric `json:"performanceMetrics,omitempty" cdx:"+1.5"` // v1.5
	Graphics           *CDXGraphicsCollection  `json:"graphics,omitempty" cdx:"+1.5"`           // v1.5
}

// v1.5: added
type CDXPerformanceMetric struct {
	Type               string                 `json:"type,omitempty" cdx:"+1.5"`               // v1.5
	Value              string                 `json:"value,omitempty" cdx:"+1.5"`              // v1.5
	Slice              string                 `json:"slice,omitempty" cdx:"+1.5"`              // v1.5
	ConfidenceInterval *CDXConfidenceInterval `json:"confidenceInterval,omitempty" cdx:"+1.5"` // v1.5
}

// v1.5: added
type CDXConfidenceInterval struct {
	LowerBound string `json:"lowerBound,omitempty" cdx:"+1.5"` // v1.5
	UpperBound string `json:"upperBound,omitempty" cdx:"+1.5"` // v1.5
}

// v1.5: added
type CDXGraphicsCollection struct {
	Description string        `json:"description,omitempty" cdx:"+1.5"` // v1.5
	Collection  *[]CDXGraphic `json:"collection,omitempty" cdx:"+1.5"`  // v1.5
}

// v1.5: added
type CDXGraphic struct {
	Name  string         `json:"name,omitempty" cdx:"+1.5"`  // v1.5
	Image *CDXAttachment `json:"image,omitempty" cdx:"+1.5"` // v1.5
}

// ========================================
// Considerations
// ========================================

// v1.5: added (anonymous type)
// Considerations that should be taken into account regarding the model's construction,
// training, and application
type CDXConsiderations struct {
	Users                       *[]string                       `json:"users,omitempty" cdx:"+1.5"`                       // v1.5
	UseCases                    *[]string                       `json:"useCases,omitempty" cdx:"+1.5"`                    // v1.5
	TechnicalLimitations        *[]string                       `json:"technicalLimitations,omitempty" cdx:"+1.5"`        // v1.5
	PerformanceTradeoffs        *[]string                       `json:"performanceTradeoffs,omitempty" cdx:"+1.5"`        // v1.5
	EthicalConsiderations       *[]CDXRisk                      `json:"ethicalConsiderations,omitempty" cdx:"+1.5"`       // v1.5
	FairnessAssessments         *[]CDXFairnessAssessment        `json:"fairnessAssessments,omitempty" cdx:"+1.5"`         // v1.5
	EnvironmentalConsiderations *CDXEnvironmentalConsiderations `json:"environmentalConsiderations,omitempty" cdx:"+1.6"` // v1.6
}

// v1.5: added
type CDXRisk struct {
	Name               string `json:"name,omitempty" cdx:"+1.5"`               // v1.5
	MitigationStrategy string `json:"mitigationStrategy,omitempty" cdx:"+1.5"` // v1.5
}

// v1.5: added
// Information about the benefits and harms of the model to an identified at risk group.
type CDXFairnessAssessment struct {
	GroupAtRisk        string `json:"groupAtRisk,omitempty" cdx:"+1.5"`        // v1.5
	Benefits           string `json:"benefits,omitempty" cdx:"+1.5"`           // v1.5
	Harms              string `json:"harms,omitempty" cdx:"+1.5"`              // v1.5
	MitigationStrategy string `json:"mitigationStrategy,omitempty" cdx:"+1.5"` // v1.5
}

// v1.6: added
// Information about the benefits and harms of the model to an identified at risk group.
type CDXEnvironmentalConsiderations struct {
	EnergyConsumptions *[]CDXEnergyConsumption `json:"energyConsumptions,omitempty" cdx:"+1.6"` // v1.6
	Properties         *[]CDXProperty          `json:"properties,omitempty" cdx:"+1.6"`         // v1.6
}

// v1.6: added
type CDXEnergyConsumption struct {
	Activity           string               `json:"activity,omitempty" cdx:"+1.6"`           // v1.6
	EnergyProviders    *[]CDXEnergyProvider `json:"energyProviders,omitempty" cdx:"+1.6"`    // v1.6
	ActivityEnergyCost *CDXEnergyMeasure    `json:"activityEnergyCost,omitempty" cdx:"+1.6"` // v1.6
	Co2CostEquivalent  *CDXCo2Measure       `json:"co2CostEquivalent,omitempty" cdx:"+1.6"`  // v1.6
	Co2CostOffset      *CDXCo2Measure       `json:"co2CostOffset,omitempty" cdx:"+1.6"`      // v1.6
	Properties         *[]CDXProperty       `json:"properties,omitempty" cdx:"+1.6"`         // v1.6
}

// v1.6: added
type CDXEnergyMeasure struct {
	Value float64 `json:"value,omitempty" cdx:"+1.6"` // v1.6
	Unit  string  `json:"unit,omitempty" cdx:"+1.6"`  // v1.6
}

// v1.6: added
type CDXCo2Measure struct {
	Value float64 `json:"value,omitempty" cdx:"+1.6"` // v1.6
	Unit  string  `json:"unit,omitempty" cdx:"+1.6"`  // v1.6
}

// v1.6: added
type CDXEnergyProvider struct {
	BOMRef             *CDXRefType              `json:"bom-ref,omitempty" cdx:"+1.6"`            // v1.6
	Description        string                   `json:"description,omitempty" cdx:"+1.6"`        // v1.6
	Organization       *CDXOrganizationalEntity `json:"organization,omitempty" cdx:"+1.6"`       // v1.6
	EnergySource       string                   `json:"energySource,omitempty" cdx:"+1.6"`       // v1.6
	EnergyProvided     *CDXEnergyMeasure        `json:"energyProvided,omitempty" cdx:"+1.6"`     // v1.6
	ExternalReferences *[]CDXExternalReference  `json:"externalReferences,omitempty" cdx:"+1.6"` // v1.6
}

// v1.6: added
type CDXPostalAddress struct {
	BOMRef              *CDXRefType `json:"bom-ref,omitempty" cdx:"+1.6"`             // v1.6
	Country             string      `json:"country,omitempty" cdx:"+1.6"`             // v1.6
	Region              string      `json:"region,omitempty" cdx:"+1.6"`              // v1.6
	Locality            string      `json:"locality,omitempty" cdx:"+1.6"`            // v1.6
	PostOfficeBoxNumber string      `json:"postOfficeBoxNumber,omitempty" cdx:"+1.6"` // v1.6
	PostalCode          string      `json:"postalCode,omitempty" cdx:"+1.6"`          // v1.6
	StreetAddress       string      `json:"streetAddress,omitempty" cdx:"+1.6"`       // v1.6
}
