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

// v1.5 added
type CDXModelCard struct {
	BomRef          CDXRefType         `json:"bom-ref,omitempty"`
	ModelParameters CDXModelParameters `json:"modelParameters,omitempty"`

	//		  "quantitativeAnalysis": {
	//			"type": "object",
	//			"description": "A quantitative analysis of the model",
	//			"additionalProperties": false,
	//			"properties": {
	//			  "performanceMetrics": {
	//				"type": "array",
	//				"title": "Performance Metrics",
	//				"description": "The model performance metrics being reported. Examples may include accuracy, F1 score, precision, top-3 error rates, MSC, etc.",
	//				"items": { "$ref": "#/definitions/performanceMetric" }
	//			  },
	//			  "graphics": { "$ref": "#/definitions/graphicsCollection" }
	//			}
	//		  },
	//		  "considerations": {
	//			"type": "object",
	//			"title": "Considerations",
	//			"description": "What considerations should be taken into account regarding the model's construction, training, and application?",
	//			"additionalProperties": false,
	//			"properties": {
	//			  "users": {
	//				"type": "array",
	//				"title": "Users",
	//				"description": "Who are the intended users of the model?",
	//				"items": {
	//				  "type": "string"
	//				}
	//			  },
	//			  "useCases": {
	//				"type": "array",
	//				"title": "Use Cases",
	//				"description": "What are the intended use cases of the model?",
	//				"items": {
	//				  "type": "string"
	//				}
	//			  },
	//			  "technicalLimitations": {
	//				"type": "array",
	//				"title": "Technical Limitations",
	//				"description": "What are the known technical limitations of the model? E.g. What kind(s) of data should the model be expected not to perform well on? What are the factors that might degrade model performance?",
	//				"items": {
	//				  "type": "string"
	//				}
	//			  },
	//			  "performanceTradeoffs": {
	//				"type": "array",
	//				"title": "Performance Tradeoffs",
	//				"description": "What are the known tradeoffs in accuracy/performance of the model?",
	//				"items": {
	//				  "type": "string"
	//				}
	//			  },
	//			  "ethicalConsiderations": {
	//				"type": "array",
	//				"title": "Ethical Considerations",
	//				"description": "What are the ethical (or environmental) risks involved in the application of this model?",
	//				"items": { "$ref": "#/definitions/risk" }
	//			  },
	//			  "fairnessAssessments": {
	//				"type": "array",
	//				"title": "Fairness Assessments",
	//				"description": "How does the model affect groups at risk of being systematically disadvantaged? What are the harms and benefits to the various affected groups?",
	//				"items": {
	//				  "$ref": "#/definitions/fairnessAssessment"
	//				}
	//			  }
	//			}
	//		  },
	//		  "properties": {
	//			"type": "array",
	//			"title": "Properties",
	//			"description": "Provides the ability to document properties in a name-value store. This provides flexibility to include data not officially supported in the standard without having to use additional namespaces or create extensions. Unlike key-value stores, properties support duplicate names, each potentially having different values. Property names of interest to the general public are encouraged to be registered in the [CycloneDX Property Taxonomy](https://github.com/CycloneDX/cyclonedx-property-taxonomy). Formal registration is OPTIONAL.",
	//			"items": {"$ref": "#/definitions/property"}
	//		  }
	//		}
	//	  },
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

	//		  "graphics": { "$ref": "#/definitions/graphicsCollection" },
	//		  "description": {
	//			"description": "A description of the dataset. Can describe size of dataset, whether it's used for source code, training, testing, or validation, etc.",
	//			"type": "string"
	//		  },
	//		  "governance": {
	//			"type": "object",
	//			"title": "Data Governance",
	//			"$ref": "#/definitions/dataGovernance"
	//		  }
	//		}
	//	  },
}

// v1.5 added
type CDXDataGovernance struct {
	//	  "dataGovernance": {
	//		"type": "object",
	//		"title": "Data Governance",
	//		"additionalProperties": false,
	//		"properties": {
	//		  "custodians": {
	//			"type": "array",
	//			"title": "Data Custodians",
	//			"description": "Data custodians are responsible for the safe custody, transport, and storage of data.",
	//			"items": { "$ref": "#/definitions/dataGovernanceResponsibleParty" }
	//		  },
	//		  "stewards": {
	//			"type": "array",
	//			"title": "Data Stewards",
	//			"description": "Data stewards are responsible for data content, context, and associated business rules.",
	//			"items": { "$ref": "#/definitions/dataGovernanceResponsibleParty" }
	//		  },
	//		  "owners": {
	//			"type": "array",
	//			"title": "Data Owners",
	//			"description": "Data owners are concerned with risk and appropriate access to data.",
	//			"items": { "$ref": "#/definitions/dataGovernanceResponsibleParty" }
	//		  }
	//		}
	//	  },
}

// v1.5 added
type CDXDataGovernanceResponsibleParty struct {

	//	  "dataGovernanceResponsibleParty": {
	//		"type": "object",
	//		"additionalProperties": false,
	//		"properties": {
	//		  "organization": {
	//			"title": "Organization",
	//			"$ref": "#/definitions/organizationalEntity"
	//		  },
	//		  "contact": {
	//			"title": "Individual",
	//			"$ref": "#/definitions/organizationalContact"
	//		  }
	//		},
	//		"oneOf":[
	//		  {
	//			"required": ["organization"]
	//		  },
	//		  {
	//			"required": ["contact"]
	//		  }
	//		]
	//	  },

}

// v1.5 added
type CDXGraphicsCollection struct {

	//	  "graphicsCollection": {
	//		"type": "object",
	//		"title": "Graphics Collection",
	//		"description": "A collection of graphics that represent various measurements.",
	//		"additionalProperties": false,
	//		"properties": {
	//		  "description": {
	//			"description": "A description of this collection of graphics.",
	//			"type": "string"
	//		  },
	//		  "collection": {
	//			"description": "A collection of graphics.",
	//			"type": "array",
	//			"items": { "$ref": "#/definitions/graphic" }
	//		  }
	//		}
	//	  },
}

// v1.5 added
type CDXGraphic struct {

	//	  "graphic": {
	//		"type": "object",
	//		"additionalProperties": false,
	//		"properties": {
	//		  "name": {
	//			"description": "The name of the graphic.",
	//			"type": "string"
	//		  },
	//		  "image": {
	//			"title": "Graphic Image",
	//			"description": "The graphic (vector or raster). Base64 encoding MUST be specified for binary images.",
	//			"$ref": "#/definitions/attachment"
	//		  }
	//		}
	//	  },
}

// v1.5 added
type CDXPerformanceMetric struct {
	//	  "performanceMetric": {
	//		"type": "object",
	//		"additionalProperties": false,
	//		"properties": {
	//		  "type": {
	//			"description": "The type of performance metric.",
	//			"type": "string"
	//		  },
	//		  "value": {
	//			"description": "The value of the performance metric.",
	//			"type": "string"
	//		  },
	//		  "slice": {
	//			"description": "The name of the slice this metric was computed on. By default, assume this metric is not sliced.",
	//			"type": "string"
	//		  },
	//		  "confidenceInterval": {
	//			"description": "The confidence interval of the metric.",
	//			"type": "object",
	//			"additionalProperties": false,
	//			"properties": {
	//			  "lowerBound": {
	//				"description": "The lower bound of the confidence interval.",
	//				"type": "string"
	//			  },
	//			  "upperBound": {
	//				"description": "The upper bound of the confidence interval.",
	//				"type": "string"
	//			  }
	//			}
	//		  }
	//		}
	//	  },
}

// v1.5 added
type CDXRisk struct {
	//	  "risk": {
	//		"type": "object",
	//		"additionalProperties": false,
	//		"properties": {
	//		  "name": {
	//			"description": "The name of the risk.",
	//			"type": "string"
	//		  },
	//		  "mitigationStrategy": {
	//			"description": "Strategy used to address this risk.",
	//			"type": "string"
	//		  }
	//		}
	//	  },
}

// v1.5 added
type CDXFairnessAssessment struct {
	//	  "fairnessAssessment": {
	//		"type": "object",
	//		"title": "Fairness Assessment",
	//		"description": "Information about the benefits and harms of the model to an identified at risk group.",
	//		"additionalProperties": false,
	//		"properties": {
	//		  "groupAtRisk": {
	//			"type": "string",
	//			"description": "The groups or individuals at risk of being systematically disadvantaged by the model."
	//		  },
	//		  "benefits": {
	//			"type": "string",
	//			"description": "Expected benefits to the identified groups."
	//		  },
	//		  "harms": {
	//			"type": "string",
	//			"description": "Expected harms to the identified groups."
	//		  },
	//		  "mitigationStrategy": {
	//			"type": "string",
	//			"description": "With respect to the benefits and harms outlined, please describe any mitigation strategy implemented."
	//		  }
	//		}
	//	  },
}
