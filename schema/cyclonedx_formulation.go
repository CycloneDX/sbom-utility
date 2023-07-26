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

// v1.5: added
type CDXFormula struct {

	//	  "formula": {
	//		"title": "Formula",
	//		"description": "Describes workflows and resources that captures rules and other aspects of how the associated BOM component or service was formed.",
	//		"type": "object",
	//		"additionalProperties": false,
	//		"properties": {
	//		  "bom-ref": {
	//			"title": "BOM Reference",
	//			"description": "An optional identifier which can be used to reference the formula elsewhere in the BOM. Every bom-ref MUST be unique within the BOM.",
	//			"$ref": "#/definitions/refType"
	//		  },
	//		  "components": {
	//			"title": "Components",
	//			"description": "Transient components that are used in tasks that constitute one or more of this formula's workflows",
	//			"type": "array",
	//			"items": {
	//			  "$ref": "#/definitions/component"
	//			},
	//			"uniqueItems": true
	//		  },
	//		  "services": {
	//			"title": "Services",
	//			"description": "Transient services that are used in tasks that constitute one or more of this formula's workflows",
	//			"type": "array",
	//			"items": {
	//			  "$ref": "#/definitions/service"
	//			},
	//			"uniqueItems": true
	//		  },
	//		  "workflows": {
	//			"title": "Workflows",
	//			"description": "List of workflows that can be declared to accomplish specific orchestrated goals and independently triggered.",
	//			"$comment": "Different workflows can be designed to work together to perform end-to-end CI/CD builds and deployments.",
	//			"type": "array",
	//			"items": {
	//			  "$ref": "#/definitions/workflow"
	//			},
	//			"uniqueItems": true
	//		  },
	//		  "properties": {
	//			"type": "array",
	//			"title": "Properties",
	//			"items": {
	//			  "$ref": "#/definitions/property"
	//			}
	//		  }
	//		}
	//	  },
}

// v1.5: added
type CDXWorkflow struct {

	//	  "workflow": {
	//		"title": "Workflow",
	//		"description": "A specialized orchestration task.",
	//		"$comment": "Workflow are as task themselves and can trigger other workflow tasks.  These relationships can be modeled in the taskDependencies graph.",
	//		"type": "object",
	//		"required": [
	//		  "bom-ref",
	//		  "uid",
	//		  "taskTypes"
	//		],
	//		"additionalProperties": false,
	//		"properties": {
	//		  "bom-ref": {
	//			"title": "BOM Reference",
	//			"description": "An optional identifier which can be used to reference the workflow elsewhere in the BOM. Every bom-ref MUST be unique within the BOM.",
	//			"$ref": "#/definitions/refType"
	//		  },
	//		  "uid": {
	//			"title": "Unique Identifier (UID)",
	//			"description": "The unique identifier for the resource instance within its deployment context.",
	//			"type": "string"
	//		  },
	//		  "name": {
	//			"title": "Name",
	//			"description": "The name of the resource instance.",
	//			"type": "string"
	//		  },
	//		  "description": {
	//			"title": "Description",
	//			"description": "A description of the resource instance.",
	//			"type": "string"
	//		  },
	//		  "resourceReferences": {
	//			"title": "Resource references",
	//			"description": "References to component or service resources that are used to realize the resource instance.",
	//			"type": "array",
	//			"uniqueItems": true,
	//			"items": {
	//			  "$ref": "#/definitions/resourceReferenceChoice"
	//			}
	//		  },
	//		  "tasks": {
	//			"title": "Tasks",
	//			"description": "The tasks that comprise the workflow.",
	//			"$comment": "Note that tasks can appear more than once as different instances (by name or UID).",
	//			"type": "array",
	//			"uniqueItems": true,
	//			"items": {
	//			  "$ref": "#/definitions/task"
	//			}
	//		  },
	//		  "taskDependencies": {
	//			"title": "Task dependency graph",
	//			"description": "The graph of dependencies between tasks within the workflow.",
	//			"type": "array",
	//			"uniqueItems": true,
	//			"items": {
	//			  "$ref": "#/definitions/dependency"
	//			}
	//		  },
	//		  "taskTypes": {
	//			"title": "Task types",
	//			"description": "Indicates the types of activities performed by the set of workflow tasks.",
	//			"$comment": "Currently, these types reflect common CI/CD actions.",
	//			"type": "array",
	//			"items": {
	//			  "$ref": "#/definitions/taskType"
	//			}
	//		  },
	//		  "trigger": {
	//			"title": "Trigger",
	//			"description": "The trigger that initiated the task.",
	//			"$ref": "#/definitions/trigger"
	//		  },
	//		  "steps": {
	//			"title": "Steps",
	//			"description": "The sequence of steps for the task.",
	//			"type": "array",
	//			"items": {
	//			  "$ref": "#/definitions/step"
	//			},
	//			"uniqueItems": true
	//		  },
	//		  "inputs": {
	//			"title": "Inputs",
	//			"description": "Represents resources and data brought into a task at runtime by executor or task commands",
	//			"examples": ["a `configuration` file which was declared as a local `component` or `externalReference`"],
	//			"type": "array",
	//			"items": {
	//			  "$ref": "#/definitions/inputType"
	//			},
	//			"uniqueItems": true
	//		  },
	//		  "outputs": {
	//			"title": "Outputs",
	//			"description": "Represents resources and data output from a task at runtime by executor or task commands",
	//			"examples": ["a log file or metrics data produced by the task"],
	//			"type": "array",
	//			"items": {
	//			  "$ref": "#/definitions/outputType"
	//			},
	//			"uniqueItems": true
	//		  },
	//		  "timeStart": {
	//			"title": "Time start",
	//			"description": "The date and time (timestamp) when the task started.",
	//			"type": "string",
	//			"format": "date-time"
	//		  },
	//		  "timeEnd": {
	//			"title": "Time end",
	//			"description": "The date and time (timestamp) when the task ended.",
	//			"type": "string",
	//			"format": "date-time"
	//		  },
	//		  "workspaces": {
	//			"title": "Workspaces",
	//			"description": "A set of named filesystem or data resource shareable by workflow tasks.",
	//			"type": "array",
	//			"uniqueItems": true,
	//			"items": {
	//			  "$ref": "#/definitions/workspace"
	//			}
	//		  },
	//		  "runtimeTopology": {
	//			"title": "Runtime topology",
	//			"description": "A graph of the component runtime topology for workflow's instance.",
	//			"$comment": "A description of the runtime component and service topology.  This can describe a partial or complete topology used to host and execute the task (e.g., hardware, operating systems, configurations, etc.),",
	//			"type": "array",
	//			"uniqueItems": true,
	//			"items": {
	//			  "$ref": "#/definitions/dependency"
	//			}
	//		  },
	//		  "properties": {
	//			"type": "array",
	//			"title": "Properties",
	//			"items": {
	//			  "$ref": "#/definitions/property"
	//			}
	//		  }
	//		}
	//	  },
}

// v1.5: added
type CDXTask struct {

	//	  "task": {
	//		"title": "Task",
	//		"description": "Describes the inputs, sequence of steps and resources used to accomplish a task and its output.",
	//		"$comment": "Tasks are building blocks for constructing assemble CI/CD workflows or pipelines.",
	//		"type": "object",
	//		"required": [
	//		  "bom-ref",
	//		  "uid",
	//		  "taskTypes"
	//		],
	//		"additionalProperties": false,
	//		"properties": {
	//		  "bom-ref": {
	//			"title": "BOM Reference",
	//			"description": "An optional identifier which can be used to reference the task elsewhere in the BOM. Every bom-ref MUST be unique within the BOM.",
	//			"$ref": "#/definitions/refType"
	//		  },
	//		  "uid": {
	//			"title": "Unique Identifier (UID)",
	//			"description": "The unique identifier for the resource instance within its deployment context.",
	//			"type": "string"
	//		  },
	//		  "name": {
	//			"title": "Name",
	//			"description": "The name of the resource instance.",
	//			"type": "string"
	//		  },
	//		  "description": {
	//			"title": "Description",
	//			"description": "A description of the resource instance.",
	//			"type": "string"
	//		  },
	//		  "resourceReferences": {
	//			"title": "Resource references",
	//			"description": "References to component or service resources that are used to realize the resource instance.",
	//			"type": "array",
	//			"uniqueItems": true,
	//			"items": {
	//			  "$ref": "#/definitions/resourceReferenceChoice"
	//			}
	//		  },
	//		  "taskTypes": {
	//			"title": "Task types",
	//			"description": "Indicates the types of activities performed by the set of workflow tasks.",
	//			"$comment": "Currently, these types reflect common CI/CD actions.",
	//			"type": "array",
	//			"items": {
	//			  "$ref": "#/definitions/taskType"
	//			}
	//		  },
	//		  "trigger": {
	//			"title": "Trigger",
	//			"description": "The trigger that initiated the task.",
	//			"$ref": "#/definitions/trigger"
	//		  },
	//		  "steps": {
	//			"title": "Steps",
	//			"description": "The sequence of steps for the task.",
	//			"type": "array",
	//			"items": {
	//			  "$ref": "#/definitions/step"
	//			},
	//			"uniqueItems": true
	//		  },
	//		  "inputs": {
	//			"title": "Inputs",
	//			"description": "Represents resources and data brought into a task at runtime by executor or task commands",
	//			"examples": ["a `configuration` file which was declared as a local `component` or `externalReference`"],
	//			"type": "array",
	//			"items": {
	//			  "$ref": "#/definitions/inputType"
	//			},
	//			"uniqueItems": true
	//		  },
	//		  "outputs": {
	//			"title": "Outputs",
	//			"description": "Represents resources and data output from a task at runtime by executor or task commands",
	//			"examples": ["a log file or metrics data produced by the task"],
	//			"type": "array",
	//			"items": {
	//			  "$ref": "#/definitions/outputType"
	//			},
	//			"uniqueItems": true
	//		  },
	//		  "timeStart": {
	//			"title": "Time start",
	//			"description": "The date and time (timestamp) when the task started.",
	//			"type": "string",
	//			"format": "date-time"
	//		  },
	//		  "timeEnd": {
	//			"title": "Time end",
	//			"description": "The date and time (timestamp) when the task ended.",
	//			"type": "string",
	//			"format": "date-time"
	//		  },
	//		  "workspaces": {
	//			"title": "Workspaces",
	//			"description": "A set of named filesystem or data resource shareable by workflow tasks.",
	//			"type": "array",
	//			"items": {
	//			  "$ref": "#/definitions/workspace"
	//			},
	//			"uniqueItems": true
	//		  },
	//		  "runtimeTopology": {
	//			"title": "Runtime topology",
	//			"description": "A graph of the component runtime topology for task's instance.",
	//			"$comment": "A description of the runtime component and service topology.  This can describe a partial or complete topology used to host and execute the task (e.g., hardware, operating systems, configurations, etc.),",
	//			"type": "array",
	//			"items": {
	//			  "$ref": "#/definitions/dependency"
	//			},
	//			"uniqueItems": true
	//		  },
	//		  "properties": {
	//			"type": "array",
	//			"title": "Properties",
	//			"items": {
	//			  "$ref": "#/definitions/property"
	//			}
	//		  }
	//		}
	//	  },
}

// v1.5: added
// "enum": ["copy","clone","lint","scan","merge","build","test","deliver","deploy","release","clean","other"]
type CDXTaskType string

// v1.5: added
type CDXStep struct {

	//	  "step": {
	//		"type": "object",
	//		"description": "Executes specific commands or tools in order to accomplish its owning task as part of a sequence.",
	//		"additionalProperties": false,
	//		"properties": {
	//		  "name": {
	//			"title": "Name",
	//			"description": "A name for the step.",
	//			"type": "string"
	//		  },
	//		  "description": {
	//			"title": "Description",
	//			"description": "A description of the step.",
	//			"type": "string"
	//		  },
	//		  "commands": {
	//			"title": "Commands",
	//			"description": "Ordered list of commands or directives for the step",
	//			"type": "array",
	//			"items": {
	//			  "$ref": "#/definitions/command"
	//			}
	//		  },
	//		  "properties": {
	//			"type": "array",
	//			"title": "Properties",
	//			"items": {
	//			  "$ref": "#/definitions/property"
	//			}
	//		  }
	//		}
	//	  },
}

type CDXCommand struct {

	//	  "command": {
	//		"type": "object",
	//		"additionalProperties": false,
	//		"properties": {
	//		  "executed": {
	//			"title": "Executed",
	//			"description": "A text representation of the executed command.",
	//			"type": "string"
	//		  },
	//		  "properties": {
	//			"type": "array",
	//			"title": "Properties",
	//			"items": {
	//			  "$ref": "#/definitions/property"
	//			}
	//		  }
	//		}
	//	  },
}

// v1.5: added
type CDXWorkspace struct {
	BomRef             CDXRefType                   `json:"bom-ref,omitempty"`
	Uid                string                       `json:"uid,omitempty"`
	Name               string                       `json:"name,omitempty"`
	Aliases            []string                     `json:"aliases,omitempty"`
	Description        string                       `json:"description,omitempty"`
	ResourceReferences []CDXResourceReferenceChoice `json:"resourceReferences,omitempty"`
	AccessMode         string                       `json:"accessMode,omitempty"`
	MountPath          string                       `json:"mountPath,omitempty"`
	ManagedDataType    string                       `json:"managedDataType,omitempty"`
	VolumeRequest      string                       `json:"volumeRequest,omitempty"`
	Volume             CDXVolume                    `json:"volume,omitempty"`
	Properties         []CDXProperty                `json:"properties,omitempty"`
}

type CDXVolume struct {
	Uid           string        `json:"uid,omitempty"`
	Name          string        `json:"name,omitempty"`
	Mode          string        `json:"mode,omitempty"`
	Path          string        `json:"path,omitempty"`
	SizeAllocated string        `json:"sizeAllocated,omitempty"`
	Persistent    bool          `json:"persistent,omitempty"`
	Remote        bool          `json:"remote,omitempty"`
	Properties    []CDXProperty `json:"properties,omitempty"`
}

type CDXTrigger struct {
	BomRef             CDXRefType                   `json:"bom-ref,omitempty"`
	Uid                string                       `json:"uid,omitempty"`
	Name               string                       `json:"name,omitempty"`
	Description        string                       `json:"description,omitempty"`
	ResourceReferences []CDXResourceReferenceChoice `json:"resourceReferences,omitempty"`
	Type               string                       `json:"type,omitempty"` // "enum": ["manual", "api", "webhook","scheduled"]
	Event              CDXEvent                     `json:"event,omitempty"`
	Condition          CDXCondition                 `json:"condition,omitempty"`
	TimeActivated      string                       `json:"timeActivated,omitempty"`
	Inputs             []CDXInputType               `json:"inputs,omitempty"`
	Outputs            []CDXOutputType              `json:"outputs,omitempty"`
	Properties         []CDXProperty                `json:"properties,omitempty"`
}

type CDXEvent struct {
	Uid          string                     `json:"uid,omitempty"`
	Description  string                     `json:"description,omitempty"`
	TimeReceived string                     `json:"timeReceived,omitempty"`
	Data         CDXAttachment              `json:"data,omitempty"`
	Source       CDXResourceReferenceChoice `json:"source,omitempty"`
	Target       CDXResourceReferenceChoice `json:"target,omitempty"`
	Properties   []CDXProperty              `json:"properties,omitempty"`
}

// v1.5: added
// TODO: likely nothing better we can do for "environmentVars" which is type "oneOf": ["#/definitions/property", "string"]
type CDXInputType struct {
	Source          CDXResourceReferenceChoice `json:"source,omitempty"`
	Target          CDXResourceReferenceChoice `json:"target,omitempty"`
	Resource        CDXResourceReferenceChoice `json:"resource,omitempty"`
	Data            CDXAttachment              `json:"data,omitempty"`
	Parameters      []CDXParameter             `json:"parameters,omitempty"`
	EnvironmentVars []interface{}              `json:"environmentVars,omitempty"` // TODO: "oneOf": ["#/definitions/property", "string"]
	Properties      []CDXProperty              `json:"properties,omitempty"`
}

// v1.5: added
// TODO: likely nothing better we can do for "environmentVars" which is type "oneOf": ["#/definitions/property", "string"]
type CDXOutputType struct {
	Type            string                     `json:"type,omitempty"` // "enum": ["artifact", "attestation", "log", "evidence", "metrics", "other"]
	Source          CDXResourceReferenceChoice `json:"source,omitempty"`
	Target          CDXResourceReferenceChoice `json:"target,omitempty"`
	Resource        CDXResourceReferenceChoice `json:"resource,omitempty"`
	Data            CDXAttachment              `json:"data,omitempty"`
	EnvironmentVars []interface{}              `json:"environmentVars,omitempty"`
	Properties      []CDXProperty              `json:"properties,omitempty"`
}

// v1.5: added
// TODO: actually, "Ref" should be its own anonymous type with "anyOf": ["#/definitions/refLinkType", "#/definitions/bomLinkElementType"]
type CDXResourceReferenceChoice struct {
	Ref               CDXRefLinkType       `json:"description,omitempty"`
	ExternalReference CDXExternalReference `json:"externalReference,omitempty"`
}

// v1.5: added
type CDXCondition struct {
	Description string        `json:"description,omitempty"`
	Expression  string        `json:"expression,omitempty"`
	Properties  []CDXProperty `json:"properties,omitempty"`
}

type CDXParameter struct {
	Name     string `json:"name,omitempty"`
	Value    string `json:"value,omitempty"`
	DataType string `json:"dataType,omitempty"`
}
