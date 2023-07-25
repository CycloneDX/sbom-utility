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

type CDXWorkspace struct {
	//	  "workspace": {
	//		"title": "Workspace",
	//		"description": "A named filesystem or data resource shareable by workflow tasks.",
	//		"type": "object",
	//		"required": [
	//		  "bom-ref",
	//		  "uid"
	//		],
	//		"additionalProperties": false,
	//		"properties": {
	//		  "bom-ref": {
	//			"title": "BOM Reference",
	//			"description": "An optional identifier which can be used to reference the workspace elsewhere in the BOM. Every bom-ref MUST be unique within the BOM.",
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
	//		  "aliases": {
	//			"title": "Aliases",
	//			"description": "The names for the workspace as referenced by other workflow tasks. Effectively, a name mapping so other tasks can use their own local name in their steps.",
	//			"type": "array",
	//			"items": {"type": "string"}
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
	//		  "accessMode": {
	//			"title": "Access mode",
	//			"description": "Describes the read-write access control for the workspace relative to the owning resource instance.",
	//			"type": "string",
	//			"enum": [
	//			  "read-only",
	//			  "read-write",
	//			  "read-write-once",
	//			  "write-once",
	//			  "write-only"
	//			]
	//		  },
	//		  "mountPath": {
	//			"title": "Mount path",
	//			"description": "A path to a location on disk where the workspace will be available to the associated task's steps.",
	//			"type": "string"
	//		  },
	//		  "managedDataType": {
	//			"title": "Managed data type",
	//			"description": "The name of a domain-specific data type the workspace represents.",
	//			"$comment": "This property is for CI/CD frameworks that are able to provide access to structured, managed data at a more granular level than a filesystem.",
	//			"examples": ["ConfigMap","Secret"],
	//			"type": "string"
	//		  },
	//		  "volumeRequest": {
	//			"title": "Volume request",
	//			"description": "Identifies the reference to the request for a specific volume type and parameters.",
	//			"examples": ["a kubernetes Persistent Volume Claim (PVC) name"],
	//			"type": "string"
	//		  },
	//		  "volume": {
	//			"title": "Volume",
	//			"description": "Information about the actual volume instance allocated to the workspace.",
	//			"$comment": "The actual volume allocated may be different than the request.",
	//			"examples": ["see https://kubernetes.io/docs/concepts/storage/persistent-volumes/"],
	//			"$ref": "#/definitions/volume"
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

type CDXVolume struct {
	//	  "volume": {
	//		"title": "Volume",
	//		"description": "An identifiable, logical unit of data storage tied to a physical device.",
	//		"type": "object",
	//		"additionalProperties": false,
	//		"properties": {
	//		  "uid": {
	//			"title": "Unique Identifier (UID)",
	//			"description": "The unique identifier for the volume instance within its deployment context.",
	//			"type": "string"
	//		  },
	//		  "name": {
	//			"title": "Name",
	//			"description": "The name of the volume instance",
	//			"type": "string"
	//		  },
	//		  "mode": {
	//			"title": "Mode",
	//			"description": "The mode for the volume instance.",
	//			"type": "string",
	//			"enum": [
	//			  "filesystem", "block"
	//			],
	//			"default": "filesystem"
	//		  },
	//		  "path": {
	//			"title": "Path",
	//			"description": "The underlying path created from the actual volume.",
	//			"type": "string"
	//		  },
	//		  "sizeAllocated": {
	//			"title": "Size allocated",
	//			"description": "The allocated size of the volume accessible to the associated workspace. This should include the scalar size as well as IEC standard unit in either decimal or binary form.",
	//			"examples": ["10GB", "2Ti", "1Pi"],
	//			"type": "string"
	//		  },
	//		  "persistent": {
	//			"title": "Persistent",
	//			"description": "Indicates if the volume persists beyond the life of the resource it is associated with.",
	//			"type": "boolean"
	//		  },
	//		  "remote": {
	//			"title": "Remote",
	//			"description": "Indicates if the volume is remotely (i.e., network) attached.",
	//			"type": "boolean"
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

type CDXTrigger struct {
	//	  "trigger": {
	//		"title": "Trigger",
	//		"description": "Represents a resource that can conditionally activate (or fire) tasks based upon associated events and their data.",
	//		"type": "object",
	//		"additionalProperties": false,
	//		"required": [
	//		  "type",
	//		  "bom-ref",
	//		  "uid"
	//		],
	//		"properties": {
	//		  "bom-ref": {
	//			"title": "BOM Reference",
	//			"description": "An optional identifier which can be used to reference the trigger elsewhere in the BOM. Every bom-ref MUST be unique within the BOM.",
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
	//		  "type": {
	//			"title": "Type",
	//			"description": "The source type of event which caused the trigger to fire.",
	//			"type": "string",
	//			"enum": [
	//			  "manual",
	//			  "api",
	//			  "webhook",
	//			  "scheduled"
	//			]
	//		  },
	//		  "event": {
	//			"title": "Event",
	//			"description": "The event data that caused the associated trigger to activate.",
	//			"$ref": "#/definitions/event"
	//		  },
	//		  "conditions": {
	//			"type": "array",
	//			"uniqueItems": true,
	//			"items": {
	//			  "$ref": "#/definitions/condition"
	//			}
	//		  },
	//		  "timeActivated": {
	//			"title": "Time activated",
	//			"description": "The date and time (timestamp) when the trigger was activated.",
	//			"type": "string",
	//			"format": "date-time"
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
	//		  "properties": {
	//			"type": "array",
	//			"title": "Properties",
	//			"items": {
	//			  "$ref": "#/definitions/property"
	//			}
	//		  }
	//		}
	//	  },
	//	  "event": {
}

type CDXEvent struct {
	//		"title": "Event",
	//		"description": "Represents something that happened that may trigger a response.",
	//		"type": "object",
	//		"additionalProperties": false,
	//		"properties": {
	//		  "uid": {
	//			"title": "Unique Identifier (UID)",
	//			"description": "The unique identifier of the event.",
	//			"type": "string"
	//		  },
	//		  "description": {
	//			"title": "Description",
	//			"description": "A description of the event.",
	//			"type": "string"
	//		  },
	//		  "timeReceived": {
	//			"title": "Time Received",
	//			"description": "The date and time (timestamp) when the event was received.",
	//			"type": "string",
	//			"format": "date-time"
	//		  },
	//		  "data": {
	//			"title": "Data",
	//			"description": "Encoding of the raw event data.",
	//			"$ref": "#/definitions/attachment"
	//		  },
	//		  "source": {
	//			"title": "Source",
	//			"description": "References the component or service that was the source of the event",
	//			"$ref": "#/definitions/resourceReferenceChoice"
	//		  },
	//		  "target": {
	//			"title": "Target",
	//			"description": "References the component or service that was the target of the event",
	//			"$ref": "#/definitions/resourceReferenceChoice"
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

type CDXInputType struct {
	//	  "inputType": {
	//		"title": "Input type",
	//		"description": "Type that represents various input data types and formats.",
	//		"type": "object",
	//		"oneOf": [
	//		  {
	//			"required": [
	//			  "resource"
	//			]
	//		  },
	//		  {
	//			"required": [
	//			  "parameters"
	//			]
	//		  },
	//		  {
	//			"required": [
	//			  "environmentVars"
	//			]
	//		  },
	//		  {
	//			"required": [
	//			  "data"
	//			]
	//		  }
	//		],
	//		"additionalProperties": false,
	//		"properties": {
	//		  "source": {
	//			"title": "Source",
	//			"description": "A references to the component or service that provided the input to the task (e.g., reference to a service with data flow value of `inbound`)",
	//			"examples": [
	//			  "source code repository",
	//			  "database"
	//			],
	//			"$ref": "#/definitions/resourceReferenceChoice"
	//		  },
	//		  "target": {
	//			"title": "Target",
	//			"description": "A reference to the component or service that received or stored the input if not the task itself (e.g., a local, named storage workspace)",
	//			"examples": [
	//			  "workspace",
	//			  "directory"
	//			],
	//			"$ref": "#/definitions/resourceReferenceChoice"
	//		  },
	//		  "resource": {
	//			"title": "Resource",
	//			"description": "A reference to an independent resource provided as an input to a task by the workflow runtime.",
	//			"examples": [
	//			  "reference to a configuration file in a repository (i.e., a bom-ref)",
	//			  "reference to a scanning service used in a task (i.e., a bom-ref)"
	//			],
	//			"$ref": "#/definitions/resourceReferenceChoice"
	//		  },
	//		  "parameters": {
	//			"title": "Parameters",
	//			"description": "Inputs that have the form of parameters with names and values.",
	//			"type": "array",
	//			"uniqueItems": true,
	//			"items": {
	//			  "$ref": "#/definitions/parameter"
	//			}
	//		  },
	//		  "environmentVars": {
	//			"title": "Environment variables",
	//			"description": "Inputs that have the form of parameters with names and values.",
	//			"type": "array",
	//			"uniqueItems": true,
	//			"items": {
	//			  "oneOf": [
	//				{
	//				  "$ref": "#/definitions/property"
	//				},
	//				{
	//				  "type": "string"
	//				}
	//			  ]
	//			}
	//		  },
	//		  "data": {
	//			"title": "Data",
	//			"description": "Inputs that have the form of data.",
	//			"$ref": "#/definitions/attachment"
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

type CDXOutputType struct {
	//	  "outputType": {
	//		"type": "object",
	//		"oneOf": [
	//		  {
	//			"required": [
	//			  "resource"
	//			]
	//		  },
	//		  {
	//			"required": [
	//			  "environmentVars"
	//			]
	//		  },
	//		  {
	//			"required": [
	//			  "data"
	//			]
	//		  }
	//		],
	//		"additionalProperties": false,
	//		"properties": {
	//		  "type": {
	//			"title": "Type",
	//			"description": "Describes the type of data output.",
	//			"type": "string",
	//			"enum": [
	//			  "artifact",
	//			  "attestation",
	//			  "log",
	//			  "evidence",
	//			  "metrics",
	//			  "other"
	//			]
	//		  },
	//		  "source": {
	//			"title": "Source",
	//			"description": "Component or service that generated or provided the output from the task (e.g., a build tool)",
	//			"$ref": "#/definitions/resourceReferenceChoice"
	//		  },
	//		  "target": {
	//			"title": "Target",
	//			"description": "Component or service that received the output from the task (e.g., reference to an artifactory service with data flow value of `outbound`)",
	//			"examples": ["a log file described as an `externalReference` within its target domain."],
	//			"$ref": "#/definitions/resourceReferenceChoice"
	//		  },
	//		  "resource": {
	//			"title": "Resource",
	//			"description": "A reference to an independent resource generated as output by the task.",
	//			"examples": [
	//			  "configuration file",
	//			  "source code",
	//			  "scanning service"
	//			],
	//			"$ref": "#/definitions/resourceReferenceChoice"
	//		  },
	//		  "data": {
	//			"title": "Data",
	//			"description": "Outputs that have the form of data.",
	//			"$ref": "#/definitions/attachment"
	//		  },
	//		  "environmentVars": {
	//			"title": "Environment variables",
	//			"description": "Outputs that have the form of environment variables.",
	//			"type": "array",
	//			"items": {
	//			  "oneOf": [
	//				{
	//				  "$ref": "#/definitions/property"
	//				},
	//				{
	//				  "type": "string"
	//				}
	//			  ]
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

type CDXResourceReferenceChoice struct {

	//	  "resourceReferenceChoice": {
	//		"title": "Resource reference choice",
	//		"description": "A reference to a locally defined resource (e.g., a bom-ref) or an externally accessible resource.",
	//		"$comment": "Enables reference to a resource that participates in a workflow; using either internal (bom-ref) or external (externalReference) types.",
	//		"type": "object",
	//		"additionalProperties": false,
	//		"properties": {
	//		  "ref": {
	//			"title": "BOM Reference",
	//			"description": "References an object by its bom-ref attribute",
	//			"anyOf": [
	//			  {
	//				"title": "Ref",
	//				"$ref": "#/definitions/refLinkType"
	//			  },
	//			  {
	//				"title": "BOM-Link Element",
	//				"$ref": "#/definitions/bomLinkElementType"
	//			  }
	//			]
	//		  },
	//		  "externalReference": {
	//			"title": "External reference",
	//			"description": "Reference to an externally accessible resource.",
	//			"$ref": "#/definitions/externalReference"
	//		  }
	//		},
	//		"oneOf": [
	//		  {
	//			"required": [
	//			  "ref"
	//			]
	//		  },
	//		  {
	//			"required": [
	//			  "externalReference"
	//			]
	//		  }
	//		]
	//	  },
}

type CDXCondition struct {
	//	  "condition": {
	//		"title": "Condition",
	//		"description": "A condition that was used to determine a trigger should be activated.",
	//		"type": "object",
	//		"additionalProperties": false,
	//		"properties": {
	//		  "description": {
	//			"title": "Description",
	//			"description": "Describes the set of conditions which cause the trigger to activate.",
	//			"type": "string"
	//		  },
	//		  "expression": {
	//			"title": "Expression",
	//			"description": "The logical expression that was evaluated that determined the trigger should be fired.",
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

type CDXTaskType struct {

	//	  "taskType": {
	//		"type": "string",
	//		"enum": [
	//		  "copy",
	//		  "clone",
	//		  "lint",
	//		  "scan",
	//		  "merge",
	//		  "build",
	//		  "test",
	//		  "deliver",
	//		  "deploy",
	//		  "release",
	//		  "clean",
	//		  "other"
	//		]
	//	  },
	//	  "parameter": {
	//		"title": "Parameter",
	//		"description": "A representation of a functional parameter.",
	//		"type": "object",
	//		"additionalProperties": false,
	//		"properties": {
	//		  "name": {
	//			"title": "Name",
	//			"description": "The name of the parameter.",
	//			"type": "string"
	//		  },
	//		  "value": {
	//			"title": "Value",
	//			"description": "The value of the parameter.",
	//			"type": "string"
	//		  },
	//		  "dataType": {
	//			"title": "Data type",
	//			"description": "The data type of the parameter.",
	//			"type": "string"
	//		  }
	//		}
	//	  },
}
