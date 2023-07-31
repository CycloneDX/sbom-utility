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
	BomRef     CDXRefType     `json:"bom-ref,omitempty"`    // v1.5
	Components []CDXComponent `json:"components,omitempty"` // v1.5
	Services   []CDXService   `json:"services,omitempty"`   // v1.5
	Workflows  []CDXWorkflow  `json:"workflows,omitempty"`  // v1.5
	Properties []CDXProperty  `json:"properties,omitempty"` // v1.5
}

// v1.5: added
type CDXWorkflow struct {
	BomRef             CDXRefType                   `json:"bom-ref,omitempty"`            // v1.5
	Uid                string                       `json:"uid,omitempty"`                // v1.5
	Name               string                       `json:"name,omitempty"`               // v1.5
	Description        string                       `json:"description,omitempty"`        // v1.5
	ResourceReferences []CDXResourceReferenceChoice `json:"resourceReferences,omitempty"` // v1.5
	Tasks              []CDXTask                    `json:"tasks,omitempty"`              // v1.5
	TaskDependencies   []CDXDependency              `json:"taskDependencies,omitempty"`   // v1.5
	TaskTypes          []CDXTaskType                `json:"taskTypes,omitempty"`          // v1.5
	Trigger            CDXTrigger                   `json:"trigger,omitempty"`            // v1.5
	Steps              []CDXStep                    `json:"steps,omitempty"`              // v1.5
	Inputs             []CDXInputType               `json:"inputs,omitempty"`             // v1.5
	Outputs            []CDXOutputType              `json:"outputs,omitempty"`            // v1.5
	TimeStart          string                       `json:"timeStart,omitempty"`          // v1.5
	TimeEnd            string                       `json:"timeEnd,omitempty"`            // v1.5
	Workspaces         []CDXWorkspace               `json:"workspaces,omitempty"`         // v1.5
	RuntimeTopology    []CDXDependency              `json:"runtimeTopology,omitempty"`    // v1.5
	Properties         []CDXProperty                `json:"properties,omitempty"`         // v1.5
}

// v1.5: added
type CDXTask struct {
	BomRef             CDXRefType                   `json:"bom-ref,omitempty"`            // v1.5
	Uid                string                       `json:"uid,omitempty"`                // v1.5
	Name               string                       `json:"name,omitempty"`               // v1.5
	Description        string                       `json:"description,omitempty"`        // v1.5
	ResourceReferences []CDXResourceReferenceChoice `json:"resourceReferences,omitempty"` // v1.5
	TaskTypes          []CDXTaskType                `json:"taskTypes,omitempty"`          // v1.5
	Trigger            CDXTrigger                   `json:"trigger,omitempty"`            // v1.5
	Steps              []CDXStep                    `json:"steps,omitempty"`              // v1.5
	Inputs             []CDXInputType               `json:"inputs,omitempty"`             // v1.5
	Outputs            []CDXOutputType              `json:"outputs,omitempty"`            // v1.5
	TimeStart          string                       `json:"timeStart,omitempty"`          // v1.5
	TimeEnd            string                       `json:"timeEnd,omitempty"`            // v1.5
	Workspaces         []CDXWorkspace               `json:"workspaces,omitempty"`         // v1.5
	RuntimeTopology    []CDXDependency              `json:"runtimeTopology,omitempty"`    // v1.5
	Properties         []CDXProperty                `json:"properties,omitempty"`         // v1.5
}

// v1.5: added
// "enum": ["copy","clone","lint","scan","merge","build","test","deliver","deploy","release","clean","other"]
type CDXTaskType string // v1.5

// v1.5: added
type CDXStep struct {
	Name        string        `json:"name,omitempty"`        // v1.5
	Description string        `json:"description,omitempty"` // v1.5
	Commands    []CDXCommand  `json:"commands,omitempty"`    // v1.5
	Properties  []CDXProperty `json:"properties,omitempty"`  // v1.5
}

// v1.5: added
type CDXCommand struct {
	Executed   bool          `json:"executed,omitempty"`   // v1.5
	Properties []CDXProperty `json:"properties,omitempty"` // v1.5
}

// v1.5: added
type CDXWorkspace struct {
	BomRef             CDXRefType                   `json:"bom-ref,omitempty"`            // v1.5
	Uid                string                       `json:"uid,omitempty"`                // v1.5
	Name               string                       `json:"name,omitempty"`               // v1.5
	Aliases            []string                     `json:"aliases,omitempty"`            // v1.5
	Description        string                       `json:"description,omitempty"`        // v1.5
	ResourceReferences []CDXResourceReferenceChoice `json:"resourceReferences,omitempty"` // v1.5
	AccessMode         string                       `json:"accessMode,omitempty"`         // v1.5
	MountPath          string                       `json:"mountPath,omitempty"`          // v1.5
	ManagedDataType    string                       `json:"managedDataType,omitempty"`    // v1.5
	VolumeRequest      string                       `json:"volumeRequest,omitempty"`      // v1.5
	Volume             CDXVolume                    `json:"volume,omitempty"`             // v1.5
	Properties         []CDXProperty                `json:"properties,omitempty"`         // v1.5
}

// v1.5: added
type CDXVolume struct {
	Uid           string        `json:"uid,omitempty"`           // v1.5
	Name          string        `json:"name,omitempty"`          // v1.5
	Mode          string        `json:"mode,omitempty"`          // v1.5
	Path          string        `json:"path,omitempty"`          // v1.5
	SizeAllocated string        `json:"sizeAllocated,omitempty"` // v1.5
	Persistent    bool          `json:"persistent,omitempty"`    // v1.5
	Remote        bool          `json:"remote,omitempty"`        // v1.5
	Properties    []CDXProperty `json:"properties,omitempty"`    // v1.5
}

type CDXTrigger struct {
	BomRef             CDXRefType                   `json:"bom-ref,omitempty"`            // v1.5
	Uid                string                       `json:"uid,omitempty"`                // v1.5
	Name               string                       `json:"name,omitempty"`               // v1.5
	Description        string                       `json:"description,omitempty"`        // v1.5
	ResourceReferences []CDXResourceReferenceChoice `json:"resourceReferences,omitempty"` // v1.5
	Type               string                       `json:"type,omitempty"`               // v1.5 // "enum": ["manual", "api", "webhook","scheduled"]
	Event              CDXEvent                     `json:"event,omitempty"`              // v1.5
	Condition          CDXCondition                 `json:"condition,omitempty"`          // v1.5
	TimeActivated      string                       `json:"timeActivated,omitempty"`      // v1.5
	Inputs             []CDXInputType               `json:"inputs,omitempty"`             // v1.5
	Outputs            []CDXOutputType              `json:"outputs,omitempty"`            // v1.5
	Properties         []CDXProperty                `json:"properties,omitempty"`         // v1.5
}

type CDXEvent struct {
	Uid          string                     `json:"uid,omitempty"`          // v1.5
	Description  string                     `json:"description,omitempty"`  // v1.5
	TimeReceived string                     `json:"timeReceived,omitempty"` // v1.5
	Data         CDXAttachment              `json:"data,omitempty"`         // v1.5
	Source       CDXResourceReferenceChoice `json:"source,omitempty"`       // v1.5
	Target       CDXResourceReferenceChoice `json:"target,omitempty"`       // v1.5
	Properties   []CDXProperty              `json:"properties,omitempty"`   // v1.5
}

// v1.5: added
// TODO: see if we can improve "environmentVars" types which is "oneOf": ["#/definitions/property", "string"]
type CDXInputType struct {
	Source          CDXResourceReferenceChoice `json:"source,omitempty"`          // v1.5
	Target          CDXResourceReferenceChoice `json:"target,omitempty"`          // v1.5
	Resource        CDXResourceReferenceChoice `json:"resource,omitempty"`        // v1.5
	Data            CDXAttachment              `json:"data,omitempty"`            // v1.5
	Parameters      []CDXParameter             `json:"parameters,omitempty"`      // v1.5
	EnvironmentVars []interface{}              `json:"environmentVars,omitempty"` // v1.5
	Properties      []CDXProperty              `json:"properties,omitempty"`      // v1.5
}

// v1.5: added
// TODO: likely nothing better we can do for "environmentVars" which is type "oneOf": ["#/definitions/property", "string"]
type CDXOutputType struct {
	Type            string                     `json:"type,omitempty"`            // "enum": ["artifact", "attestation", "log", "evidence", "metrics", "other"]
	Source          CDXResourceReferenceChoice `json:"source,omitempty"`          // v1.5
	Target          CDXResourceReferenceChoice `json:"target,omitempty"`          // v1.5
	Resource        CDXResourceReferenceChoice `json:"resource,omitempty"`        // v1.5
	Data            CDXAttachment              `json:"data,omitempty"`            // v1.5
	EnvironmentVars []interface{}              `json:"environmentVars,omitempty"` // v1.5
	Properties      []CDXProperty              `json:"properties,omitempty"`      // v1.5
}

// v1.5: added
// v1.5: Note: "ref" is a constrained "string" which can be "anyOf": ["#/definitions/refLinkType", "#/definitions/bomLinkElementType"]
// TODO: actually, "Ref" should be its own anonymous type with "anyOf": ["#/definitions/refLinkType", "#/definitions/bomLinkElementType"]
type CDXResourceReferenceChoice struct {
	Ref               CDXRefLinkType       `json:"description,omitempty"`       // v1.5
	ExternalReference CDXExternalReference `json:"externalReference,omitempty"` // v1.5
}

// v1.5: added
type CDXCondition struct {
	Description string        `json:"description,omitempty"` // v1.5
	Expression  string        `json:"expression,omitempty"`  // v1.5
	Properties  []CDXProperty `json:"properties,omitempty"`  // v1.5
}

// v1.5: added
type CDXParameter struct {
	Name     string `json:"name,omitempty"`     // v1.5
	Value    string `json:"value,omitempty"`    // v1.5
	DataType string `json:"dataType,omitempty"` // v1.5
}
