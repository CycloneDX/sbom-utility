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
	BomRef     CDXRefType     `json:"bom-ref,omitempty"`
	Components []CDXComponent `json:"components,omitempty"`
	Services   []CDXService   `json:"services,omitempty"`
	Workflows  []CDXWorkflow  `json:"workflows,omitempty"`
	Properties []CDXProperty  `json:"properties,omitempty"`
}

// v1.5: added
type CDXWorkflow struct {
	BomRef             CDXRefType                   `json:"bom-ref,omitempty"`
	Uid                string                       `json:"uid,omitempty"`
	Name               string                       `json:"name,omitempty"`
	Description        string                       `json:"description,omitempty"`
	ResourceReferences []CDXResourceReferenceChoice `json:"resourceReferences,omitempty"`
	Tasks              []CDXTask                    `json:"tasks,omitempty"`
	TaskDependencies   []CDXDependency              `json:"taskDependencies,omitempty"`
	TaskTypes          []CDXTaskType                `json:"taskTypes,omitempty"`
	Trigger            CDXTrigger                   `json:"trigger,omitempty"`
	Steps              []CDXStep                    `json:"steps,omitempty"`
	Inputs             []CDXInputType               `json:"inputs,omitempty"`
	Outputs            []CDXOutputType              `json:"outputs,omitempty"`
	TimeStart          string                       `json:"timeStart,omitempty"`
	TimeEnd            string                       `json:"timeEnd,omitempty"`
	Workspaces         []CDXWorkspace               `json:"workspaces,omitempty"`
	RuntimeTopology    []CDXDependency              `json:"runtimeTopology,omitempty"`
	Properties         []CDXProperty                `json:"properties,omitempty"`
}

// v1.5: added
type CDXTask struct {
	BomRef             CDXRefType                   `json:"bom-ref,omitempty"`
	Uid                string                       `json:"uid,omitempty"`
	Name               string                       `json:"name,omitempty"`
	Description        string                       `json:"description,omitempty"`
	ResourceReferences []CDXResourceReferenceChoice `json:"resourceReferences,omitempty"`
	TaskTypes          []CDXTaskType                `json:"taskTypes,omitempty"`
	Trigger            CDXTrigger                   `json:"trigger,omitempty"`
	Steps              []CDXStep                    `json:"steps,omitempty"`
	Inputs             []CDXInputType               `json:"inputs,omitempty"`
	Outputs            []CDXOutputType              `json:"outputs,omitempty"`
	TimeStart          string                       `json:"timeStart,omitempty"`
	TimeEnd            string                       `json:"timeEnd,omitempty"`
	Workspaces         []CDXWorkspace               `json:"workspaces,omitempty"`
	RuntimeTopology    []CDXDependency              `json:"runtimeTopology,omitempty"`
	Properties         []CDXProperty                `json:"properties,omitempty"`
}

// v1.5: added
// "enum": ["copy","clone","lint","scan","merge","build","test","deliver","deploy","release","clean","other"]
type CDXTaskType string

// v1.5: added
type CDXStep struct {
	Name        string        `json:"name,omitempty"`
	Description string        `json:"description,omitempty"`
	Commands    []CDXCommand  `json:"commands,omitempty"`
	Properties  []CDXProperty `json:"properties,omitempty"`
}

type CDXCommand struct {
	Executed   bool          `json:"executed,omitempty"`
	Properties []CDXProperty `json:"properties,omitempty"`
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
