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

import "sort"

// named BOM slice types
type CDXFormulaSlice []CDXFormula
type CDXTaskSlice []CDXTask
type CDXTaskTypeSlice []CDXTaskType
type CDXWorkflowSlice []CDXWorkflow

// ====================================================================
// Struct Normalizers
// ====================================================================

func (formula *CDXFormula) Normalize() {
	// Sort: Components
	// Note: The following method is recursive
	if formula.Components != nil {
		CDXComponentSlice(*formula.Components).Normalize()
	}
	// Sort: Services
	// Note: The following method is recursive
	if formula.Services != nil {
		CDXServiceSlice(*formula.Services).Normalize()
	}
	// Sort: Workflows
	if formula.Workflows != nil {
		CDXWorkflowSlice(*formula.Workflows).Normalize()
	}
	// Sort: Properties
	if formula.Properties != nil {
		CDXPropertySlice(*formula.Properties).Normalize()
	}
}

func (workflow *CDXWorkflow) Normalize() {
	// Sort: TaskTypes
	if workflow.TaskTypes != nil {
		CDXTaskTypeSlice(*workflow.TaskTypes).Normalize()
	}
	// Sort: Tasks
	if workflow.Tasks != nil {
		CDXTaskSlice(*workflow.Tasks).Normalize()
	}
	// TODO: Sort: ResourceReferences
	// TODO: Sort: Tasks
	// TODO: Sort: TaskDependencies
	// TODO: Sort: Trigger
	// TODO: Sort: Steps
	// TODO: Sort: Inputs
	// TODO: Sort: Outputs
	// TODO: Sort: Workspaces
	// TODO: Sort: RuntimeTopology
	// Sort: Properties
	if workflow.Properties != nil {
		CDXPropertySlice(*workflow.Properties).Normalize()
	}
}

func (task *CDXTask) Normalize() {
	// Sort: TaskTypes
	if task.TaskTypes != nil {
		CDXTaskTypeSlice(*task.TaskTypes).Normalize()
	}
	// TODO: Sort: ResourceReferences
	// TODO: Sort: Tasks
	// TODO: Sort: TaskDependencies
	// TODO: Sort: Trigger
	// TODO: Sort: Steps
	// TODO: Sort: Inputs
	// TODO: Sort: Outputs
	// TODO: Sort: Workspaces
	// TODO: Sort: RuntimeTopology
	// Sort: Properties
	if task.Properties != nil {
		CDXPropertySlice(*task.Properties).Normalize()
	}
}

// ====================================================================
// Slice Normalizers
// ====================================================================

func (slice CDXFormulaSlice) Normalize() {
	sort.Slice(slice, func(i, j int) bool {
		element1 := slice[i]
		element2 := slice[j]
		return comparatorFormula(element1, element2)
	})

	// TODO: Sort: workflows (tasks), components, services, properties, etc.
	// Normalize() each entry in the Dependency slice
	for _, formula := range slice {
		formula.Normalize()
	}
}

func (slice CDXTaskSlice) Normalize() {
	sort.Slice(slice, func(i, j int) bool {
		element1 := slice[i]
		element2 := slice[j]
		return comparatorTask(element1, element2)
	})

	for _, task := range slice {
		task.Normalize()
	}
}

func (slice CDXTaskTypeSlice) Normalize() {
	sort.Slice(slice, func(i, j int) bool {
		// Note: CDXTaskType is a named type for "string"
		return slice[i] < slice[j]
	})
}

func (slice CDXWorkflowSlice) Normalize() {
	sort.Slice(slice, func(i, j int) bool {
		element1 := slice[i]
		element2 := slice[j]
		return comparatorWorkflow(element1, element2)
	})

	for _, workflow := range slice {
		workflow.Normalize()
	}
}

// ====================================================================
// Struct comparators
// ====================================================================

// NOTE: sorting structs like this are challenge since there are no required fields
// within the top-level data schema; yet, there are LOTS of slices to sort within.
// TODO: make the "bom-ref" field "required" in v2.0
func comparatorFormula(element1 CDXFormula, element2 CDXFormula) bool {
	// sort by pseudo-required field "bom-ref"
	if element1.BOMRef != nil && element2.BOMRef != nil {
		return comparatorRefType(*element1.BOMRef, *element2.BOMRef)
	}
	// default: preserve existing order
	return true
}

func comparatorWorkflow(element1 CDXWorkflow, element2 CDXWorkflow) bool {
	// sort by required field "bom-ref"
	if element1.BOMRef != nil && element2.BOMRef != nil {
		return comparatorRefType(*element1.BOMRef, *element2.BOMRef)
	}
	if element1.Uid != element2.Uid {
		return element1.Uid < element2.Uid
	}
	// default: preserve existing order
	return true
}

func comparatorTask(element1 CDXTask, element2 CDXTask) bool {
	// sort by required field "bom-ref"
	if element1.BOMRef != nil && element2.BOMRef != nil {
		return comparatorRefType(*element1.BOMRef, *element2.BOMRef)
	}
	if element1.Uid != element2.Uid {
		return element1.Uid < element2.Uid
	}
	// default: preserve existing order
	return true
}
