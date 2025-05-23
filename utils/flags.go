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

package utils

const (
	PROJECT_NAME = "sbom-utility"
)

// Globals
var GlobalFlags CommandFlags

type CommandFlags struct {
	// Not flags, but "main" package var copies
	Project    string
	Binary     string
	Version    string
	WorkingDir string
	ExecDir    string

	// Configurations
	ConfigSchemaFile           string
	ConfigCustomValidationFile string
	ConfigLicensePolicyFile    string

	// persistent flags (common to all commands)
	PersistentFlags PersistentCommandFlags

	// Command-specific flags
	ComponentFlags          ComponentCommandFlags
	CustomValidationOptions CustomValidationFlags
	DiffFlags               DiffCommandFlags
	LicenseFlags            LicenseCommandFlags
	PatchFlags              PatchCommandFlags
	ResourceFlags           ResourceCommandFlags
	SchemaFlags             SchemaCommandFlags
	StatsFlags              StatsCommandFlags
	TrimFlags               TrimCommandFlags
	ValidateFlags           ValidateCommandFlags
	VulnerabilityFlags      VulnerabilityCommandFlags

	// Misc flags
	LogOutputIndentCallstack bool // Log indent
}

// NOTE: These flags are shared by both the list and policy subcommands
type PersistentCommandFlags struct {
	Quiet           bool // suppresses all non-essential (informational) output from a command. Overrides any other log-level commands.
	Trace           bool // trace logging
	Debug           bool // debug logging
	InputFile       string
	OutputFile      string // TODO: TODO: Note: not used by `validate` command, which emits a warning if supplied
	OutputFormat    string // e.g., "txt", "csv"", "md" (markdown) (normalized to lowercase)
	OutputIndent    uint8
	OutputNormalize bool
}

func (persistentFlags PersistentCommandFlags) GetOutputIndentInt() int {
	return int(persistentFlags.OutputIndent)
}

// Common flags for all "list" (report) commands (e.g., license list, vulnerability list, etc.)
type ReportCommandFlags struct {
	Summary      bool
	ListLineWrap bool // NOTE: SHOULD ONLY be used for "text" output; currently only used by "license policy" command.
}

type LicenseCommandFlags struct {
	ReportCommandFlags
}

type ValidateCommandFlags struct {
	SchemaVariant        string
	ForcedJsonSchemaFile string
	CustomValidation     bool // Uses custom validation flags if "true"; defaults to config. "custom.json"
	// validation error result (output) processing
	MaxNumErrors              int
	MaxErrorDescriptionLength int
	ColorizeErrorOutput       bool
	ShowErrorValue            bool
}

type VulnerabilityCommandFlags struct {
	ReportCommandFlags
}

type DiffCommandFlags struct {
	Colorize    bool
	RevisedFile string
}

type ResourceCommandFlags struct {
	ReportCommandFlags // NOTE: currently unused; as # columns grows, please implement
	ResourceType       string
}

type ComponentCommandFlags struct {
	ReportCommandFlags
	Types []string
}

func NewResourceCommandFlags(resourceType string) ResourceCommandFlags {
	return ResourceCommandFlags{
		ResourceType: resourceType,
	}
}

type SchemaCommandFlags struct {
	ReportCommandFlags // NOTE: currently unused; as # columns grows, please implement
}

// TODO: unused/unimplemented
type StatsCommandFlags struct {
}

// TODO: write a "parse" method for the struct (i.e., from "raw" to slice)
type TrimCommandFlags struct {
	RawKeys   string
	RawPaths  string
	Keys      []string
	FromPaths []string
}

type PatchCommandFlags struct {
	PatchFile    string
	OutputFormat string // NOTE: needed to overcome Cobra limitation when diff. commands have diff. default values
}

type CustomValidationFlags struct {
	Composition bool
	License     bool
	Properties  bool
}

// format and output the MyFlags struct as a string using Go's Stringer interface
func (flags *CommandFlags) String() string {
	buffer, _ := EncodeAnyToDefaultIndentedJSONStr(flags)
	return buffer.String()
}
