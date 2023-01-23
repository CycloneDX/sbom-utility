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

import (
	"fmt"

	"github.com/ibm/sbom-utility/log"
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
	Quiet            bool // suppresses all non-essential (informational) output from a command. Overrides any other log-level commands.
	Trace            bool // trace logging
	Debug            bool // debug logging
	InputFile        string
	OutputFile       string
	OutputSbomFormat string

	// License flags
	//LicensePolicyConfigFile string

	// Validate (local) flags
	ForcedJsonSchemaFile    string
	Variant                 string
	ValidateProperties      bool
	CustomValidation        bool
	CustomValidationOptions CustomValidationFlags

	// Summary formats (i.e., only valid for summary)
	// NOTE: "query" and "list" (raw) commands always returns JSON by default
	OutputFormat string // e.g., TXT (default), CSV, markdown (normalized to lowercase)

	// Log indent
	LogOutputIndentCallstack bool
}

type CustomValidationFlags struct {
	Composition bool
	License     bool
	Properties  bool
}

// format and output the MyFlags struct as a string using Go's Stringer interface
func (flags *CommandFlags) String() string {
	value, err := log.FormatStruct(flags)

	if err != nil {
		return fmt.Sprintf("%s\n", err.Error())
	}
	return value
}
