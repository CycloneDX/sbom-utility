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

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/CycloneDX/sbom-utility/cmd"
	"github.com/CycloneDX/sbom-utility/log"
	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/CycloneDX/sbom-utility/utils"
)

// Struct used to hold tagged (release) build information
// Which is displayed by the `version` command.
// These values can be overwritten by `go build ${LDFLAGS}`
// for example, LDFLAGS=-ldflags "-X main.Version=${VERSION}
var (
	// public
	Project = "sbom-utility"
	Binary  = "unset"
	Version = "x.y.z"
	Logger  *log.MiniLogger

	// Default configurations
	DefaultLogLevel = log.INFO
)

func init() {
	// Create logger at the earliest
	// NOTE: This logger will not apply to `go test` as package "main" will not be loaded
	Logger = log.NewLogger(DefaultLogLevel)

	// Check for log-related flags (anywhere) and apply to logger
	// as early as possible (before customary Cobra flag formalization)
	// NOTE: the last log-level flag found, in order of appearance "wins"
	// Set default log level and turn "quiet mode" off
	Logger.InitLogLevelAndModeFromFlags()

	// Emit log level used from this point forward
	Logger.Tracef("Logger (%T) created: with Level=`%v`", Logger, Logger.GetLevelName())

	// Provide access to project logger to other modules
	cmd.ProjectLogger = Logger
	schema.ProjectLogger = Logger

	// Copy program package vars into command flags
	utils.GlobalFlags.Project = Project
	utils.GlobalFlags.Binary = Binary
	utils.GlobalFlags.Version = Version

	// Capture working directory
	utils.GlobalFlags.WorkingDir, _ = os.Getwd()

	// Set the executable directory path
	execNameWithPath, err := os.Executable()
	if err == nil {
		utils.GlobalFlags.ExecDir = filepath.Dir(execNameWithPath)
	}
}

func printWelcome() {
	if !Logger.QuietModeOn() {
		goos := fmt.Sprintf("(%s/%s)", runtime.GOOS, runtime.GOARCH)
		echo := fmt.Sprintf("Welcome to the %s! Version `%s` (%s) %s\n", Project, Version, Binary, goos)
		// Logger will only print the welcome if log level requested indicates INFO level (or higher)
		Logger.DumpString(echo)
		// Show intent to not check for error returns as there is no recovery
		_, _ = Logger.DumpSeparator('=', len(echo)-1)
	}
}

func main() {
	Logger.Enter()
	defer Logger.Exit()
	printWelcome()
	// Use Cobra convention and execute top-level command
	cmd.Execute()
}
