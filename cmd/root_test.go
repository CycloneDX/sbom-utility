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

package cmd

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/CycloneDX/sbom-utility/common"
	"github.com/CycloneDX/sbom-utility/utils"
)

// Test files that span commands
const (
	TEST_INPUT_FILE_NON_EXISTENT = "non-existent-sbom.json"
)

// Assure test infrastructure (shared resources) are only initialized once
// This would help if tests are eventually run in parallel
var initTestInfra sync.Once

// !!! SECRET SAUCE !!!
// The "go test" framework uses the "flags" package where all flags
// MUST be declared (as a global) otherwise `go test` will error out when passed
// NOTE: The following flags flags serve this purpose, but they are only
// filled in after "flag.parse()" is called which MUST be done post any init() processing.
// In order to get --trace or --debug output during init() processing, we rely upon
// directly parsing "os.Args[1:] in the `log` package
// USAGE: to set on command line and have it parsed, simply append
// it as follows: '--args --trace'
var TestLogLevelDebug = flag.Bool(FLAG_DEBUG, false, "")
var TestLogLevelTrace = flag.Bool(FLAG_TRACE, false, "")
var TestLogQuiet = flag.Bool(FLAG_QUIET_MODE, false, "")

type CommonTestInfo struct {
	InputFile                         string
	OutputFormat                      string
	ListSummary                       bool
	WhereClause                       string
	ResultExpectedError               error
	ResultExpectedLineCount           int
	ResultLineContainsValuesAtLineNum int
	ResultLineContainsValues          []string
	MockStdin                         bool
}

func NewCommonTestInfo() *CommonTestInfo {
	var ti = new(CommonTestInfo)
	return ti
}

func NewCommonTestInfoBasic(inputFile string, whereClause string, listFormat string, listSummary bool) *CommonTestInfo {
	var ti = NewCommonTestInfo()
	ti.InputFile = inputFile
	ti.WhereClause = whereClause
	ti.OutputFormat = listFormat
	ti.ListSummary = listSummary
	return ti
}

// default (empty) TestInfo struct values
const (
	TI_LIST_SUMMARY_FALSE   = false
	TI_LIST_LINE_WRAP       = false
	TI_DEFAULT_WHERE_CLAUSE = ""
	TI_DEFAULT_LINE_COUNT   = -1
	TI_DEFAULT_POLICY_FILE  = ""
)

// Stringer interface for ResourceTestInfo (just display subset of key values)
func (ti *CommonTestInfo) String() string {
	return fmt.Sprintf("InputFile: `%s`, Format: `%s`, WhereClause: `%s`, ListSummary: `%v`",
		ti.InputFile, ti.OutputFormat, ti.WhereClause, ti.ListSummary)
}

func (ti *CommonTestInfo) Init(inputFile string, listFormat string, listSummary bool, whereClause string,
	resultContainsValues []string, resultExpectedLineCount int, resultExpectedError error) *CommonTestInfo {
	ti.InputFile = inputFile
	ti.OutputFormat = listFormat
	ti.ListSummary = listSummary
	ti.WhereClause = whereClause
	ti.ResultExpectedLineCount = resultExpectedLineCount
	ti.ResultExpectedError = resultExpectedError
	return ti
}

func (ti *CommonTestInfo) InitBasic(inputFile string, format string, expectedError error) *CommonTestInfo {
	ti.Init(inputFile, format, TI_LIST_SUMMARY_FALSE, TI_DEFAULT_WHERE_CLAUSE,
		nil, TI_DEFAULT_LINE_COUNT, expectedError)
	return ti
}

func TestMain(m *testing.M) {
	// Note: getLogger(): if it is creating the logger, will also
	// initialize the log "level" and set "quiet" mode from command line args.
	getLogger().Enter()
	defer getLogger().Exit()

	// Set log/trace/debug settings as if the were set by command line flags
	if !flag.Parsed() {
		getLogger().Tracef("calling `flag.Parse()`...")
		flag.Parse()
	}
	getLogger().Tracef("Setting Debug=`%t`, Trace=`%t`, Quiet=`%t`,", *TestLogLevelDebug, *TestLogLevelTrace, *TestLogQuiet)
	utils.GlobalFlags.PersistentFlags.Trace = *TestLogLevelTrace
	utils.GlobalFlags.PersistentFlags.Debug = *TestLogLevelDebug
	utils.GlobalFlags.PersistentFlags.Quiet = *TestLogQuiet

	// Load configs, create logger, etc.
	// NOTE: Be sure ALL "go test" flags are parsed/processed BEFORE initializing
	initTestInfrastructure()

	// Run test
	exitCode := m.Run()
	getLogger().Tracef("exit code: `%v`", exitCode)

	// Exit with exit value from tests
	os.Exit(exitCode)
}

// NOTE: if we need to override test setup in our own "main" routine, you can create
// a function named "TestMain" (and you will need to manage Init() and other setup)
// See: https://pkg.go.dev/testing
func initTestInfrastructure() {
	getLogger().Enter()
	defer getLogger().Exit()

	initTestInfra.Do(func() {
		getLogger().Tracef("initTestInfra.Do(): Initializing shared resources...")

		// Assures we are loading relative to the application's executable directory
		// which may vary if using IDEs or "go test"
		initTestApplicationDirectories()

		// Leverage the root command's init function to populate schemas, policies, etc.
		initConfigurations()

		// initConfig() loads the policies from file; hash policies for tests
		// Note: we hash policies (once) for all tests
		getLogger().Debugf("Hashing license policies...")
		errHash := licensePolicyConfig.HashLicensePolicies()
		if errHash != nil {
			getLogger().Error(errHash.Error())
			os.Exit(ERROR_APPLICATION)
		}
	})
}

// Set the working directory to match where the executable is being called from
func initTestApplicationDirectories() (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Only set the working directory path once
	if utils.GlobalFlags.WorkingDir == "" {
		// Need to change the working directory to the application root instead of
		// the "cmd" directory where this "_test" file runs so that all test files
		// as well as "config.json" and its referenced JSON schema files load properly.
		err = os.Chdir("..")

		if err != nil {
			// unable to change working directory; test data will not be found
			return
		}

		// Need 'workingDir' to prepend to relative test files
		utils.GlobalFlags.WorkingDir, _ = os.Getwd()
		getLogger().Infof("Set `utils.GlobalFlags.WorkingDir`: `%s`", utils.GlobalFlags.WorkingDir)
	}

	return
}

// Helper functions
// TODO seek to use same function for evaluating error and messages as we do for other commands
func EvaluateErrorAndKeyPhrases(t *testing.T, err error, messages []string) (matched bool) {
	matched = true
	if err == nil {
		t.Errorf("error expected: %s", messages)
	} else {
		getLogger().Tracef("Testing error message for the following substrings:\n%v", messages)
		errorMessage := err.Error()
		for _, substring := range messages {
			if !strings.Contains(errorMessage, substring) {
				matched = false
				t.Errorf("expected string: `%s` not found in error message: `%s`", substring, err.Error())
			}
		}
	}
	return
}

func prepareWhereFilters(t *testing.T, testInfo *CommonTestInfo) (whereFilters []common.WhereFilter, err error) {

	if testInfo.WhereClause != "" {
		whereFilters, err = retrieveWhereFilters(testInfo.WhereClause)
		if err != nil {
			t.Errorf("test failed: %s: detail: %s ", testInfo.String(), err.Error())
			return
		}
	}
	return
}
