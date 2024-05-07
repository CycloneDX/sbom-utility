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

import (
	"flag"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/CycloneDX/sbom-utility/utils"
)

const (
	// Hash test BOM files
	TEST_HASH_CDX_1_5_METADATA_COMPONENT_EMPTY     = "test/hash/hash-cdx-1-5-metadata-component-empty.sbom.json"
	TEST_HASH_CDX_1_5_METADATA_COMPONENT_FULL      = "test/hash/hash-cdx-1-5-metadata-component-full.sbom.json"
	TEST_HASH_CDX_1_5_METADATA_COMPONENT_NAME_ONLY = "test/hash/hash-cdx-1-5-metadata-component-name-only.sbom.json"
	TEST_HASH_CDX_1_5_COMPONENTS                   = "test/hash/hash-cdx-1-5-components.sbom.json"
	TEST_HASH_CDX_1_5_SERVICES                     = "test/hash/hash-cdx-1-5-services.sbom.json"
	TEST_HASH_CDX_1_5_VULNERABILITIES              = "test/hash/hash-cdx-1-5-vulnerabilities.sbom.json"
)

type HashTestInfo struct {
	InputFile           string
	OutputFile          string
	OutputFormat        string
	WhereClause         string
	ResultExpectedError error
}

func NewHashTestInfo(inputFilename string) *HashTestInfo {
	var ti = new(HashTestInfo)
	ti.InputFile = inputFilename
	return ti
}

var TestFormatConfig BOMFormatAndSchemaConfig

const (
	DEFAULT_TEST_SCHEMA_CONFIG = "config.json"
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
const (
	FLAG_DEBUG      = "debug"
	FLAG_TRACE      = "trace"
	FLAG_QUIET_MODE = "quiet"
)

var SchemaTestLogLevelDebug = flag.Bool(FLAG_DEBUG, false, "")
var SchemaTestLogLevelTrace = flag.Bool(FLAG_TRACE, false, "")
var SchemaTestLogQuiet = flag.Bool(FLAG_QUIET_MODE, false, "")

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
	getLogger().Tracef("Setting Debug=`%t`, Trace=`%t`, Quiet=`%t`,", *SchemaTestLogLevelDebug, *SchemaTestLogLevelTrace, *SchemaTestLogQuiet)
	utils.GlobalFlags.PersistentFlags.Trace = *SchemaTestLogLevelTrace
	utils.GlobalFlags.PersistentFlags.Debug = *SchemaTestLogLevelDebug
	utils.GlobalFlags.PersistentFlags.Quiet = *SchemaTestLogQuiet

	// Load configs, create logger, etc.
	// NOTE: Be sure ALL "go test" flags are parsed/processed BEFORE initializing
	err := initTestInfrastructure()
	if err != nil {
		os.Exit(1) // TODO: use common/shared constant cmd.ERROR_APPLICATION = 1
	}

	// Run test
	exitCode := m.Run()
	getLogger().Tracef("exit code: `%v`", exitCode)

	// Exit with exit value from tests
	os.Exit(exitCode)
}

// NOTE: if we need to override test setup in our own "main" routine, you can create
// a function named "TestMain" (and you will need to manage Init() and other setup)
// See: https://pkg.go.dev/testing
func initTestInfrastructure() (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	initTestInfra.Do(func() {
		getLogger().Tracef("initTestInfra.Do(): Initializing shared resources...")

		// Assures we are loading relative to the application's executable directory
		// which may vary if using IDEs or "go test"
		err = initTestApplicationDirectories()
		if err != nil {
			return
		}

		// Leverage the root command's init function to populate schemas, policies, etc.
		// TODO: call initConfigurations() as defined in "cmd" package (as a common/shared pkg.)
		err = TestFormatConfig.LoadSchemaConfigFile("", DEFAULT_TEST_SCHEMA_CONFIG)
		if err != nil {
			return
		}
	})
	return
}

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

func loadBOMFile(inputFile string) (document *BOM, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// check for required fields on command
	if inputFile == "" {
		return nil, fmt.Errorf("invalid input file: `%s` ", inputFile)
	}

	// Construct a BOM document object around the input file
	document = NewBOM(inputFile)
	document.filename = inputFile

	// Load the raw, candidate BOM (file) as JSON data
	getLogger().Infof("Attempting to load and unmarshal data from: `%s`...", document.GetFilenameInterpolated())
	err = document.UnmarshalBOMAsJSONMap() // i.e., utils.Flags.InputFile
	if err != nil {
		return
	}
	getLogger().Infof("Successfully unmarshalled data from: `%s`", document.GetFilenameInterpolated())

	// Search the document keys/values for known BOM formats and schema in the config. file
	getLogger().Infof("Determining file's BOM format and version...")
	err = TestFormatConfig.FindFormatAndSchema(document)
	if err != nil {
		return
	}

	// Display detected format, version with (optional) schema variant (i.e., if requested on command line)
	getLogger().Infof("Determined BOM format, version (variant): `%s`, `%s` %s",
		document.FormatInfo.CanonicalName,
		document.SchemaInfo.Version,
		FormatSchemaVariant(document.SchemaInfo.Variant))
	getLogger().Infof("Matching BOM schema (for validation): %s", document.SchemaInfo.File)
	return
}

// ---------------------------
// Hash tests
// ---------------------------

// -------------------
// Component Hashing
// -------------------
func TestHashCDXComponentEmpty(t *testing.T) {
	document, err := loadBOMFile(TEST_HASH_CDX_1_5_METADATA_COMPONENT_EMPTY)
	if err != nil {
		t.Error(err)
		return
	}

	// need to unmarshal into CDX structures.
	if err = document.UnmarshalCycloneDXBOM(); err != nil {
		t.Error(err)
		return
	}

	component := document.GetCdxMetadataComponent()
	if component == nil {
		err = getLogger().Errorf("invalid test case. No component declared in BOM metadata.")
		t.Error(err)
		return
	}

	_, err = document.HashmapComponent(*component, nil, false)
	if err != nil {
		t.Error(err)
		return
	}
}

func TestHashCDXComponentNameOnly(t *testing.T) {
	document, err := loadBOMFile(TEST_HASH_CDX_1_5_METADATA_COMPONENT_NAME_ONLY)
	if err != nil {
		t.Error(err)
		return
	}

	// need to unmarshal into CDX structures.
	if err = document.UnmarshalCycloneDXBOM(); err != nil {
		t.Error(err)
		return
	}

	component := document.GetCdxMetadataComponent()
	if component == nil {
		err = getLogger().Errorf("invalid test case. No component declared in BOM metadata.")
		t.Error(err)
		return
	}

	_, err = document.HashmapComponent(*component, nil, false)
	if err != nil {
		t.Error(err)
		return
	}
}

func TestHashCDXComponentFull(t *testing.T) {
	document, err := loadBOMFile(TEST_HASH_CDX_1_5_METADATA_COMPONENT_FULL)
	if err != nil {
		t.Error(err)
		return
	}

	// need to unmarshal into CDX structures.
	if err = document.UnmarshalCycloneDXBOM(); err != nil {
		t.Error(err)
		return
	}

	component := document.GetCdxMetadataComponent()
	if component == nil {
		err = getLogger().Errorf("invalid test case. No component declared in BOM metadata.")
		t.Error(err)
		return
	}

	_, err = document.HashmapComponent(*component, nil, false)
	if err != nil {
		t.Error(err)
		return
	}
}

func TestHashCDXComponentsSlice(t *testing.T) {
	document, err := loadBOMFile(TEST_HASH_CDX_1_5_COMPONENTS)
	if err != nil {
		t.Error(err)
		return
	}

	// need to unmarshal into CDX structures.
	if err = document.UnmarshalCycloneDXBOM(); err != nil {
		t.Error(err)
		return
	}

	components := document.GetCdxComponents()
	if components == nil || len(*components) == 0 {
		err = getLogger().Errorf("invalid test case. No components declared in BOM.")
		t.Error(err)
		return
	}

	// Now that we believe we have actual components, hash them
	err = document.HashmapComponents(*components, nil, false)
	if err != nil {
		t.Error(err)
		return
	}
}

func TestHashZeroCDXComponentStruct(t *testing.T) {
	cdxComponent := new(CDXComponent)
	document := NewBOM("")
	hashed, err := document.HashmapComponent(*cdxComponent, nil, false)
	if err != nil {
		t.Error(err)
		return
	}

	// NOTE: we do not want to hash empty (zero) structures
	if hashed {
		t.Error(getLogger().Errorf("hashed an empty (zero) structure."))
	}
}

// -------------------
// Service Hashing
// -------------------
func TestHashCDXServicesSlice(t *testing.T) {
	document, err := loadBOMFile(TEST_HASH_CDX_1_5_SERVICES)
	if err != nil {
		t.Error(err)
		return
	}

	// need to unmarshal into CDX structures.
	if err = document.UnmarshalCycloneDXBOM(); err != nil {
		t.Error(err)
		return
	}

	services := document.GetCdxServices()
	if services == nil || len(*services) == 0 {
		err = getLogger().Errorf("invalid test case. No services declared in BOM.")
		t.Error(err)
		return
	}

	err = document.HashmapServices(*services, nil)
	if err != nil {
		t.Error(err)
		return
	}
}

func TestHashZeroCDXServiceStruct(t *testing.T) {
	cdxService := new(CDXService)
	document := NewBOM("")
	hashed, err := document.HashmapService(*cdxService, nil)
	if err != nil {
		t.Error(err)
		return
	}

	// NOTE: we do not want to hash empty (zero) structures
	if hashed {
		t.Error(getLogger().Errorf("hashed an empty (zero) structure."))
	}
}

func TestHashCDXVulnerabilitiesSlice(t *testing.T) {
	document, err := loadBOMFile(TEST_HASH_CDX_1_5_VULNERABILITIES)
	if err != nil {
		t.Error(err)
		return
	}

	// need to unmarshal into CDX structures.
	if err = document.UnmarshalCycloneDXBOM(); err != nil {
		t.Error(err)
		return
	}

	vulnerabilities := document.GetCdxVulnerabilities()
	if vulnerabilities == nil || len(*vulnerabilities) == 0 {
		err = getLogger().Errorf("invalid test case. No vulnerabilities declared in BOM.")
		t.Error(err)
		return
	}

	err = document.HashmapVulnerabilities(*vulnerabilities, nil)
	if err != nil {
		t.Error(err)
		return
	}
}

// ----------------------
// Vulnerability Hashing
// ----------------------

// Note: unused function
func TestHashZeroCDXVulnerabilityStruct(t *testing.T) {
	cdxVulnerability := new(CDXVulnerability)
	document := NewBOM("")
	hashed, err := document.HashmapVulnerability(*cdxVulnerability, nil)
	if err != nil {
		t.Error(err)
		return
	}

	// NOTE: we do not want to hash empty (zero) structures
	if hashed {
		t.Error(getLogger().Errorf("hashed an empty (zero) structure."))
	}
}

// ----------------------
// License Hashing
// ----------------------
// Note: unused function
func TestHashZeroCDXLicenseInfoStruct(t *testing.T) {
	cdxLicenseInfo := new(LicenseInfo)
	document := NewBOM("")
	flags := new(utils.LicenseCommandFlags)
	hashed, err := document.HashmapLicenseInfo(nil, "foo", *cdxLicenseInfo, nil, *flags)
	if err != nil {
		t.Error(err)
		return
	}

	// NOTE: we do not want to hash empty (zero) structures
	if hashed {
		t.Error(getLogger().Errorf("hashed an empty (zero) structure."))
	}
}
