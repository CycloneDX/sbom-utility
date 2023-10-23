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
	"fmt"
	"io"
	"os"

	"github.com/CycloneDX/sbom-utility/log"
	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/CycloneDX/sbom-utility/utils"
	"github.com/spf13/cobra"
)

// Globals
var ProjectLogger *log.MiniLogger
var licensePolicyConfig *LicenseComplianceConfig
var SupportedFormatConfig schema.BOMFormatAndSchemaConfig

// top-level commands
const (
	CMD_DIFF          = "diff"
	CMD_LICENSE       = "license"
	CMD_QUERY         = "query"
	CMD_RESOURCE      = "resource"
	CMD_SCHEMA        = "schema"
	CMD_VALIDATE      = "validate"
	CMD_VERSION       = "version"
	CMD_VULNERABILITY = "vulnerability"
	CMD_STATS         = "stats"
	CMD_TRIM          = "trim"
)

// WARNING!!! The ".Use" field of a Cobra command MUST have the first word be the actual command
// otherwise, the command will NOT be found by the Cobra framework. This is poor code assumption is NOT documented.
const (
	CMD_USAGE_DIFF               = CMD_DIFF + " --input-file <base_file> --input-revision <revised_file> [--format json|txt] [--colorize=true|false]"
	CMD_USAGE_LICENSE_LIST       = SUBCOMMAND_LICENSE_LIST + " --input-file <input_file> [--summary] [--where key=regex[,...]] [--format json|txt|csv|md]"
	CMD_USAGE_LICENSE_POLICY     = SUBCOMMAND_LICENSE_POLICY + " [--where key=regex[,...]] [--format txt|csv|md]"
	CMD_USAGE_QUERY              = CMD_QUERY + " --input-file <input_file> [--select * | field1[,fieldN]] [--from [key1[.keyN]] [--where key=regex[,...]]"
	CMD_USAGE_RESOURCE_LIST      = CMD_RESOURCE + " --input-file <input_file> [--type component|service] [--where key=regex[,...]] [--format txt|csv|md]"
	CMD_USAGE_SCHEMA_LIST        = CMD_SCHEMA + " [--where key=regex[,...]] [--format txt|csv|md]"
	CMD_USAGE_VALIDATE           = CMD_VALIDATE + " --input-file <input_file> [--variant <variant_name>] [--format txt|json] [--force schema_file]"
	CMD_USAGE_VULNERABILITY_LIST = CMD_VULNERABILITY + " " + SUBCOMMAND_VULNERABILITY_LIST + " --input-file <input_file> [--summary] [--where key=regex[,...]] [--format json|txt|csv|md]"
	CMD_USAGE_STATS_LIST         = CMD_STATS + " --input-file <input_file> [--type component|service] [--format txt|csv|md]"
	CMD_USAGE_TRIM               = CMD_TRIM + " --input-file <input_file>  --input-file <output_file>"
)

const (
	FLAG_CONFIG_SCHEMA            = "config-schema"
	FLAG_CONFIG_LICENSE_POLICY    = "config-license"
	FLAG_CONFIG_CUSTOM_VALIDATION = "config-validation"
	FLAG_TRACE                    = "trace"
	FLAG_TRACE_SHORT              = "t"
	FLAG_DEBUG                    = "debug"
	FLAG_DEBUG_SHORT              = "d"
	FLAG_FILENAME_INPUT           = "input-file"
	FLAG_FILENAME_INPUT_SHORT     = "i"
	FLAG_FILENAME_OUTPUT          = "output-file"
	FLAG_FILENAME_OUTPUT_SHORT    = "o"
	FLAG_QUIET_MODE               = "quiet"
	FLAG_QUIET_MODE_SHORT         = "q"
	FLAG_LOG_OUTPUT_INDENT        = "indent"
	FLAG_FILE_OUTPUT_FORMAT       = "format"
	FLAG_COLORIZE_OUTPUT          = "colorize"
)

const (
	MSG_APP_NAME            = "Bill-of-Materials (BOM) utility."
	MSG_APP_DESCRIPTION     = "This utility serves as centralized command line interface into various Software Bill-of-Materials (SBOM) helper utilities."
	MSG_FLAG_TRACE          = "enable trace logging"
	MSG_FLAG_DEBUG          = "enable debug logging"
	MSG_FLAG_INPUT          = "input filename (e.g., \"path/sbom.json\")"
	MSG_FLAG_OUTPUT         = "output filename"
	MSG_FLAG_LOG_QUIET      = "enable quiet logging mode (removes all informational messages from console output); overrides other logging commands"
	MSG_FLAG_LOG_INDENT     = "enable log indentation of functional callstack"
	MSG_FLAG_CONFIG_SCHEMA  = "provide custom application schema configuration file (i.e., overrides default `config.json`)"
	MSG_FLAG_CONFIG_LICENSE = "provide custom application license policy configuration file (i.e., overrides default `license.json`)"
)

const (
	MSG_SUPPORTED_OUTPUT_FORMATS_HELP         = "\n- Supported formats: "
	MSG_SUPPORTED_OUTPUT_FORMATS_SUMMARY_HELP = "\n- Supported formats using the --summary flag: "
)

const (
	DEFAULT_SCHEMA_CONFIG            = "config.json"
	DEFAULT_CUSTOM_VALIDATION_CONFIG = "custom.json"
	DEFAULT_LICENSE_POLICY_CONFIG    = "license.json"
)

// Supported output formats
const (
	FORMAT_DEFAULT  = ""
	FORMAT_TEXT     = "txt"
	FORMAT_JSON     = "json"
	FORMAT_CSV      = "csv"
	FORMAT_MARKDOWN = "md"
	FORMAT_ANY      = "<any>" // Used for test errors
)

// Command reserved values
const (
	INPUT_TYPE_STDIN = "-"
)

var rootCmd = &cobra.Command{
	Use:           fmt.Sprintf("%s [command] [flags]", utils.GlobalFlags.Project),
	SilenceErrors: false,
	SilenceUsage:  false,
	Short:         MSG_APP_NAME,
	Long:          MSG_APP_DESCRIPTION,
	RunE:          RootCmdImpl,
}

func getLogger() *log.MiniLogger {
	if ProjectLogger == nil {
		// TODO: use LDFLAGS to turn on "TRACE" (and require creation of a Logger)
		// ONLY if needed to debug init() methods in the "cmd" package
		ProjectLogger = log.NewLogger(log.ERROR)

		// Attempt to read in `--args` values such as `--trace`
		// Note: if they exist, quiet mode will be overridden
		// Default to ERROR level and, turn on "Quiet mode" for tests
		// This simplifies the test output to simply RUN/PASS|FAIL messages.
		ProjectLogger.InitLogLevelAndModeFromFlags()
	}
	return ProjectLogger
}

// initialize the module; primarily, initialize cobra
// NOTE: the "cmd" module is problematic as Cobra recommends using init() to configure flags.
func init() {
	// Note: getLogger(): if it is creating the logger, will also
	// initialize the log "level" and set "quiet" mode from command line args.
	getLogger().Enter()
	defer getLogger().Exit()

	// Tell Cobra what our Cobra "init" call back method is
	cobra.OnInitialize(initConfigurations)

	// Declare top-level, persistent flags used for configuration of utility
	rootCmd.PersistentFlags().StringVarP(&utils.GlobalFlags.ConfigSchemaFile, FLAG_CONFIG_SCHEMA, "", "", MSG_FLAG_CONFIG_SCHEMA)
	rootCmd.PersistentFlags().StringVarP(&utils.GlobalFlags.ConfigLicensePolicyFile, FLAG_CONFIG_LICENSE_POLICY, "", "", MSG_FLAG_CONFIG_LICENSE)
	utils.GlobalFlags.ConfigCustomValidationFile = DEFAULT_CUSTOM_VALIDATION_CONFIG
	// TODO: Make configurable once we have organized the set of custom validation configurations
	//rootCmd.PersistentFlags().StringVarP(&utils.GlobalFlags.ConfigCustomValidationFile, FLAG_CONFIG_CUSTOM_VALIDATION, "", DEFAULT_CUSTOM_VALIDATION_CONFIG, "TODO")

	// Declare top-level, persistent flags and where to place the post-parse values
	rootCmd.PersistentFlags().BoolVarP(&utils.GlobalFlags.PersistentFlags.Trace, FLAG_TRACE, FLAG_TRACE_SHORT, false, MSG_FLAG_TRACE)
	rootCmd.PersistentFlags().BoolVarP(&utils.GlobalFlags.PersistentFlags.Debug, FLAG_DEBUG, FLAG_DEBUG_SHORT, false, MSG_FLAG_DEBUG)
	rootCmd.PersistentFlags().StringVarP(&utils.GlobalFlags.PersistentFlags.InputFile, FLAG_FILENAME_INPUT, FLAG_FILENAME_INPUT_SHORT, "", MSG_FLAG_INPUT)
	rootCmd.PersistentFlags().StringVarP(&utils.GlobalFlags.PersistentFlags.OutputFile, FLAG_FILENAME_OUTPUT, FLAG_FILENAME_OUTPUT_SHORT, "", MSG_FLAG_OUTPUT)

	// NOTE: Although we check for the quiet mode flag in main; we track the flag
	// using Cobra framework in order to enable more comprehensive help
	// and take advantage of other features.
	rootCmd.PersistentFlags().BoolVarP(&utils.GlobalFlags.PersistentFlags.Quiet, FLAG_QUIET_MODE, FLAG_QUIET_MODE_SHORT, false, MSG_FLAG_LOG_QUIET)

	// Optionally, allow log callstack trace to be indented
	rootCmd.PersistentFlags().BoolVarP(&utils.GlobalFlags.LogOutputIndentCallstack, FLAG_LOG_OUTPUT_INDENT, "", false, MSG_FLAG_LOG_INDENT)

	// Add root commands
	rootCmd.AddCommand(NewCommandVersion())
	rootCmd.AddCommand(NewCommandSchema())
	rootCmd.AddCommand(NewCommandValidate())
	rootCmd.AddCommand(NewCommandQuery())
	rootCmd.AddCommand(NewCommandResource())
	rootCmd.AddCommand(NewCommandVulnerability())
	rootCmd.AddCommand(NewCommandDiff())
	rootCmd.AddCommand(NewCommandStats())

	// Add license command its subcommands
	licenseCmd := NewCommandLicense()
	licenseCmd.AddCommand(NewCommandList())
	licenseCmd.AddCommand(NewCommandPolicy())
	rootCmd.AddCommand(licenseCmd)
}

// load and process configuration files.  Processing includes JSON unmarshalling and hashing.
// includes JSON files:
// config.json (SBOM format/schema definitions),
// license.json (license policy definitions),
// custom.json (custom validation settings)
func initConfigurations() {
	getLogger().Enter()
	defer getLogger().Exit()

	getLogger().Tracef("Executable Directory`: `%s`", utils.GlobalFlags.ExecDir)
	getLogger().Tracef("Working Directory`: `%s`", utils.GlobalFlags.WorkingDir)

	// Print global flags in debug mode
	flagInfo, err := getLogger().FormatStructE(utils.GlobalFlags)
	if err != nil {
		getLogger().Error(err.Error())
	} else {
		getLogger().Debugf("%s: \n%s", "utils.Flags", flagInfo)
	}

	// NOTE: some commands operate just on the JSON SBOM (i.e., no validation)
	// we leave the code below "in place" as we may still want to validate any
	// input file as JSON SBOM document that matches a known format/version (TODO in the future)

	// Load application configuration file (i.e., primarily SBOM supported Formats/Schemas)
	var schemaConfigFile = utils.GlobalFlags.ConfigSchemaFile
	errorLoadSchemaConfig := SupportedFormatConfig.LoadSchemaConfigFile(schemaConfigFile, DEFAULT_SCHEMA_CONFIG)
	if errorLoadSchemaConfig != nil {
		getLogger().Error(errorLoadSchemaConfig.Error())
		os.Exit(ERROR_APPLICATION)
	}

	// License information and approval policies (customizable)
	var licensePolicyFile = utils.GlobalFlags.ConfigLicensePolicyFile
	licensePolicyConfig = new(LicenseComplianceConfig)
	errLoadLicensePolicies := licensePolicyConfig.LoadLicensePolicies(licensePolicyFile, DEFAULT_LICENSE_POLICY_CONFIG)
	if errLoadLicensePolicies != nil {
		getLogger().Warning(errLoadLicensePolicies.Error())
		getLogger().Warningf("All license policies will default to `%s`.", POLICY_UNDEFINED)
	}
}

func RootCmdImpl(cmd *cobra.Command, args []string) error {
	getLogger().Enter()
	defer getLogger().Exit()

	// no commands (empty) passed; display help
	if len(args) == 0 {
		// Show intent to not check error return as no recovery steps possible
		_ = cmd.Help()
		os.Exit(ERROR_APPLICATION)
	}
	return nil
}

func Execute() {
	// instead of creating a dependency on the "main" module
	getLogger().Enter()
	defer getLogger().Exit()

	if err := rootCmd.Execute(); err != nil {
		if IsInvalidBOMError(err) {
			os.Exit(ERROR_VALIDATION)
		} else {
			os.Exit(ERROR_APPLICATION)
		}
	}
}

// Command PreRunE helper function to test for input file
func preRunTestForInputFile(cmd *cobra.Command, args []string) error {
	getLogger().Enter()
	defer getLogger().Exit()
	getLogger().Tracef("args: %v", args)

	// Make sure the input filename is present and exists
	inputFilename := utils.GlobalFlags.PersistentFlags.InputFile
	if inputFilename == "" {
		return getLogger().Errorf("Missing required argument(s): %s", FLAG_FILENAME_INPUT)
	} else if inputFilename == INPUT_TYPE_STDIN {
		return nil
	} else if _, err := os.Stat(inputFilename); err != nil {
		return getLogger().Errorf("File not found: `%s`", inputFilename)
	}
	return nil
}

// TODO: when the package "golang.org/x/exp/slices" is graduated from "experimental", replace
// for loop with the "Contains" method.
func preRunTestForSubcommand(cmd *cobra.Command, validSubcommands []string, subcommand string) bool {
	getLogger().Enter()
	defer getLogger().Exit()
	getLogger().Tracef("subcommands: %v, subcommand: `%v`", validSubcommands, subcommand)

	for _, value := range validSubcommands {
		if value == subcommand {
			getLogger().Tracef("Valid subcommand `%v` found", subcommand)
			return true
		}
	}
	return false
}

func createOutputFile(outputFilename string) (outputFile *os.File, writer io.Writer, err error) {
	// default to Stdout
	writer = os.Stdout

	// If command included an output file, attempt to create it and create a writer
	if outputFilename != "" {
		getLogger().Infof("Creating output file: `%s`...", outputFilename)
		outputFile, err = os.Create(outputFilename)
		if err != nil {
			getLogger().Error(err)
		}
		writer = outputFile
	}
	return
}
