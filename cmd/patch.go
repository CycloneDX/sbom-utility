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

package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/CycloneDX/sbom-utility/utils"
	"github.com/spf13/cobra"
)

// flags (do not translate)
const (
	FLAG_PATCH_FILE = "patch-file"
)

// flag help (translate)
const (
	MSG_PATCH_FILE = "patch filename"
)

var PATCH_OUTPUT_SUPPORTED_FORMATS = MSG_SUPPORTED_OUTPUT_FORMATS_HELP +
	strings.Join([]string{FORMAT_JSON}, ", ")

// Command PreRunE helper function to test for patch file
func preRunTestForPatchFile(cmd *cobra.Command, args []string) error {
	getLogger().Enter()
	defer getLogger().Exit()
	getLogger().Tracef("args: %v", args)

	// Make sure the input filename is present and exists
	patchFilename := utils.GlobalFlags.PatchFlags.PatchFile
	if patchFilename == "" {
		return getLogger().Errorf("Missing required argument(s): %s", FLAG_PATCH_FILE)
	} else if _, err := os.Stat(patchFilename); err != nil {
		return getLogger().Errorf("File not found: `%s`", patchFilename)
	}
	return nil
}

func NewCommandPatch() *cobra.Command {
	var command = new(cobra.Command)
	command.Use = CMD_USAGE_PATCH
	command.Short = "Apply an IETF RFC 6902 patch file to a JSON BOM file"
	command.Long = "Apply an IETF RFC 6902 patch file to a JSON BOM file"
	command.RunE = patchCmdImpl
	command.PreRunE = func(cmd *cobra.Command, args []string) (err error) {
		// Test for required flags (parameters)
		err = preRunTestForInputFile(cmd, args)
		if err != nil {
			return
		}
		err = preRunTestForPatchFile(cmd, args)
		if err != nil {
			return
		}
		return
	}
	initCommandPatchFlags(command)

	return command
}

func initCommandPatchFlags(command *cobra.Command) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	command.PersistentFlags().StringVar(&utils.GlobalFlags.PersistentFlags.OutputFormat, FLAG_OUTPUT_FORMAT, FORMAT_JSON,
		MSG_FLAG_OUTPUT_FORMAT+PATCH_OUTPUT_SUPPORTED_FORMATS)
	command.Flags().StringVarP(&utils.GlobalFlags.PatchFlags.PatchFile, FLAG_PATCH_FILE, "", "", MSG_PATCH_FILE)
	err = command.MarkFlagRequired(FLAG_PATCH_FILE)
	if err != nil {
		err = getLogger().Errorf("unable to mark flag `%s` as required: %s", FLAG_PATCH_FILE, err)
	}
	return
}

func patchCmdImpl(cmd *cobra.Command, args []string) (err error) {
	getLogger().Enter(args)
	defer getLogger().Exit()

	// Create output writer
	outputFilename := utils.GlobalFlags.PersistentFlags.OutputFile
	outputFile, writer, err := createOutputFile(outputFilename)
	getLogger().Tracef("outputFile: `%v`; writer: `%v`", outputFilename, writer)

	// use function closure to assure consistent error output based upon error type
	defer func() {
		// always close the output file
		if outputFile != nil {
			outputFile.Close()
			getLogger().Infof("Closed output file: `%s`", outputFilename)
		}
	}()

	if err == nil {
		err = Patch(writer, utils.GlobalFlags.PersistentFlags, utils.GlobalFlags.PatchFlags)
	}

	return
}

// Assure all errors are logged
func processPatchResults(err error) {
	if err != nil {
		// No special processing at this time
		getLogger().Error(err)
	}
}

// NOTE: resourceType has already been validated
func Patch(writer io.Writer, persistentFlags utils.PersistentCommandFlags, patchFlags utils.PatchCommandFlags) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// use function closure to assure consistent error output based upon error type
	defer func() {
		if err != nil {
			processPatchResults(err)
		}
	}()

	// Note: returns error if either file load or unmarshal to JSON map fails
	var document *schema.BOM
	if document, err = LoadInputBOMFileAndDetectSchema(); err != nil {
		return
	}

	// At this time, fail SPDX format SBOMs as "unsupported" (for "any" format)
	if !document.FormatInfo.IsCycloneDx() {
		err = schema.NewUnsupportedFormatForCommandError(
			document.FormatInfo.CanonicalName,
			document.GetFilename(),
			CMD_LICENSE, FORMAT_ANY)
		return
	}

	// validate parameters
	patchFile := utils.GlobalFlags.PatchFlags.PatchFile
	if patchFile == "" {
		err = fmt.Errorf("invalid patch file")
		return
	}

	patchDocument := NewIETFRFC6902PatchDocument(patchFile)
	// if err = patchDocument.UnmarshalIETFRFC6903Document(); err != nil {
	// 	return
	// }

	if err = patchDocument.UnmarshalRecords(); err != nil {
		return
	}

	// Output the "patched" version of the Input BOM
	format := persistentFlags.OutputFormat
	getLogger().Infof("Writing patched BOM (`%s` format)...", format)
	switch format {
	case FORMAT_JSON:
		err = document.WriteAsEncodedJSONInt(writer, utils.GlobalFlags.PersistentFlags.GetOutputIndentInt())
	default:
		// Default to Text output for anything else (set as flag default)
		getLogger().Warningf("Trim not supported for `%s` format; defaulting to `%s` format...",
			format, FORMAT_JSON)
		err = document.WriteAsEncodedJSONInt(writer, utils.GlobalFlags.PersistentFlags.GetOutputIndentInt())
	}

	return
}
