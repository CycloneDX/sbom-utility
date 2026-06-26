// SPDX-License-Identifier: Apache-2.0

package bridge

import (
	"bytes"

	"github.com/CycloneDX/sbom-utility/cmd"
	"github.com/CycloneDX/sbom-utility/utils"
	"github.com/xeipuuv/gojsonschema"
)

// ValidateParams mirrors the flags exposed on the `validate` CLI command.
type ValidateParams struct {
	InputFile    string
	SchemaVariant string
	ForceSchema  string
	MaxErrors    int
	ShowValues   bool
}

// ValidateResult is what the GUI renders after a validate run.
type ValidateResult struct {
	Valid        bool
	SchemaErrors []gojsonschema.ResultError
	Output       string // text representation of errors
	Err          error
}

// RunValidate sets GlobalFlags from params and calls the real Validate().
func RunValidate(p ValidateParams) ValidateResult {
	// Persist input file so LoadInputBOMFileAndDetectSchema can find it.
	utils.GlobalFlags.PersistentFlags.InputFile = p.InputFile
	utils.GlobalFlags.PersistentFlags.OutputFormat = cmd.FORMAT_TEXT

	validateFlags := utils.ValidateCommandFlags{
		SchemaVariant:        p.SchemaVariant,
		ForcedJsonSchemaFile: p.ForceSchema,
		MaxNumErrors:         p.MaxErrors,
		ShowErrorValue:       p.ShowValues,
		ColorizeErrorOutput:  false, // no ANSI in the GUI
	}
	if validateFlags.MaxNumErrors == 0 {
		validateFlags.MaxNumErrors = cmd.DEFAULT_MAX_ERROR_LIMIT
	}

	var buf bytes.Buffer
	valid, _, schemaErrors, err := cmd.Validate(&buf, utils.GlobalFlags.PersistentFlags, validateFlags)
	return ValidateResult{
		Valid:        valid,
		SchemaErrors: schemaErrors,
		Output:       buf.String(),
		Err:          err,
	}
}
