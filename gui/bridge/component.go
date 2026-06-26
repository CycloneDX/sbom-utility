// SPDX-License-Identifier: Apache-2.0

package bridge

import (
	"bytes"

	"github.com/CycloneDX/sbom-utility/cmd"
	"github.com/CycloneDX/sbom-utility/utils"
)

// ComponentParams mirrors the flags on `component list`.
type ComponentParams struct {
	InputFile    string
	Summary      bool
	OutputFormat string
	WhereRaw     string
}

func ListComponentsText(p ComponentParams) (string, error) {
	utils.GlobalFlags.PersistentFlags.InputFile = p.InputFile
	utils.GlobalFlags.PersistentFlags.OutputFormat = p.OutputFormat
	if utils.GlobalFlags.PersistentFlags.OutputFormat == "" {
		utils.GlobalFlags.PersistentFlags.OutputFormat = cmd.FORMAT_TEXT
	}

	flags := utils.ComponentCommandFlags{}
	flags.Summary = p.Summary

	whereFilters, err := parseWhere(p.WhereRaw)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	err = cmd.ListComponents(&buf, utils.GlobalFlags.PersistentFlags, flags, whereFilters)
	return buf.String(), err
}
