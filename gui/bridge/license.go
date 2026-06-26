// SPDX-License-Identifier: Apache-2.0

package bridge

import (
	"bytes"

	"github.com/CycloneDX/sbom-utility/cmd"
	"github.com/CycloneDX/sbom-utility/common"
	"github.com/CycloneDX/sbom-utility/utils"
)

// LicenseParams mirrors the flags exposed on the `license list` CLI command.
type LicenseParams struct {
	InputFile    string
	Summary      bool
	OutputFormat string // "txt", "csv", "json", "md"
	WhereRaw     string // raw "key=regex,key=regex" string
}

// ListLicensesText captures tabular output as a string for display.
func ListLicensesText(p LicenseParams) (string, error) {
	utils.GlobalFlags.PersistentFlags.InputFile = p.InputFile
	utils.GlobalFlags.PersistentFlags.OutputFormat = p.OutputFormat
	if utils.GlobalFlags.PersistentFlags.OutputFormat == "" {
		utils.GlobalFlags.PersistentFlags.OutputFormat = cmd.FORMAT_TEXT
	}

	licenseFlags := utils.LicenseCommandFlags{}
	licenseFlags.Summary = p.Summary

	whereFilters, err := parseWhere(p.WhereRaw)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	err = cmd.ListLicenses(&buf, cmd.LicensePolicyConfig, utils.GlobalFlags.PersistentFlags, licenseFlags, whereFilters)
	return buf.String(), err
}

// parseWhere converts a raw "key=regex,key=regex" string into WhereFilter slice.
func parseWhere(raw string) ([]common.WhereFilter, error) {
	if raw == "" {
		return nil, nil
	}
	predicates := common.ParseWherePredicates(raw)
	return common.ParseWhereFilters(predicates)
}
