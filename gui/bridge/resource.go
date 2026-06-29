// SPDX-License-Identifier: Apache-2.0

package bridge

import (
	"bytes"

	"github.com/CycloneDX/sbom-utility/cmd"
	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/CycloneDX/sbom-utility/utils"
)

// ResourceParams mirrors the flags on `resource list`.
type ResourceParams struct {
	InputFile    string
	ResourceType string // "", "component", "service"
	OutputFormat string
	WhereRaw     string
}

func ListResourcesText(p ResourceParams) (string, error) {
	utils.GlobalFlags.PersistentFlags.InputFile = p.InputFile
	utils.GlobalFlags.PersistentFlags.OutputFormat = p.OutputFormat
	if utils.GlobalFlags.PersistentFlags.OutputFormat == "" {
		utils.GlobalFlags.PersistentFlags.OutputFormat = cmd.FORMAT_TEXT
	}

	resourceType := p.ResourceType
	if resourceType == "" {
		resourceType = schema.RESOURCE_TYPE_DEFAULT
	}
	flags := utils.NewResourceCommandFlags(resourceType)

	whereFilters, err := parseWhere(p.WhereRaw)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	err = cmd.ListResources(&buf, utils.GlobalFlags.PersistentFlags, flags, whereFilters)
	return buf.String(), err
}
